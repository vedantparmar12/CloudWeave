package analysis

import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/vedantparmar12/cloudweave/internal/state"
)

const (
	OutcomeOK      = "ok"
	OutcomeWarn    = "warn"
	OutcomeFail    = "fail"
	OutcomeBlocked = "blocked"
)

type SimStep struct {
	Step    int      `json:"step"`
	State   string   `json:"state"`
	Node    string   `json:"node,omitempty"`
	Action  string   `json:"action"`
	Outcome string   `json:"outcome"`
	Before  string   `json:"before,omitempty"`
	After   string   `json:"after,omitempty"`
	Notes   []string `json:"notes,omitempty"`
	Affects []string `json:"affects,omitempty"`
}

type Simulation struct {
	Steps        []SimStep `json:"steps"`
	Fails        int       `json:"fails"`
	Warns        int       `json:"warns"`
	Blocked      int       `json:"blocked"`
	FirstFailure int       `json:"first_failure,omitempty"`
	Limitations  []string  `json:"limitations"`
}

type simOperation struct {
	node   string
	action string
	wait   map[string]bool
}

type simObject struct {
	old       bool
	new       bool
	forgotten bool
}

func (o simObject) status() string {
	switch {
	case o.forgotten:
		return "unmanaged (object retained)"
	case o.old && o.new:
		return "old and replacement exist"
	case o.new:
		return "new object exists"
	case o.old:
		return "existing object"
	default:
		return "absent"
	}
}

func (a *analyzer) simulate() *Simulation {
	if a.plan == nil {
		return nil
	}
	sim := &Simulation{Steps: []SimStep{}, Limitations: []string{
		"Offline, resource-level model, not Terraform's execution engine. No Terraform or cloud calls are made.",
		"Only the supplied plan is replayed. Other states remain snapshots; follow-up entries are not simulated applies.",
		"Waves express known dependency order, not real parallelism or timing. Provider behavior, quotas, live drift, credential refresh and IAM propagation are unknown.",
		"Existing edges may change during apply. Failures and warnings are model predictions, not observed cloud failures; OK means only no modeled issue.",
	}}
	if (a.plan.Errored != nil && *a.plan.Errored) || (a.plan.Complete != nil && !*a.plan.Complete) || len(a.plan.Deferred) > 0 {
		sim.Limitations = append(sim.Limitations, "The plan is errored, incomplete or deferred; this replay is partial.")
	}
	sequences := map[string][]string{}
	ambiguous := map[string]bool{}
	for _, c := range a.plan.Changes {
		seq := c.Actions
		if len(seq) == 0 && c.Action != state.ActionReplace {
			seq = []string{c.Action}
		}
		for _, id := range a.g.Resolve(a.primary.Name, c.Address) {
			if !isMutation(a.g.Nodes[id].Action) {
				continue
			}
			if previous, ok := sequences[id]; ok && !reflect.DeepEqual(previous, seq) {
				ambiguous[id] = true
			}
			sequences[id] = seq
			if len(seq) == 0 || c.Deposed != "" {
				ambiguous[id] = true
			}
		}
	}
	objects := map[string]simObject{}
	ops := map[string]*simOperation{}
	byNode := map[string][]string{}
	for _, n := range a.g.SortedNodes() {
		objects[n.ID] = simObject{old: !n.Planned && n.Action != state.ActionCreate && n.Drift != state.ActionDelete}
		if !isMutation(n.Action) {
			continue
		}
		if n.Instances > 1 {
			msg := "Multiple instances are aggregated; per-instance dependencies and partial replacements cannot be resolved exactly."
			if n.HasCount || n.HasForEach {
				msg += " count/for_each keys cannot be evaluated offline."
			}
			sim.Limitations = appendUniqueStr(sim.Limitations, msg)
		}
		seq := sequences[n.ID]
		if ambiguous[n.ID] || len(seq) == 0 {
			seq = []string{"unresolved"}
		}
		for i, action := range seq {
			key := fmt.Sprintf("%s::%d", n.ID, i)
			ops[key] = &simOperation{node: n.ID, action: action, wait: map[string]bool{}}
			if i > 0 {
				ops[key].wait[byNode[n.ID][i-1]] = true
			}
			byNode[n.ID] = append(byNode[n.ID], key)
		}
	}
	if len(ops) == 0 {
		return sim
	}
	phase := func(id string, destroy bool) string {
		for _, key := range byNode[id] {
			if (ops[key].action == state.ActionDelete) == destroy {
				return key
			}
		}
		return ""
	}
	waitFor := func(key, dependency string) {
		if key != "" && dependency != "" && key != dependency {
			ops[key].wait[dependency] = true
		}
	}
	for id := range byNode {
		seen := map[string]bool{}
		queue := []string{id}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			for _, e := range a.g.Dependencies(current) {
				if e.Kind != EdgeDependency || e.Confidence == ConfLow || a.g.Nodes[e.To].State != a.g.Nodes[id].State || seen[e.To] {
					continue
				}
				seen[e.To] = true
				if len(byNode[e.To]) == 0 {
					queue = append(queue, e.To)
					continue
				}
				waitFor(phase(id, false), phase(e.To, false))
				waitFor(phase(e.To, true), phase(id, true))
				// Consumers must switch before an old create-before-destroy object retires.
				keys := byNode[e.To]
				if len(keys) > 1 && ops[keys[0]].action == state.ActionCreate {
					waitFor(phase(e.To, true), phase(id, false))
				}
			}
		}
	}
	pending := map[string]bool{}
	degree := map[string]int{}
	users := map[string][]string{}
	var ready []string
	for key, op := range ops {
		pending[key] = true
		degree[key] = len(op.wait)
		if len(op.wait) == 0 {
			ready = append(ready, key)
		}
		for dependency := range op.wait {
			users[dependency] = append(users[dependency], key)
		}
	}
	wave := 0
	unresolved := map[string]bool{}
	for len(ready) > 0 {
		wave++
		sort.Strings(ready)
		var next []string
		for _, key := range ready {
			op := ops[key]
			n := a.g.Nodes[op.node]
			object := objects[n.ID]
			step := SimStep{Step: wave, State: n.State, Node: n.ID, Action: op.action, Outcome: OutcomeOK, Before: object.status()}
			if n.Action == state.ActionReplace {
				step.Notes = append(step.Notes, "Replacement phase; order is taken from the plan's actions.")
			}
			for dependency := range op.wait {
				if unresolved[dependency] {
					mark(&step, OutcomeBlocked, "A required modeled operation failed or is unresolved; no transition is predicted.")
				}
			}
			if op.action == "unresolved" {
				mark(&step, OutcomeBlocked, "Instance actions differ, a deposed object is present, or replacement order is missing. No transition is predicted.")
			}
			if step.Outcome != OutcomeBlocked {
				if op.action == state.ActionCreate || op.action == state.ActionUpdate {
					for _, edge := range a.g.Dependencies(n.ID) {
						other := objects[edge.To]
						if edge.Confidence != ConfLow && !other.old && !other.new {
							severity := OutcomeWarn
							if edge.Kind == EdgeDependency {
								severity = OutcomeFail
							}
							mark(&step, severity, "Dependency is absent in this model: "+edge.To)
							step.Affects = appendUniqueStr(step.Affects, edge.To)
						}
						if isIAMGrant(a.g.Nodes[edge.To].Type) && other.new {
							mark(&step, OutcomeWarn, "A newly created IAM grant may not have propagated. Dependency ordering alone cannot guarantee access.")
						}
					}
				}
				if op.action == state.ActionDelete {
					for _, edge := range a.g.Dependents(n.ID) {
						other := objects[edge.From]
						if edge.Confidence == ConfLow || (!other.old && !other.new) {
							continue
						}
						step.Affects = appendUniqueStr(step.Affects, edge.From)
					}
					if len(step.Affects) > 0 {
						mark(&step, OutcomeWarn, "Live consumers may still reference the retiring object. Deletion may be rejected or break references; separate states do not automatically switch to its replacement.")
					}
				}
				if federationTypes[n.Type] && op.action != state.ActionForget {
					mark(&step, OutcomeWarn, "If this apply uses the affected identity or trust chain, token exchange may fail mid-apply. The provider's authentication dependency is not known.")
				}
				if op.action == state.ActionCreate && isIAMGrant(n.Type) {
					mark(&step, OutcomeWarn, "IAM grant propagation is not instantaneous. Verify access before running consumers; no fixed wait guarantees propagation.")
				}
				if n.Drift != "" && n.Drift != state.ActionNoop {
					mark(&step, OutcomeWarn, "Drift was reported by the plan; subsequent live changes are not observable offline.")
				}
				if len(n.Provisioners) > 0 {
					mark(&step, OutcomeWarn, "Provisioners execute only at apply time; the plan does not exercise them, and their runtime needs may fail.")
				}
				if a.credLeft != nil && *a.credLeft < a.opts.ApplyWindow {
					note := "A credential expires within the expected apply window; exact affected steps and provider refresh behavior are unknown."
					if *a.credLeft <= 0 {
						note = "A credential is already expired; operations using it may fail unless the provider refreshes it."
					}
					mark(&step, OutcomeWarn, note)
				}
				if step.Outcome != OutcomeFail {
					switch op.action {
					case state.ActionCreate:
						object.new = true
					case state.ActionDelete:
						object.old = false
					case state.ActionForget:
						object.forgotten = true
					}
				}
			}
			unresolved[key] = step.Outcome == OutcomeFail || step.Outcome == OutcomeBlocked
			step.After = object.status()
			objects[n.ID] = object
			sim.Steps = append(sim.Steps, step)
			delete(pending, key)
			for _, user := range users[key] {
				degree[user]--
				if degree[user] == 0 {
					next = append(next, user)
				}
			}
		}
		ready = next
	}
	if len(pending) > 0 {
		wave++
		for _, key := range nodeList(pending) {
			op := ops[key]
			sim.Steps = append(sim.Steps, SimStep{Step: wave, State: a.g.Nodes[op.node].State, Node: op.node, Action: op.action, Outcome: OutcomeBlocked, Notes: []string{"Dependency cycle in the modeled operations; no order or state transition was invented."}})
		}
	}
	for _, name := range a.followUpStates() {
		wave++
		sim.Steps = append(sim.Steps, SimStep{Step: wave, State: name, Action: "re-plan", Outcome: OutcomeWarn, Notes: []string{"Impacted state: obtain a fresh plan after reviewing the producer change. No plan for this state was supplied, so its apply is not simulated."}})
	}
	for _, step := range sim.Steps {
		switch step.Outcome {
		case OutcomeFail:
			sim.Fails++
			if sim.FirstFailure == 0 {
				sim.FirstFailure = step.Step
			}
		case OutcomeWarn:
			sim.Warns++
		case OutcomeBlocked:
			sim.Blocked++
		}
	}
	return sim
}

func (a *analyzer) followUpStates() []string {
	changed, impacted := map[string]bool{}, map[string]bool{}
	for _, n := range a.g.Nodes {
		if isMutation(n.Action) {
			changed[n.State] = true
		} else if n.Role == RoleDownstream {
			impacted[n.State] = true
		}
	}
	var out []string
	for _, name := range a.order {
		if impacted[name] && !changed[name] {
			out = append(out, name)
			delete(impacted, name)
		}
	}
	for _, name := range nodeList(impacted) {
		if !changed[name] {
			out = append(out, name)
		}
	}
	return out
}

func mark(st *SimStep, outcome, note string) {
	st.Notes = appendUniqueStr(st.Notes, note)
	if outcome == OutcomeBlocked || outcome == OutcomeFail || (outcome == OutcomeWarn && st.Outcome == OutcomeOK) {
		st.Outcome = outcome
	}
}

func (a *analyzer) noteCredential(left time.Duration) {
	if a.credLeft == nil || left < *a.credLeft {
		a.credLeft = &left
	}
}
