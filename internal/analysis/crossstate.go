package analysis

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/vedantparmar12/cloudweave/internal/state"
)

type remoteLink struct {
	Consumer   string // state name
	DataNode   string // node ID of data.terraform_remote_state.<name>
	Producer   string // state name
	Outputs    []string
	Stale      []string // outputs whose consumer copy differs from producer
	Confidence string
}

// ownerKeys are top-level attributes that identify the resource itself.
var ownerKeys = map[string]bool{
	"id": true, "self_link": true, "email": true, "unique_id": true,
	"principal_id": true, "client_id": true, "object_id": true,
	"application_id": true, "name": true,
}

type owner struct {
	State   string
	Address string
	Type    string
	Mode    string
	Key     string
}

func (a *analyzer) linkCrossState() {
	if len(a.states) < 2 {
		return
	}
	idx := a.ownerIndex()
	a.linkRemoteState(idx)
	a.linkByIdentity(idx)
}

func (a *analyzer) ownerIndex() map[string][]owner {
	idx := map[string][]owner{}
	for _, st := range a.states {
		for _, r := range st.Resources {
			if r.Type == "terraform_remote_state" || r.Mode == "data" {
				continue
			}
			seen := map[string]bool{}
			for _, inst := range r.Instances {
				for k, v := range inst.Attributes {
					if !ownerKeys[k] || inst.Sensitive.IsSensitive("/"+k) {
						continue
					}
					s, ok := v.(string)
					if !ok || !strongIdentifier(k, s) {
						continue
					}
					h := state.HashValue(s)
					if seen[h] {
						continue
					}
					seen[h] = true
					idx[h] = append(idx[h], owner{State: st.Name, Address: r.Address, Type: r.Type, Mode: r.Mode, Key: k})
				}
			}
		}
	}
	return idx
}

// strongIdentifier filters out short or generic values that would create
// false cross-state edges.
func strongIdentifier(key, v string) bool {
	if len(v) < 8 {
		return false
	}
	switch idConfidence(v) {
	case ConfHigh, ConfMedium:
		return true
	}
	return key != "name" && len(v) >= 16
}

func idConfidence(v string) string {
	lower := strings.ToLower(v)
	switch {
	case strings.HasPrefix(lower, "/subscriptions/"),
		strings.HasPrefix(lower, "projects/"),
		strings.HasPrefix(lower, "organizations/"),
		strings.HasPrefix(lower, "//"),
		strings.HasPrefix(lower, "https://"),
		strings.HasPrefix(lower, "principal"),
		strings.Count(lower, "/") >= 2:
		return ConfHigh
	case len(lower) == 36 && strings.Count(lower, "-") == 4:
		return ConfMedium
	case strings.Contains(lower, "@") && strings.Contains(lower, "."):
		return ConfMedium
	case len(lower) >= 15 && strings.Trim(lower, "0123456789") == "":
		return ConfMedium
	}
	return ConfLow
}

func (a *analyzer) linkRemoteState(idx map[string][]owner) {
	for _, consumer := range a.states {
		for _, r := range consumer.Resources {
			outs := r.RemoteStateOutputs()
			if len(outs) == 0 {
				continue
			}
			link := a.bestProducer(consumer, outs)
			if link == nil {
				a.add(Finding{
					Rule:     "CW501",
					Severity: SevInfo,
					Category: CatCrossState,
					Title:    "Remote state source not provided",
					Detail: fmt.Sprintf("%s in %s reads %d outputs from a state that was not passed to CloudWeave, so impact through it cannot be traced.",
						r.Address, consumer.Name, len(outs)),
					Remediation: "Pass the producer state with another --state flag.",
					Nodes:       []string{NodeID(consumer.Name, r.Address)},
				})
				continue
			}
			link.DataNode = NodeID(consumer.Name, r.Address)
			a.remoteLinks = append(a.remoteLinks, *link)
			a.addRemoteEdges(*link, outs, idx)

			if len(link.Stale) > 0 {
				a.add(Finding{
					Rule:     "CW502",
					Severity: SevMedium,
					Category: CatCrossState,
					Title:    "Consumer state holds stale copy of remote outputs",
					Detail: fmt.Sprintf("%s in %s has values for outputs [%s] that differ from %s. The producer changed after the consumer was last applied; the consumer's next plan will pick up new values.",
						r.Address, consumer.Name, joinLimited(link.Stale, 6), link.Producer),
					Remediation: "Plan and review " + consumer.Name + " after this change set, or apply them in producer → consumer order.",
					Nodes:       []string{link.DataNode},
				})
			}
		}
	}
}

func (a *analyzer) bestProducer(consumer *state.State, outs map[string]any) *remoteLink {
	var best *remoteLink
	bestScore := 0
	for _, producer := range a.states {
		if producer == consumer || a.sameLineage(producer.Name, consumer.Name) {
			continue
		}
		byName := map[string]*state.Output{}
		for _, o := range producer.Outputs {
			byName[o.Name] = o
		}
		link := &remoteLink{Consumer: consumer.Name, Producer: producer.Name}
		score, valueMatches := 0, 0
		for name, v := range outs {
			po, ok := byName[name]
			if !ok {
				continue
			}
			link.Outputs = append(link.Outputs, name)
			if po.Sensitive {
				score++
				continue
			}
			if canonical(v) == canonical(po.Value) {
				valueMatches++
				score += 3
			} else {
				link.Stale = append(link.Stale, name)
				score++
			}
		}
		if len(link.Outputs) == 0 {
			continue
		}
		switch {
		case valueMatches > 0 && len(link.Outputs) == len(outs):
			link.Confidence = ConfHigh
		case valueMatches > 0:
			link.Confidence = ConfMedium
		case len(link.Outputs) == len(outs):
			link.Confidence = ConfLow
		default:
			continue
		}
		if score > bestScore {
			best, bestScore = link, score
		}
	}
	if best != nil {
		sort.Strings(best.Outputs)
		sort.Strings(best.Stale)
	}
	return best
}

func canonical(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func (a *analyzer) addRemoteEdges(link remoteLink, outs map[string]any, idx map[string][]owner) {
	producer := a.stateByName(link.Producer)
	for _, name := range link.Outputs {
		var targets []string
		for _, leaf := range state.OutputLeaves(link.Producer, outputByName(producer, name)) {
			for _, o := range idx[leaf.Hash] {
				if o.State == link.Producer {
					targets = append(targets, NodeID(o.State, o.Address))
				}
			}
		}
		if len(targets) == 0 {
			targets = []string{a.outputNode(link.Producer, name)}
		}
		for _, t := range targets {
			a.g.AddEdge(Edge{
				From:       link.DataNode,
				To:         t,
				Kind:       EdgeRemoteState,
				Confidence: link.Confidence,
				Evidence:   "output " + name,
			})
		}
	}
}

func (a *analyzer) outputNode(stateName, output string) string {
	n := a.g.AddNode(&Node{
		ID:      NodeID(stateName, "output."+output),
		State:   stateName,
		Address: "output." + output,
		Mode:    "output",
		Type:    "output",
		Cloud:   state.CloudOther,
	})
	return n.ID
}

func outputByName(st *state.State, name string) *state.Output {
	if st == nil {
		return nil
	}
	for _, o := range st.Outputs {
		if o.Name == name {
			return o
		}
	}
	return nil
}

func (a *analyzer) stateByName(name string) *state.State {
	for _, st := range a.states {
		if st.Name == name {
			return st
		}
	}
	return nil
}

// linkByIdentity adds edges where a resource attribute holds the identifier
// of a resource managed in another state, and flags resources managed twice.
func (a *analyzer) linkByIdentity(idx map[string][]owner) {
	type dupKey struct{ a, b string }
	dups := map[dupKey]bool{}
	for _, st := range a.states {
		for _, r := range st.Resources {
			if r.Type == "terraform_remote_state" {
				continue
			}
			from := NodeID(st.Name, r.Address)
			for _, leaf := range r.IdentityLeaves(st.Name) {
				owners := idx[leaf.Hash]
				var foreign []owner
				for _, o := range owners {
					if o.State != st.Name && !a.sameLineage(o.State, st.Name) {
						foreign = append(foreign, o)
					}
				}
				if len(foreign) == 0 || len(foreign) > 3 {
					continue
				}
				for _, o := range foreign {
					to := NodeID(o.State, o.Address)
					if r.Mode == "managed" && o.Mode == "managed" && leaf.Path == "/id" && o.Key == "id" && r.Type == o.Type {
						k := dupKey{from, to}
						if from > to {
							k = dupKey{to, from}
						}
						dups[k] = true
						continue
					}
					conf := idConfidence(leaf.Value)
					if len(foreign) > 1 && conf == ConfHigh {
						conf = ConfMedium
					}
					a.g.AddEdge(Edge{
						From:       from,
						To:         to,
						Kind:       EdgeIDMatch,
						Confidence: conf,
						Evidence:   fmt.Sprintf("%s equals %s.%s", strings.TrimPrefix(leaf.Path, "/"), o.Type, o.Key),
					})
				}
			}
		}
	}
	keys := make([]dupKey, 0, len(dups))
	for k := range dups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].a < keys[j].a })
	for _, k := range keys {
		a.add(Finding{
			Rule:     "CW503",
			Severity: SevHigh,
			Category: CatCrossState,
			Title:    "Same cloud resource managed by two states",
			Detail: fmt.Sprintf("%s and %s track the same resource ID. Applying either state can silently revert the other, and a destroy in one deletes infrastructure the other still owns.",
				k.a, k.b),
			Remediation: "Keep the resource in one state and remove it from the other with a `removed` block (Terraform ≥1.7) or `terraform state rm` after taking a backup.",
			Nodes:       []string{k.a, k.b},
		})
	}
}

// sameLineage reports whether two inputs are snapshots of the same state.
func (a *analyzer) sameLineage(x, y string) bool {
	sx, sy := a.stateByName(x), a.stateByName(y)
	return sx != nil && sy != nil && sx.Lineage != "" && sx.Lineage == sy.Lineage
}

// applyOrder orders states so that every state comes after the states it
// reads values from. Federation edges are trust links that can be created in
// either order, so they do not constrain the order. States in a cycle are
// appended last and reported.
func (a *analyzer) applyOrder() []string {
	if len(a.states) < 2 {
		return nil
	}
	deps := map[string]map[string]bool{}
	for _, st := range a.states {
		deps[st.Name] = map[string]bool{}
	}
	for _, e := range a.g.Edges {
		from, to := a.g.Nodes[e.From], a.g.Nodes[e.To]
		if from == nil || to == nil || from.State == to.State || e.Confidence == ConfLow || e.Kind == EdgeFederation {
			continue
		}
		if deps[from.State] != nil && deps[to.State] != nil {
			deps[from.State][to.State] = true
		}
	}
	var order []string
	done := map[string]bool{}
	for len(order) < len(a.states) {
		var ready []string
		for name, d := range deps {
			if done[name] {
				continue
			}
			ok := true
			for dep := range d {
				if !done[dep] {
					ok = false
					break
				}
			}
			if ok {
				ready = append(ready, name)
			}
		}
		if len(ready) == 0 {
			break
		}
		sort.Strings(ready)
		for _, n := range ready {
			done[n] = true
		}
		order = append(order, ready...)
	}
	if len(order) < len(a.states) {
		var cycle []string
		for _, st := range a.states {
			if !done[st.Name] {
				cycle = append(cycle, st.Name)
			}
		}
		sort.Strings(cycle)
		order = append(order, cycle...)
		a.add(Finding{
			Rule:     "CW504",
			Severity: SevMedium,
			Category: CatCrossState,
			Title:    "States depend on each other in a cycle",
			Detail: fmt.Sprintf("States [%s] read from each other, so no apply order lets each one see the other's latest outputs. A change in either can need two applies to converge.",
				strings.Join(cycle, ", ")),
			Remediation: "Move the shared resources or outputs into one state, or break the cycle with a data source that does not depend on the other state's outputs.",
		})
	}
	return order
}
