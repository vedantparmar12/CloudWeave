package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vedantparmar12/cloudweave/internal/state"
	"github.com/vedantparmar12/cloudweave/internal/tfconfig"
)

// Options controls analysis. The zero value is usable.
type Options struct {
	// PrimaryState names the state the plan applies to (name, path or base name).
	PrimaryState string
	// PlanMaxAge flags saved plans older than this.
	PlanMaxAge time.Duration
	// ApplyWindow is how long the apply is expected to run; credentials that
	// expire within it are flagged.
	ApplyWindow time.Duration
	// BlastRadius flags changes impacting more than this many resources.
	BlastRadius int
	// RevealIDs disables masking of identifiers in finding text.
	RevealIDs bool
	// CheckCredentials inspects local credential env vars and files.
	CheckCredentials bool
	// Config is an optional parse of the primary state's Terraform
	// configuration directory (literals only; expressions are never evaluated).
	Config *tfconfig.Config
	Now    time.Time
	Getenv func(string) string
}

func (o *Options) defaults() {
	if o.PlanMaxAge == 0 {
		o.PlanMaxAge = time.Hour
	}
	if o.ApplyWindow == 0 {
		o.ApplyWindow = 30 * time.Minute
	}
	if o.BlastRadius == 0 {
		o.BlastRadius = 25
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
}

type StateSummary struct {
	Name             string         `json:"name"`
	Format           state.Format   `json:"format"`
	Source           state.Source   `json:"source"`
	TerraformVersion string         `json:"terraform_version,omitempty"`
	Serial           *int64         `json:"serial,omitempty"`
	Lineage          string         `json:"lineage,omitempty"`
	Resources        int            `json:"resources"`
	DataSources      int            `json:"data_sources"`
	Instances        int            `json:"instances"`
	Outputs          int            `json:"outputs"`
	Clouds           map[string]int `json:"clouds"`
	Primary          bool           `json:"primary,omitempty"`
	FromPlan         bool           `json:"from_plan,omitempty"`
}

type PlanSummary struct {
	TerraformVersion string         `json:"terraform_version,omitempty"`
	Timestamp        string         `json:"timestamp,omitempty"`
	AgeMinutes       *int           `json:"age_minutes,omitempty"`
	Complete         *bool          `json:"complete,omitempty"`
	Applyable        *bool          `json:"applyable,omitempty"`
	Errored          *bool          `json:"errored,omitempty"`
	Actions          map[string]int `json:"actions"`
	Drift            int            `json:"drift"`
	Deferred         int            `json:"deferred"`
	ChangedOutputs   []string       `json:"changed_outputs,omitempty"`
	PrimaryState     string         `json:"primary_state,omitempty"`
}

type Result struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Verdict     string         `json:"verdict"`
	States      []StateSummary `json:"states"`
	Plan        *PlanSummary   `json:"plan,omitempty"`
	Config      *ConfigSummary `json:"config,omitempty"`
	Findings    []Finding      `json:"findings"`
	Seeds       []string       `json:"seeds"`
	ApplyOrder  []string       `json:"apply_order,omitempty"`
	Simulation  *Simulation    `json:"simulation,omitempty"`
	Graph       *Graph         `json:"-"`
}

// ConfigSummary describes the optionally supplied configuration directory.
// It contains only the path and literal required_version.
type ConfigSummary struct {
	Path            string `json:"path"`
	RequiredVersion string `json:"required_version,omitempty"`
}

type analyzer struct {
	opts     Options
	states   []*state.State
	plan     *state.Plan
	primary  *state.State
	g        *Graph
	findings []Finding
	cfg      *tfconfig.Config
	// changed outputs of the primary state consumed by other states
	remoteLinks []remoteLink
	credLeft    *time.Duration
	order       []string
}

// Analyze runs every read-only check. It never modifies inputs on disk.
func Analyze(states []*state.State, plan *state.Plan, opts Options) (*Result, error) {
	opts.defaults()
	if len(states) == 0 && plan == nil {
		return nil, fmt.Errorf("nothing to analyze: provide at least one --state or a --plan")
	}
	a := &analyzer{opts: opts, states: states, plan: plan, g: NewGraph(), cfg: opts.Config}
	uniqueNames(a.states)

	if err := a.choosePrimary(); err != nil {
		return nil, err
	}
	for _, st := range a.states {
		buildStateGraph(a.g, st)
	}
	if a.plan != nil && a.primary != nil {
		a.applyPlan()
	}
	a.applyConfigMetadata()
	a.linkCrossState()
	a.analyzeFederation()
	seeds := a.computeCone()
	a.checkPlan()
	a.checkDrift()
	a.checkProvisioners()
	a.checkBlastRadius(seeds)
	a.checkStates()
	if a.opts.CheckCredentials {
		a.checkCredentials()
	}
	a.order = a.applyOrder()
	sim := a.simulate()
	if sim != nil && sim.Fails+sim.Blocked > 0 {
		var nodes []string
		for _, step := range sim.Steps {
			if step.Node != "" && (step.Outcome == OutcomeFail || step.Outcome == OutcomeBlocked) {
				nodes = appendUniqueStr(nodes, step.Node)
			}
		}
		a.add(Finding{Rule: "CW601", Severity: SevHigh, Category: CatPlan,
			Title:       "Pseudo-apply found an unavailable dependency or unresolved order",
			Detail:      "The offline model cannot complete these operations. This is a prediction, not an observed cloud failure; inspect the simulation limitations.",
			Remediation: "Review the affected dependency paths and per-instance actions in a fresh full plan before applying.", Nodes: nodes})
	}
	a.addFixes()

	sortFindings(a.findings)
	var configSummary *ConfigSummary
	if a.cfg != nil {
		configSummary = &ConfigSummary{Path: a.cfg.Path, RequiredVersion: a.cfg.RequiredVersion}
	}
	res := &Result{
		GeneratedAt: opts.Now,
		Verdict:     Verdict(a.findings),
		Config:      configSummary,
		Findings:    a.findings,
		Seeds:       seeds,
		ApplyOrder:  a.order,
		Simulation:  sim,
		Graph:       a.g,
	}
	if res.Findings == nil {
		res.Findings = []Finding{}
	}
	for _, st := range a.states {
		res.States = append(res.States, summarizeState(st, st == a.primary))
	}
	if a.plan != nil {
		res.Plan = a.summarizePlan()
	}
	return res, nil
}

func (a *analyzer) add(f Finding) {
	a.findings = append(a.findings, f)
}

// mask hides most of an identifier unless RevealIDs is set.
func (a *analyzer) mask(v string) string {
	if a.opts.RevealIDs || v == "" {
		return v
	}
	if len(v) <= 8 {
		return "****"
	}
	return v[:4] + "…" + v[len(v)-4:]
}

func uniqueNames(states []*state.State) {
	count := map[string]int{}
	for _, st := range states {
		count[st.Name]++
	}
	seen := map[string]int{}
	for _, st := range states {
		if count[st.Name] < 2 {
			continue
		}
		parent := filepath.Base(filepath.Dir(st.Path))
		name := parent + "/" + st.Name
		seen[name]++
		if seen[name] > 1 {
			name = fmt.Sprintf("%s#%d", name, seen[name])
		}
		st.Name = name
	}
}

func (a *analyzer) choosePrimary() error {
	if a.opts.PrimaryState != "" {
		want := a.opts.PrimaryState
		for _, st := range a.states {
			if st.Name == want || st.Path == want || filepath.Base(st.Path) == want ||
				filepath.Clean(st.Path) == filepath.Clean(want) {
				a.primary = st
				break
			}
		}
		if a.primary == nil {
			return fmt.Errorf("--primary-state %q does not match any --state", want)
		}
	}

	if a.plan == nil {
		if a.primary == nil && len(a.states) == 1 {
			a.primary = a.states[0]
		}
		return nil
	}

	prior := a.plan.PriorState
	if a.primary == nil && prior != nil {
		priorIDs := prior.InstanceIDs()
		best, bestScore := (*state.State)(nil), 0
		for _, st := range a.states {
			score := 0
			for addr, h := range st.InstanceIDs() {
				if priorIDs[addr] == h {
					score++
				}
			}
			if score > bestScore {
				best, bestScore = st, score
			}
		}
		a.primary = best
		if a.primary == nil && len(a.states) == 1 && len(priorIDs) == 0 {
			a.primary = a.states[0]
		}
	}

	if a.primary == nil {
		if prior == nil {
			prior = &state.State{Name: "plan", Format: state.FormatShowJSON}
		}
		prior.Name = "plan-prior-state"
		a.states = append(a.states, prior)
		a.primary = prior
		if len(a.states) > 1 {
			a.add(Finding{
				Rule:     "CW008",
				Severity: SevMedium,
				Category: CatPlan,
				Title:    "Plan does not match any provided state",
				Detail:   "No provided state shares resource IDs with the plan's prior state, so the plan was analyzed against its own embedded prior state.",
				Remediation: "Pass the state the plan was created from (terraform state pull > primary.tfstate) " +
					"or set --primary-state explicitly.",
			})
		}
	}
	return nil
}

var actionRank = map[string]int{
	state.ActionReplace: 7, state.ActionDelete: 6, state.ActionCreate: 5,
	state.ActionUpdate: 4, state.ActionForget: 3, state.ActionRead: 2, state.ActionNoop: 1,
}

func strongerAction(a, b string) string {
	if actionRank[b] > actionRank[a] {
		return b
	}
	return a
}

func (a *analyzer) applyConfigMetadata() {
	if a.cfg == nil || a.primary == nil {
		return
	}
	for addr, res := range a.cfg.Resources {
		for _, id := range a.g.Resolve(a.primary.Name, addr) {
			if n := a.g.Nodes[id]; n != nil {
				n.PreventDestroy = res.PreventDestroy
				n.CreateBeforeDestroy = res.CreateBeforeDestroy
				if res.Count {
					n.HasCount = true
				}
				if res.ForEach {
					n.HasForEach = true
				}
			}
		}
	}
}

func isMutation(action string) bool {
	switch action {
	case state.ActionCreate, state.ActionUpdate, state.ActionDelete, state.ActionReplace, state.ActionForget:
		return true
	}
	return false
}

func isDestructive(action string) bool {
	return action == state.ActionDelete || action == state.ActionReplace
}

func (a *analyzer) applyPlan() {
	ps := a.primary.Name
	for _, c := range a.plan.Changes {
		ids := a.g.Resolve(ps, c.Address)
		if len(ids) == 0 {
			n := a.g.AddNode(&Node{
				ID:       NodeID(ps, c.Address),
				State:    ps,
				Address:  c.Address,
				Module:   c.Module,
				Mode:     c.Mode,
				Type:     c.Type,
				Provider: c.Provider,
				Cloud:    c.Cloud,
				Planned:  true,
			})
			ids = []string{n.ID}
		}
		for _, id := range ids {
			n := a.g.Nodes[id]
			n.Action = strongerAction(n.Action, c.Action)
			if n.Planned {
				n.Instances++
			}
			if !isMutation(c.Action) {
				continue
			}
			for _, k := range c.ChangedAttrs {
				n.ChangedAttrs = appendUniqueStr(n.ChangedAttrs, k)
			}
			for _, k := range c.UnknownAttrs {
				n.UnknownAttrs = appendUniqueStr(n.UnknownAttrs, k)
			}
			for _, p := range c.ReplacePaths {
				n.ReplacePaths = appendUniqueStr(n.ReplacePaths, p)
			}
			if c.ActionReason != "" {
				n.Reasons = appendUniqueStr(n.Reasons, c.ActionReason)
			}
			n.SensitiveAttrs = max(n.SensitiveAttrs, c.SensitiveAttrs)
			n.Importing = n.Importing || c.Importing
		}
	}
	for _, d := range a.plan.Drifts {
		for _, id := range a.g.Resolve(ps, d.Address) {
			n := a.g.Nodes[id]
			n.Drift = strongerAction(n.Drift, d.Action)
		}
	}
	for addr, provs := range a.plan.ConfigProvisioners {
		for _, id := range a.g.Lookup(ps, addr) {
			n := a.g.Nodes[id]
			for _, p := range provs {
				n.Provisioners = appendUniqueStr(n.Provisioners, p)
			}
		}
	}
	for addr := range a.plan.ConfigCounts {
		for _, id := range a.g.Lookup(ps, addr) {
			a.g.Nodes[id].HasCount = true
		}
	}
	for addr := range a.plan.ConfigForEach {
		for _, id := range a.g.Lookup(ps, addr) {
			a.g.Nodes[id].HasForEach = true
		}
	}
	for from, deps := range a.plan.ConfigDeps {
		for _, fromID := range a.g.Lookup(ps, from) {
			fn := a.g.Nodes[fromID]
			if !fn.Planned && len(a.g.deps[fromID]) > 0 {
				continue
			}
			for _, dep := range deps {
				for _, toID := range a.g.Lookup(ps, dep) {
					a.g.AddEdge(Edge{From: fromID, To: toID, Kind: EdgeDependency, Evidence: "configuration reference"})
				}
			}
		}
	}
	for _, ref := range a.plan.RemoteStateRefs {
		for _, fromID := range a.g.Lookup(ps, ref.ResourceAddress) {
			for _, toID := range a.g.Lookup(ps, ref.DataAddress) {
				ev := "configuration reference"
				if ref.Output != "" {
					ev = "reads output " + ref.Output
				}
				a.g.AddEdge(Edge{From: fromID, To: toID, Kind: EdgeDependency, Evidence: ev})
			}
		}
	}
}

// computeCone marks changed nodes, their transitive dependents and their
// direct dependencies, and returns the seed IDs.
func (a *analyzer) computeCone() []string {
	var seeds []string
	for _, n := range a.g.SortedNodes() {
		if isMutation(n.Action) || (n.Drift != "" && n.Drift != state.ActionNoop) {
			n.Role = RoleSeed
			seeds = append(seeds, n.ID)
		}
	}
	if len(seeds) == 0 {
		return []string{}
	}
	for id, d := range a.g.Downstream(seeds) {
		n := a.g.Nodes[id]
		n.Role = RoleDownstream
		n.Distance = d
	}
	for id, d := range a.g.Upstream(seeds, 1) {
		n := a.g.Nodes[id]
		if n.Role == "" {
			n.Role = RoleUpstream
			n.Distance = -d
		}
	}
	for _, s := range seeds {
		n := a.g.Nodes[s]
		down := a.g.Downstream([]string{s})
		n.Impact = len(down)
		for id := range down {
			if a.g.Nodes[id].State != n.State {
				n.CrossImp++
			}
		}
	}
	return seeds
}

func summarizeState(st *state.State, primary bool) StateSummary {
	s := StateSummary{
		Name:             st.Name,
		Format:           st.Format,
		Source:           st.Source,
		TerraformVersion: st.TerraformVersion,
		Serial:           st.Serial,
		Lineage:          st.Lineage,
		Outputs:          len(st.Outputs),
		Clouds:           map[string]int{},
		Primary:          primary,
		FromPlan:         st.Source == state.SourcePlan,
	}
	for _, r := range st.Resources {
		if r.Mode == "data" {
			s.DataSources++
		} else {
			s.Resources++
		}
		s.Instances += len(r.Instances)
		s.Clouds[string(r.Cloud)]++
	}
	return s
}

func (a *analyzer) summarizePlan() *PlanSummary {
	p := a.plan
	s := &PlanSummary{
		TerraformVersion: p.TerraformVersion,
		Complete:         p.Complete,
		Applyable:        p.Applyable,
		Errored:          p.Errored,
		Actions:          map[string]int{},
		Drift:            len(p.Drifts),
		Deferred:         len(p.Deferred),
		ChangedOutputs:   p.ChangedOutputs,
	}
	if p.Timestamp != nil {
		s.Timestamp = p.Timestamp.UTC().Format(time.RFC3339)
		age := int(a.opts.Now.Sub(*p.Timestamp).Minutes())
		s.AgeMinutes = &age
	}
	for _, c := range p.Changes {
		s.Actions[c.Action]++
	}
	if a.primary != nil {
		s.PrimaryState = a.primary.Name
	}
	return s
}

func nodeList(ids map[string]bool) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func joinLimited(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" and %d more", len(items)-max)
}
