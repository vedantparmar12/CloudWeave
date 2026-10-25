package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	version "github.com/hashicorp/go-version"
	"github.com/vedantparmar12/cloudweave/internal/state"
	"github.com/vedantparmar12/cloudweave/internal/tfconfig"
)

func (a *analyzer) checkPlan() {
	p := a.plan
	if p == nil {
		return
	}
	if p.Errored != nil && *p.Errored {
		a.add(Finding{
			Rule: "CW001", Severity: SevCritical, Category: CatPlan,
			Title:       "Plan errored",
			Detail:      "Terraform reported errors while planning; the plan is partial and must not be applied.",
			Remediation: "Fix the plan errors and re-run terraform plan.",
		})
	}
	if p.Complete != nil && !*p.Complete {
		detail := "The plan is incomplete: it was created with -target or some changes were deferred, so it does not converge the whole configuration."
		if len(p.Deferred) > 0 {
			detail = fmt.Sprintf("%d changes were deferred until after apply (unknown values, for_each/count on unknowns, or provider deferral). The apply will not converge and a follow-up plan is required.", len(p.Deferred))
		}
		a.add(Finding{
			Rule: "CW002", Severity: SevHigh, Category: CatPlan,
			Title:       "Plan is incomplete (targeted or deferred)",
			Detail:      detail,
			Remediation: "Avoid -target for routine changes; plan again after apply to confirm convergence.",
		})
	}
	if p.Applyable != nil && !*p.Applyable {
		a.add(Finding{
			Rule: "CW007", Severity: SevInfo, Category: CatPlan,
			Title:  "Plan has nothing to apply",
			Detail: "Terraform marked this plan as not applyable (no changes).",
		})
	}
	if p.Timestamp != nil {
		age := a.opts.Now.Sub(*p.Timestamp)
		if age > a.opts.PlanMaxAge {
			sev := SevMedium
			if age > 24*time.Hour {
				sev = SevHigh
			}
			a.add(Finding{
				Rule: "CW003", Severity: sev, Category: CatPlan,
				Title: "Saved plan is old",
				Detail: fmt.Sprintf("The plan was created %s ago. Cloud resources, credentials and other states may have changed since; "+
					"Terraform will also reject a saved plan if the state serial moved.", roundDuration(age)),
				Remediation: "Re-run terraform plan immediately before apply.",
			})
		}
	}
	a.checkVersionSkew()
	a.checkPriorState()
	a.checkFederationChanges()
	a.checkRemovedConfig()
	a.checkLifecycleContradiction()
	a.checkConsumedOutputs()
}

// checkProvisioners flags changed resources that run provisioners at apply
// time. Plans never execute provisioners, so their failures are invisible to
// terraform plan. Only provisioner types are reported, never their commands.
func (a *analyzer) checkProvisioners() {
	if a.plan == nil || a.primary == nil {
		return
	}
	var nodes, types []string
	for _, n := range a.g.SortedNodes() {
		if n.State != a.primary.Name || !isMutation(n.Action) || len(n.Provisioners) == 0 {
			continue
		}
		nodes = append(nodes, n.ID)
		for _, p := range n.Provisioners {
			types = appendUniqueStr(types, p)
		}
	}
	if len(nodes) == 0 {
		return
	}
	sort.Strings(types)
	a.add(Finding{
		Rule: "CW602", Severity: SevMedium, Category: CatPlan,
		Title: "Apply runs provisioners on changed resources",
		Detail: fmt.Sprintf("%d changed resources run provisioners (%s). terraform plan never executes provisioners, so missing tools, network access or credentials appear only during apply.",
			len(nodes), strings.Join(types, ", ")),
		Remediation: "Review each provisioner's runtime needs with its owner before apply; prefer provider features or native resources over shell steps, and never place secrets in provisioner commands.",
		Nodes:       nodes,
	})
}

func roundDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%.1f hours", d.Hours())
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}

func (a *analyzer) checkVersionSkew() {
	if a.primary == nil || a.primary.Name == "plan-prior-state" {
		return
	}
	sv, err1 := version.NewVersion(a.primary.TerraformVersion)
	pv, err2 := version.NewVersion(a.plan.TerraformVersion)
	if err1 != nil || err2 != nil {
		return
	}
	switch {
	case sv.GreaterThan(pv):
		a.add(Finding{
			Rule: "CW005", Severity: SevHigh, Category: CatPlan,
			Title:       "State was written by a newer Terraform than the plan",
			Detail:      fmt.Sprintf("State says Terraform %s, plan was made with %s. Older Terraform refuses to apply against state written by a newer version.", sv, pv),
			Remediation: "Use the same Terraform version for plan and apply (pin it with required_version and in CI).",
		})
	case pv.Segments()[0] != sv.Segments()[0] || pv.Segments()[1] != sv.Segments()[1]:
		a.add(Finding{
			Rule: "CW005", Severity: SevLow, Category: CatPlan,
			Title:       "Apply will upgrade the state's Terraform version",
			Detail:      fmt.Sprintf("State says Terraform %s, plan was made with %s. After apply, anyone on the older version can no longer use this state.", sv, pv),
			Remediation: "Upgrade Terraform everywhere that touches this state together.",
		})
	}
}

// checkPriorState compares the provided primary state with the prior state
// embedded in the plan. A mismatch means the plan was built against a
// different snapshot.
func (a *analyzer) checkPriorState() {
	prior := a.plan.PriorState
	if prior == nil || a.primary == nil || a.primary == prior {
		return
	}
	deletedByDrift := map[string]bool{}
	for _, d := range a.plan.Drifts {
		if d.Action == state.ActionDelete {
			deletedByDrift[d.InstanceAddress] = true
		}
	}
	priorIDs := managedIDs(prior)
	stateIDs := managedIDs(a.primary)

	var missing, extra, changed []string
	for addr, h := range stateIDs {
		ph, ok := priorIDs[addr]
		switch {
		case !ok && !deletedByDrift[addr]:
			missing = append(missing, addr)
		case ok && ph != h:
			changed = append(changed, addr)
		}
	}
	for addr := range priorIDs {
		if _, ok := stateIDs[addr]; !ok {
			extra = append(extra, addr)
		}
	}
	if len(missing)+len(extra)+len(changed) == 0 {
		return
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(changed)
	detail := "The state you provided is not the snapshot this plan was built from."
	if len(changed) > 0 {
		detail += fmt.Sprintf(" %d resources have a different ID (replaced since plan: %s).", len(changed), joinLimited(changed, 5))
	}
	if len(extra) > 0 {
		detail += fmt.Sprintf(" %d resources exist in the plan but not in the state (%s).", len(extra), joinLimited(extra, 5))
	}
	if len(missing) > 0 {
		detail += fmt.Sprintf(" %d resources exist in the state but not in the plan (%s).", len(missing), joinLimited(missing, 5))
	}
	detail += " Either someone applied after this plan was made, or the wrong state file was supplied."
	a.add(Finding{
		Rule: "CW004", Severity: SevHigh, Category: CatPlan,
		Title:       "Plan and state disagree",
		Detail:      detail,
		Remediation: "Pull the current state (terraform state pull) and re-plan; never apply a plan made against an older snapshot.",
	})
}

func managedIDs(st *state.State) map[string]string {
	out := map[string]string{}
	for _, r := range st.Resources {
		if r.Mode != "managed" {
			continue
		}
		for _, inst := range r.Instances {
			if inst.Deposed != "" {
				continue
			}
			if s, ok := inst.Attributes["id"].(string); ok && s != "" {
				out[inst.Address] = state.HashValue(s)
			}
		}
	}
	return out
}

// cfgResource finds a configuration fact by address, tolerating module
// instance keys (module.vpc["a"].x) because --config records none.
func (a *analyzer) cfgResource(addr string) (tfconfig.Resource, bool) {
	if a.cfg == nil {
		return tfconfig.Resource{}, false
	}
	if res, ok := a.cfg.Resources[addr]; ok {
		return res, true
	}
	res, ok := a.cfg.Resources[state.StripAllKeys(addr)]
	return res, ok
}

func (a *analyzer) checkRemovedConfig() {
	var nodes []string
	seen := map[string]bool{}
	for _, c := range a.plan.Changes {
		if c.ActionReason != "delete_because_no_resource_config" && c.ActionReason != "delete_because_no_module" {
			continue
		}
		id := NodeID(a.primary.Name, c.Address)
		if !seen[id] {
			seen[id] = true
			nodes = append(nodes, id)
		}
	}
	if len(nodes) == 0 {
		return
	}
	detail := fmt.Sprintf("%d resources lost their configuration block. If they were moved to another state or module, applying this plan deletes live infrastructure.", len(nodes))
	if a.cfg != nil {
		var stillConfigured, absent []string
		for _, id := range nodes {
			if n := a.g.Nodes[id]; n != nil {
				if _, ok := a.cfgResource(n.Address); ok {
					stillConfigured = append(stillConfigured, n.Address)
				} else {
					absent = append(absent, n.Address)
				}
			}
		}
		if len(stillConfigured) > 0 {
			detail += fmt.Sprintf(" %d of them are still declared in the provided configuration directory (%s); confirm count/for_each did not evaluate to zero rather than assuming a move.",
				len(stillConfigured), joinLimited(stillConfigured, 5))
		}
		if len(absent) > 0 {
			detail += fmt.Sprintf(" %d of them are confirmed absent from the provided configuration directory.", len(absent))
			if a.cfg.UnresolvedModules {
				detail += " Some module sources (registry, remote or dynamic) could not be read, so this absence is not fully confirmed."
			}
		}
	}
	a.add(Finding{
		Rule: "CW206", Severity: SevHigh, Category: CatPlan,
		Title:       "Resources will be destroyed because their configuration was removed",
		Detail:      detail,
		Remediation: "For a same-state move, retain destination configuration and use a reviewed `moved` block. For a cross-state ownership transfer, pause competing runs and take protected backups, coordinate non-destructive removal only in the relinquishing state with import into exactly one destination owner, and review full plans for both states to prevent destruction or recreation.",
		Nodes:       nodes,
	})
}

// checkLifecycleContradiction flags replacements whose recorded order destroys
// the current object first even though the configuration declares
// create_before_destroy. Only addresses present in the provided configuration
// directory can be checked.
func (a *analyzer) checkLifecycleContradiction() {
	if a.cfg == nil || a.primary == nil {
		return
	}
	var nodes []string
	for _, c := range a.plan.Changes {
		if len(c.Actions) != 2 || c.Actions[0] != state.ActionDelete || c.Actions[1] != state.ActionCreate {
			continue
		}
		res, ok := a.cfgResource(c.Address)
		if !ok || !res.CreateBeforeDestroy {
			continue
		}
		for _, id := range a.g.Resolve(a.primary.Name, c.Address) {
			nodes = appendUniqueStr(nodes, id)
		}
	}
	if len(nodes) == 0 {
		return
	}
	a.add(Finding{
		Rule: "CW603", Severity: SevMedium, Category: CatPlan,
		Title: "Replacement order contradicts create_before_destroy",
		Detail: fmt.Sprintf("%d replacements destroy the current object before creating its successor although the configuration declares create_before_destroy. Consumers may lose the object before its replacement exists.",
			len(nodes)),
		Remediation: "Investigate deposed objects and provider behavior with the owner, confirm consumers tolerate any gap, and review a new full plan before applying.",
		Nodes:       nodes,
	})
}

func (a *analyzer) checkConsumedOutputs() {
	if len(a.plan.ChangedOutputs) == 0 {
		return
	}
	changed := map[string]bool{}
	for _, o := range a.plan.ChangedOutputs {
		changed[o] = true
	}
	for _, link := range a.remoteLinks {
		if link.Producer != a.primary.Name {
			continue
		}
		var hit []string
		for _, o := range link.Outputs {
			if changed[o] {
				hit = append(hit, o)
			}
		}
		if len(hit) == 0 {
			continue
		}
		a.add(Finding{
			Rule: "CW204", Severity: SevMedium, Category: CatCrossState,
			Title: "Changed outputs are consumed by another state",
			Detail: fmt.Sprintf("%s reads [%s] from this state through terraform_remote_state. It keeps the old values until it is planned and applied again.",
				link.Consumer, joinLimited(hit, 6)),
			Remediation: "After this apply, plan " + link.Consumer + " and apply it before relying on the new values.",
			Nodes:       []string{link.DataNode},
		})
	}
}

func (a *analyzer) checkDrift() {
	if a.plan == nil || a.primary == nil || len(a.plan.Drifts) == 0 {
		return
	}
	deleted := map[string]bool{}
	overlap := map[string]bool{}
	upstream := map[string]bool{}
	other := map[string]bool{}
	for _, d := range a.plan.Drifts {
		for _, id := range a.g.Resolve(a.primary.Name, d.Address) {
			n := a.g.Nodes[id]
			switch {
			case d.Action == state.ActionDelete:
				deleted[id] = true
			case isMutation(n.Action):
				overlap[id] = true
			case a.feedsChange(id):
				upstream[id] = true
			default:
				other[id] = true
			}
		}
	}
	if len(deleted) > 0 {
		a.add(Finding{
			Rule: "CW102", Severity: SevHigh, Category: CatDrift,
			Title:       "Resources were deleted outside Terraform",
			Detail:      fmt.Sprintf("%d resources no longer exist in the cloud. The plan recreates them with new IDs, which breaks anything that referenced the old IDs (including other states).", len(deleted)),
			Remediation: "Find out why they were deleted (manual cleanup, policy, expiry) before letting Terraform recreate them.",
			Nodes:       nodeList(deleted),
		})
	}
	if len(overlap) > 0 {
		a.add(Finding{
			Rule: "CW101", Severity: SevHigh, Category: CatDrift,
			Title:       "Drift overlaps planned changes",
			Detail:      fmt.Sprintf("%d resources were changed outside Terraform and are also changed by this plan. Applying overwrites the out-of-band change, and if the object keeps changing between plan and apply the provider can fail on a conflict or etag mismatch.", len(overlap)),
			Remediation: "Confirm the manual change should be reverted, or codify it, then re-plan right before apply.",
			Nodes:       nodeList(overlap),
		})
	}
	if len(upstream) > 0 {
		a.add(Finding{
			Rule: "CW103", Severity: SevMedium, Category: CatDrift,
			Title:       "Drifted resources feed planned changes",
			Detail:      fmt.Sprintf("%d drifted resources are dependencies of resources this plan changes; the changes are computed from the drifted values.", len(upstream)),
			Remediation: "Review the drift with terraform plan -refresh-only before applying.",
			Nodes:       nodeList(upstream),
		})
	}
	if len(other) > 0 {
		a.add(Finding{
			Rule: "CW104", Severity: SevLow, Category: CatDrift,
			Title:       "Resources drifted outside Terraform",
			Detail:      fmt.Sprintf("%d resources changed outside Terraform. Apply will record the new values in state.", len(other)),
			Remediation: "Run terraform plan -refresh-only to review, and codify intentional changes.",
			Nodes:       nodeList(other),
		})
	}
}

// feedsChange reports whether any direct dependent of id is being changed.
func (a *analyzer) feedsChange(id string) bool {
	for _, e := range a.g.Dependents(id) {
		if isMutation(a.g.Nodes[e.From].Action) {
			return true
		}
	}
	return false
}

func (a *analyzer) checkBlastRadius(seeds []string) {
	destructive := map[string]bool{}
	wide := map[string]bool{}
	for _, id := range seeds {
		n := a.g.Nodes[id]
		if isDestructive(n.Action) {
			destructive[id] = true
			if n.CrossImp > 0 {
				var cross []string
				for dep := range a.g.Downstream([]string{id}) {
					if a.g.Nodes[dep].State != n.State {
						cross = append(cross, dep)
					}
				}
				sort.Strings(cross)
				a.add(Finding{
					Rule: "CW201", Severity: SevCritical, Category: CatBlast,
					Title: fmt.Sprintf("%s %s is used by other states", n.Action, n.Address),
					Detail: fmt.Sprintf("%d resources in other states depend on it (%s). They keep pointing at the old object until their own state is re-applied, and Terraform here cannot see them.",
						len(cross), joinLimited(cross, 5)),
					Remediation: "Verify independent working credentials that do not rely on the changing identity or trust before staging parallel identities or resources with reviewed full, non-targeted plans. Retain the old object and trust in configuration until all consumers have migrated and verified token exchange and required API authorization; never use targeted federation changes as a shortcut.",
					Nodes:       append([]string{id}, cross...),
				})
			}
		}
		if n.Impact >= a.opts.BlastRadius {
			wide[id] = true
		}
	}
	if len(destructive) > 0 {
		a.add(Finding{
			Rule: "CW202", Severity: SevMedium, Category: CatBlast,
			Title:       fmt.Sprintf("%d resources will be deleted or replaced", len(destructive)),
			Detail:      "Deletes and replacements are where apply-time failures (dependency locks, deletion protection, resources still in use) and outages happen.",
			Remediation: "Review each destructive change in the change cone view.",
			Nodes:       nodeList(destructive),
		})
	}
	if len(wide) > 0 {
		a.add(Finding{
			Rule: "CW203", Severity: SevMedium, Category: CatBlast,
			Title:       "High blast radius",
			Detail:      fmt.Sprintf("%d changed resources each have at least %d transitive dependents.", len(wide), a.opts.BlastRadius),
			Remediation: "Consider splitting the change or applying during a maintenance window.",
			Nodes:       nodeList(wide),
		})
	}
}

func (a *analyzer) checkStates() {
	tainted := map[string]bool{}
	deposed := map[string]bool{}
	byLineage := map[string][]*state.State{}
	for _, st := range a.states {
		if st.Lineage != "" {
			byLineage[st.Lineage] = append(byLineage[st.Lineage], st)
		}
		if st.Path != "" && st.Name != "plan-prior-state" {
			lock := filepath.Join(filepath.Dir(st.Path), ".terraform.tfstate.lock.info")
			if _, err := os.Stat(lock); err == nil {
				a.add(Finding{
					Rule: "CW006", Severity: SevHigh, Category: CatState,
					Title:       "State lock file present next to " + st.Name,
					Detail:      "A local lock file exists, so another Terraform process may be running against this state or crashed while holding the lock.",
					Remediation: "Confirm no run is active. Only then use terraform force-unlock with the lock ID; never delete the file by hand during a run.",
				})
			}
		}
		for _, r := range st.Resources {
			id := NodeID(st.Name, r.Address)
			if r.Tainted {
				tainted[id] = true
			}
			for _, inst := range r.Instances {
				if inst.Deposed != "" {
					deposed[id] = true
				}
			}
		}
	}
	if len(tainted) > 0 {
		a.add(Finding{
			Rule: "CW205", Severity: SevMedium, Category: CatState,
			Title:       "Tainted resources will be replaced",
			Detail:      fmt.Sprintf("%d resources are tainted (usually from a failed create). The next apply destroys and recreates them.", len(tainted)),
			Remediation: "Investigate the failed operation's root cause and verify object health before deciding whether replacement is appropriate. Do not clear a taint merely to suppress replacement; any manual state change requires owner review, a protected backup, and a new full plan afterward.",
			Nodes:       nodeList(tainted),
		})
	}
	if len(deposed) > 0 {
		a.add(Finding{
			Rule: "CW205", Severity: SevMedium, Category: CatState,
			Title:       "Deposed objects left from a failed replacement",
			Detail:      fmt.Sprintf("%d resources have deposed instances: a create_before_destroy replacement failed half-way. The next apply tries to delete the old objects.", len(deposed)),
			Remediation: "Check that nothing still uses the old objects before applying.",
			Nodes:       nodeList(deposed),
		})
	}
	for _, group := range byLineage {
		if len(group) < 2 {
			continue
		}
		var names []string
		for _, st := range group {
			label := st.Name
			if st.Serial != nil {
				label = fmt.Sprintf("%s (serial %d)", st.Name, *st.Serial)
			}
			names = append(names, label)
		}
		a.add(Finding{
			Rule: "CW011", Severity: SevMedium, Category: CatState,
			Title:       "Two inputs are versions of the same state",
			Detail:      "These files share a lineage: " + joinLimited(names, 5) + ". Analyzing an old copy hides recent changes and creates false cross-state links.",
			Remediation: "Pass only the latest snapshot of each state (terraform state pull).",
		})
	}
}
