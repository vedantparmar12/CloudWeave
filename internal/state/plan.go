package state

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	tfjson "github.com/hashicorp/terraform-json"
)

const (
	ActionCreate  = "create"
	ActionUpdate  = "update"
	ActionDelete  = "delete"
	ActionReplace = "replace"
	ActionRead    = "read"
	ActionNoop    = "no-op"
	ActionForget  = "forget"
)

// Change is a normalized Terraform resource change.
type Change struct {
	Address         string // resource address (no instance key)
	InstanceAddress string // exact address including index
	Module          string
	Mode            string
	Type            string
	Name            string
	Provider        string
	Cloud           Cloud
	Actions         []string
	Action          string
	Drift           bool
	DriftActions    []string
	ActionReason    string
	ReplacePaths    []string
	Importing       bool
	Deposed         string
	// ChangedAttrs and UnknownAttrs hold top-level attribute names only;
	// values are compared in memory and never retained.
	ChangedAttrs []string
	UnknownAttrs []string
	// SensitiveAttrs counts touched attributes Terraform marks sensitive;
	// their names are left out of every list above.
	SensitiveAttrs int
}

// DeferredChange is a change Terraform deferred until apply.
type DeferredChange struct {
	Address string
	Reason  string
}

// RemoteStateRef is an explicit configuration reference to a
// terraform_remote_state output.
type RemoteStateRef struct {
	ResourceAddress string // resource whose configuration contains the reference
	DataAddress     string // normalized data.terraform_remote_state.<name>
	Output          string // output name; empty means the whole data source
}

// Plan is a normalized Terraform plan.
type Plan struct {
	Path             string
	FormatVersion    string
	TerraformVersion string
	Timestamp        *time.Time
	Complete         *bool
	Applyable        *bool
	Errored          *bool
	Changes          []Change
	Drifts           []Change
	Deferred         []DeferredChange
	PriorState       *State
	RemoteStateRefs  []RemoteStateRef
	// ConfigDeps maps a resource address (no instance keys) to the resource
	// addresses its configuration references.
	ConfigDeps map[string][]string
	// ConfigProvisioners maps resource addresses to provisioner types
	// (e.g. local-exec). Provisioner commands are never read.
	ConfigProvisioners map[string][]string
	// ConfigCounts lists resource addresses with a count expression.
	ConfigCounts map[string]bool
	// ConfigForEach lists resource addresses with a for_each expression.
	ConfigForEach  map[string]bool
	ChangedOutputs []string
}

// LoadPlan reads the JSON output of `terraform show -json <planfile>`.
func LoadPlan(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plan %s: %w", path, err)
	}

	var probe stateProbe
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse plan %s: %w", path, err)
	}
	if len(probe.ResourceChanges) == 0 && probe.FormatVersion == "" && probe.Version != nil {
		return nil, fmt.Errorf("%s looks like Terraform state, not a plan; pass it with --state", path)
	}

	var raw tfjson.Plan
	raw.UseJSONNumber(true)
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode plan %s: %w", path, err)
	}

	plan := &Plan{
		Path:             path,
		FormatVersion:    raw.FormatVersion,
		TerraformVersion: raw.TerraformVersion,
		Complete:         raw.Complete,
	}
	for name, oc := range raw.OutputChanges {
		if oc != nil && !oc.Actions.NoOp() && len(oc.Actions) > 0 {
			plan.ChangedOutputs = append(plan.ChangedOutputs, name)
		}
	}
	sort.Strings(plan.ChangedOutputs)
	if raw.Timestamp != "" {
		if ts, err := parseTimestamp(raw.Timestamp); err == nil {
			plan.Timestamp = &ts
		}
	}

	var extra struct {
		Applyable *bool `json:"applyable"`
		Errored   *bool `json:"errored"`
	}
	if err := json.Unmarshal(data, &extra); err == nil {
		plan.Applyable = extra.Applyable
		plan.Errored = extra.Errored
	}

	for _, rc := range raw.ResourceChanges {
		if c, ok := normalizeChange(rc, false); ok {
			plan.Changes = append(plan.Changes, c)
		}
	}
	for _, rc := range raw.ResourceDrift {
		if c, ok := normalizeChange(rc, true); ok {
			plan.Drifts = append(plan.Drifts, c)
		}
	}
	for _, dc := range raw.DeferredChanges {
		d := DeferredChange{Reason: dc.Reason}
		if dc.ResourceChange != nil {
			d.Address = dc.ResourceChange.Address
		}
		plan.Deferred = append(plan.Deferred, d)
	}

	if raw.PriorState != nil && raw.PriorState.Values != nil {
		prior := &State{
			Name:             "plan-prior-state",
			Path:             path,
			Format:           FormatShowJSON,
			Source:           SourcePlan,
			TerraformVersion: raw.PriorState.TerraformVersion,
		}
		for outName, out := range raw.PriorState.Values.Outputs {
			if out == nil {
				continue
			}
			prior.AddOutput(&Output{Name: outName, Sensitive: out.Sensitive, Value: out.Value})
		}
		addShowJSONModule(prior, raw.PriorState.Values.RootModule)
		plan.PriorState = prior
	}

	plan.RemoteStateRefs, plan.ConfigDeps, plan.ConfigProvisioners, plan.ConfigCounts, plan.ConfigForEach = analyzeConfig(raw.Config)

	return plan, nil
}

func normalizeChange(rc *tfjson.ResourceChange, drift bool) (Change, bool) {
	if rc == nil || rc.Change == nil {
		return Change{}, false
	}
	info, err := ParseAddress(rc.Address)
	if err != nil {
		return Change{}, false
	}
	c := Change{
		Address:         info.Address,
		InstanceAddress: rc.Address,
		Module:          info.Module,
		Mode:            info.Mode,
		Type:            info.Type,
		Name:            info.Name,
		Provider:        ProviderShort(rc.ProviderName),
		Cloud:           CloudFor(info.Type, rc.ProviderName),
		ActionReason:    string(rc.ActionReason),
		Drift:           drift,
		Importing:       rc.Change.Importing != nil,
		Deposed:         rc.DeposedKey,
	}
	for _, a := range rc.Change.Actions {
		c.Actions = append(c.Actions, string(a))
	}
	c.Action = CanonicalAction(rc.Change.Actions)
	if drift {
		c.DriftActions = append([]string{}, c.Actions...)
	}
	allSensitive, sensitive := sensitiveKeys(rc.Change.BeforeSensitive, rc.Change.AfterSensitive)
	hidden := map[string]bool{}
	visible := func(names []string) []string {
		var out []string
		for _, k := range names {
			if allSensitive || sensitive[k] {
				hidden[k] = true
			} else {
				out = append(out, k)
			}
		}
		return out
	}
	for _, p := range rc.Change.ReplacePaths {
		if steps, ok := p.([]any); ok && len(steps) > 0 {
			if k, ok := steps[0].(string); ok && len(visible([]string{k})) == 0 {
				continue
			}
		} else if allSensitive {
			hidden["(path)"] = true
			continue
		}
		c.ReplacePaths = appendUnique(c.ReplacePaths, formatPath(p))
	}
	if c.Action == ActionUpdate || c.Action == ActionReplace {
		changed, pending := attrDiff(rc.Change.Before, rc.Change.After, rc.Change.AfterUnknown)
		c.ChangedAttrs, c.UnknownAttrs = visible(changed), visible(pending)
	}
	c.SensitiveAttrs = len(hidden)
	return c, true
}

// sensitiveKeys returns the top-level attributes marked sensitive in either
// before_sensitive or after_sensitive, or true when the whole object is.
func sensitiveKeys(marks ...any) (bool, map[string]bool) {
	keys := map[string]bool{}
	for _, m := range marks {
		switch x := m.(type) {
		case bool:
			if x {
				return true, keys
			}
		case map[string]any:
			for k, v := range x {
				if containsTrue(v) {
					keys[k] = true
				}
			}
		}
	}
	return false, keys
}

// attrDiff returns the sorted top-level attribute names whose value differs
// between before and after, and those whose new value is unknown until apply.
func attrDiff(before, after, unknown any) (changed, pending []string) {
	b, _ := before.(map[string]any)
	a, _ := after.(map[string]any)
	u, _ := unknown.(map[string]any)
	for k, v := range u {
		if containsTrue(v) {
			pending = append(pending, k)
		}
	}
	isPending := map[string]bool{}
	for _, k := range pending {
		isPending[k] = true
	}
	keys := map[string]bool{}
	if b != nil && a != nil {
		for k := range b {
			keys[k] = true
		}
		for k := range a {
			keys[k] = true
		}
	}
	for k := range keys {
		if isPending[k] {
			continue
		}
		if canonicalJSON(b[k]) != canonicalJSON(a[k]) {
			changed = append(changed, k)
		}
	}
	sort.Strings(changed)
	sort.Strings(pending)
	return changed, pending
}

func containsTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case map[string]any:
		for _, e := range x {
			if containsTrue(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if containsTrue(e) {
				return true
			}
		}
	}
	return false
}

func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// formatPath renders a replace path such as ["network",0,"subnet"] as
// network[0].subnet.
func formatPath(v any) string {
	steps, ok := v.([]any)
	if !ok {
		return pathString(v)
	}
	var sb strings.Builder
	for _, s := range steps {
		switch x := s.(type) {
		case string:
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.WriteString(x)
		default:
			sb.WriteString("[" + pathString(x) + "]")
		}
	}
	return sb.String()
}

// CanonicalAction reduces a Terraform action list to one label.
func CanonicalAction(actions tfjson.Actions) string {
	switch {
	case actions.Replace():
		return ActionReplace
	case actions.Create():
		return ActionCreate
	case actions.Update():
		return ActionUpdate
	case actions.Delete():
		return ActionDelete
	case actions.Read():
		return ActionRead
	case actions.NoOp():
		return ActionNoop
	case actions.Forget():
		return ActionForget
	default:
		if len(actions) == 0 {
			return ""
		}
		parts := make([]string, 0, len(actions))
		for _, a := range actions {
			parts = append(parts, string(a))
		}
		return strings.Join(parts, "+")
	}
}

func pathString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return fmt.Sprintf("%v", x)
	case json.RawMessage:
		return string(x)
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprint(x)
		}
		return strings.Trim(string(b), `"`)
	}
}

func parseTimestamp(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z0700",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized plan timestamp %q", s)
}

// analyzeConfig walks the plan configuration and returns explicit
// terraform_remote_state references, resource-to-resource references, and
// per-resource metadata (provisioner types and count/for_each presence).
// Only names and flags are collected; expression values are never read.
func analyzeConfig(cfg *tfjson.Config) (refs []RemoteStateRef, deps, provisioners map[string][]string, counted, forEached map[string]bool) {
	if cfg == nil {
		return nil, nil, nil, nil, nil
	}
	deps = map[string][]string{}
	provisioners = map[string][]string{}
	counted = map[string]bool{}
	forEached = map[string]bool{}
	walkConfigModule(cfg.RootModule, "", func(prefix, resAddr string, cr *tfjson.ConfigResource) {
		for _, ref := range gatherReferences(cr) {
			if dataAddr, output, ok := parseRemoteStateReference(ref); ok {
				if prefix != "" && !strings.HasPrefix(dataAddr, "module.") {
					dataAddr = prefix + "." + dataAddr
				}
				refs = append(refs, RemoteStateRef{
					ResourceAddress: resAddr,
					DataAddress:     dataAddr,
					Output:          output,
				})
			}
			if dep, ok := configRefToAddress(ref, prefix); ok && dep != resAddr {
				deps[resAddr] = appendUnique(deps[resAddr], dep)
			}
		}
		for _, p := range cr.Provisioners {
			if p != nil && p.Type != "" {
				provisioners[resAddr] = appendUnique(provisioners[resAddr], p.Type)
			}
		}
		if cr.CountExpression != nil {
			counted[resAddr] = true
		}
		if cr.ForEachExpression != nil {
			forEached[resAddr] = true
		}
	})
	// Expression maps iterate in random order; sort so reports are deterministic.
	for addr := range deps {
		sort.Strings(deps[addr])
	}
	for addr := range provisioners {
		sort.Strings(provisioners[addr])
	}
	return dedupeRefs(refs), deps, provisioners, counted, forEached
}

func walkConfigModule(mod *tfjson.ConfigModule, prefix string, fn func(prefix, addr string, cr *tfjson.ConfigResource)) {
	if mod == nil {
		return
	}
	for _, cr := range mod.Resources {
		if cr == nil {
			continue
		}
		addr := cr.Address
		if prefix != "" {
			addr = prefix + "." + addr
		}
		if n, ok := NormalizeAddress(addr); ok {
			addr = n
		}
		fn(prefix, addr, cr)
	}
	for name, call := range mod.ModuleCalls {
		if call == nil {
			continue
		}
		childPrefix := "module." + name
		if prefix != "" {
			childPrefix = prefix + "." + childPrefix
		}
		walkConfigModule(call.Module, childPrefix, fn)
	}
}

func gatherReferences(cr *tfjson.ConfigResource) []string {
	var refs []string
	var addExpr func(*tfjson.Expression)
	addExpr = func(e *tfjson.Expression) {
		if e == nil || e.ExpressionData == nil {
			return
		}
		refs = append(refs, e.References...)
		for _, block := range e.NestedBlocks {
			for _, nested := range block {
				addExpr(nested)
			}
		}
	}
	for _, e := range cr.Expressions {
		addExpr(e)
	}
	addExpr(cr.CountExpression)
	addExpr(cr.ForEachExpression)
	for _, p := range cr.Provisioners {
		if p == nil {
			continue
		}
		for _, e := range p.Expressions {
			addExpr(e)
		}
	}
	refs = append(refs, cr.DependsOn...)
	return refs
}

// configRefToAddress turns a module-relative configuration reference such as
// "azurerm_resource_group.rg.name" into an absolute resource address without
// instance keys.
func configRefToAddress(ref, prefix string) (string, bool) {
	parts := splitAddress(ref)
	if len(parts) < 2 {
		return "", false
	}
	var addr string
	switch stripInstanceKey(parts[0]) {
	case "var", "local", "module", "each", "count", "path", "terraform", "self":
		return "", false
	case "data":
		if len(parts) < 3 {
			return "", false
		}
		typ, name := stripInstanceKey(parts[1]), stripInstanceKey(parts[2])
		if !validIdent(typ) || !validIdent(name) {
			return "", false
		}
		addr = "data." + typ + "." + name
	default:
		typ, name := stripInstanceKey(parts[0]), stripInstanceKey(parts[1])
		if !validIdent(typ) || !validIdent(name) {
			return "", false
		}
		addr = typ + "." + name
	}
	if prefix != "" {
		addr = prefix + "." + addr
	}
	return addr, true
}

// parseRemoteStateReference recognizes references such as
// data.terraform_remote_state.network.outputs.vpc_id and returns the data
// source address and output name.
func parseRemoteStateReference(ref string) (string, string, bool) {
	parts := splitAddress(ref)
	for i := 0; i+2 < len(parts); i++ {
		if stripInstanceKey(parts[i]) != "data" || stripInstanceKey(parts[i+1]) != "terraform_remote_state" {
			continue
		}
		name := stripInstanceKey(parts[i+2])
		if !validIdent(name) {
			return "", "", false
		}
		dataAddr := "data.terraform_remote_state." + name
		if i > 0 {
			dataAddr = strings.Join(parts[:i], ".") + "." + dataAddr
		}
		output := ""
		if i+3 < len(parts) {
			next := parts[i+3]
			switch {
			case next == "outputs" && i+4 < len(parts):
				output = stripInstanceKey(parts[i+4])
			case strings.HasPrefix(next, "outputs["):
				output = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(next, "outputs["), "]"), `"'`)
			}
		}
		return dataAddr, output, true
	}
	return "", "", false
}

func dedupeRefs(refs []RemoteStateRef) []RemoteStateRef {
	seen := make(map[string]struct{}, len(refs))
	var out []RemoteStateRef
	for _, r := range refs {
		key := r.ResourceAddress + "\x00" + r.DataAddress + "\x00" + r.Output
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

// StripAllKeys removes every instance key from an address, including module
// instance keys, so it can be compared with configuration addresses.
func StripAllKeys(addr string) string {
	parts := splitAddress(addr)
	for i, p := range parts {
		parts[i] = stripInstanceKey(p)
	}
	return strings.Join(parts, ".")
}
