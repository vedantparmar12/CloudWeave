package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"
)

type rawStateFile struct {
	Version          int                  `json:"version"`
	TerraformVersion string               `json:"terraform_version"`
	Serial           int64                `json:"serial"`
	Lineage          string               `json:"lineage"`
	Outputs          map[string]rawOutput `json:"outputs"`
	Resources        []rawResource        `json:"resources"`
	CheckResults     json.RawMessage      `json:"check_results"`
}

type rawOutput struct {
	Sensitive bool `json:"sensitive"`
	Type      any  `json:"type"`
	Value     any  `json:"value"`
}

type rawResource struct {
	Module    string        `json:"module"`
	Mode      string        `json:"mode"`
	Type      string        `json:"type"`
	Name      string        `json:"name"`
	Provider  string        `json:"provider"`
	Instances []rawInstance `json:"instances"`
}

type rawInstance struct {
	IndexKey            any             `json:"index_key"`
	SchemaVersion       int             `json:"schema_version"`
	Attributes          map[string]any  `json:"attributes"`
	SensitiveAttributes json.RawMessage `json:"sensitive_attributes"`
	Private             string          `json:"private"`
	Dependencies        []string        `json:"dependencies"`
	DependsOn           []string        `json:"depends_on"`
	CreateBeforeDestroy bool            `json:"create_before_destroy"`
	Status              string          `json:"status"`
	Deposed             string          `json:"deposed"`
}

type stateProbe struct {
	FormatVersion   string          `json:"format_version"`
	Version         *int            `json:"version"`
	Values          json.RawMessage `json:"values"`
	Resources       json.RawMessage `json:"resources"`
	ResourceChanges json.RawMessage `json:"resource_changes"`
}

// LoadState reads either a raw .tfstate file or the output of
// `terraform show -json` for a state.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}

	var probe stateProbe
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if len(probe.ResourceChanges) > 0 && string(probe.ResourceChanges) != "null" {
		return nil, fmt.Errorf("%s looks like a Terraform plan, not a state; pass it with --plan", path)
	}

	name := filepath.Base(path)
	switch {
	case probe.Version != nil && len(probe.Resources) > 0:
		return loadRawState(path, name, data)
	case probe.FormatVersion != "" && len(probe.Values) > 0:
		return loadShowJSONState(path, name, data)
	case probe.Version != nil:
		// Empty raw state still has version/resources (resources may be omitted).
		return loadRawState(path, name, data)
	default:
		return nil, fmt.Errorf("%s is not a Terraform state (missing version or format_version)", path)
	}
}

func loadRawState(path, name string, data []byte) (*State, error) {
	var raw rawStateFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode raw state %s: %w", path, err)
	}
	if raw.Version != 4 {
		return nil, fmt.Errorf("state %s uses format version %d; only Terraform state format 4 is supported", path, raw.Version)
	}

	st := &State{
		Name:             name,
		Path:             path,
		Format:           FormatRaw,
		Source:           SourceFile,
		TerraformVersion: raw.TerraformVersion,
		Lineage:          raw.Lineage,
	}
	if raw.Serial != 0 || raw.Lineage != "" {
		serial := raw.Serial
		st.Serial = &serial
	}

	for outName, out := range raw.Outputs {
		st.AddOutput(&Output{Name: outName, Sensitive: out.Sensitive, Value: out.Value})
	}

	for _, rr := range raw.Resources {
		resAddr := resourceAddress(rr.Module, rr.Mode, rr.Type, rr.Name)
		if resAddr == "" {
			continue
		}
		res := &Resource{
			Address:  resAddr,
			Module:   rr.Module,
			Mode:     rr.Mode,
			Type:     rr.Type,
			Name:     rr.Name,
			Provider: rr.Provider,
			Cloud:    CloudFor(rr.Type, rr.Provider),
		}
		if res.Mode == "" {
			res.Mode = "managed"
		}
		for _, ri := range rr.Instances {
			inst := Instance{
				Address:             resAddr + indexSuffix(ri.IndexKey),
				IndexKey:            indexKeyString(ri.IndexKey),
				Attributes:          ri.Attributes,
				Sensitive:           rawSensitiveSet(ri.SensitiveAttributes),
				Dependencies:        normalizeDependencies(append(append([]string{}, ri.Dependencies...), ri.DependsOn...)),
				CreateBeforeDestroy: ri.CreateBeforeDestroy,
				Status:              ri.Status,
				Deposed:             ri.Deposed,
			}
			if strings.EqualFold(ri.Status, "tainted") {
				res.Tainted = true
			}
			res.Instances = append(res.Instances, inst)
		}
		st.AddResource(res)
	}

	return st, nil
}

func resourceAddress(module, mode, typ, name string) string {
	if typ == "" || name == "" {
		return ""
	}
	parts := make([]string, 0, 4)
	if module != "" {
		parts = append(parts, module)
	}
	if mode == "data" {
		parts = append(parts, "data")
	}
	parts = append(parts, typ+"."+name)
	return strings.Join(parts, ".")
}

// rawSensitiveSet accepts the state v4 list of cty paths, where each step is
// {"type":"get_attr"|"index","value":...}, as well as a sensitive_values-style
// boolean tree.
func rawSensitiveSet(raw json.RawMessage) SensitiveSet {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	set := SensitiveSet{}
	switch x := v.(type) {
	case map[string]any:
		collectSensitive(x, "", set)
	case []any:
		for _, p := range x {
			steps, ok := p.([]any)
			if !ok {
				continue
			}
			parts := make([]string, 0, len(steps))
			for _, step := range steps {
				if m, ok := step.(map[string]any); ok {
					step = m["value"]
					if inner, ok := step.(map[string]any); ok {
						step = inner["value"]
					}
				}
				s, ok := scalarString(step)
				if !ok {
					s = fmt.Sprint(step)
				}
				parts = append(parts, escapePointer(s))
			}
			set["/"+strings.Join(parts, "/")] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func indexSuffix(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return `["` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(x) + `"]`
	case json.Number:
		return "[" + x.String() + "]"
	case float64:
		return "[" + strconv.FormatFloat(x, 'f', -1, 64) + "]"
	case int:
		return "[" + strconv.Itoa(x) + "]"
	default:
		return ""
	}
}

func indexKeyString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}

func normalizeDependencies(deps []string) []string {
	out := make([]string, 0, len(deps))
	for _, d := range deps {
		if n, ok := NormalizeAddress(d); ok {
			out = append(out, n)
		}
	}
	return appendUnique(out)
}

// loadShowJSONState parses `terraform show -json` output for a state.
func loadShowJSONState(path, name string, data []byte) (*State, error) {
	var sj tfjson.State
	if err := json.Unmarshal(data, &sj); err != nil {
		return nil, fmt.Errorf("decode show-json state %s: %w", path, err)
	}
	st := &State{
		Name:             name,
		Path:             path,
		Format:           FormatShowJSON,
		Source:           SourceFile,
		TerraformVersion: sj.TerraformVersion,
	}
	if sj.Values == nil {
		return st, nil
	}
	for outName, out := range sj.Values.Outputs {
		if out == nil {
			continue
		}
		st.AddOutput(&Output{Name: outName, Sensitive: out.Sensitive, Value: out.Value})
	}
	addShowJSONModule(st, sj.Values.RootModule)
	return st, nil
}

func addShowJSONModule(st *State, mod *tfjson.StateModule) {
	if mod == nil {
		return
	}
	for _, sr := range mod.Resources {
		if sr == nil {
			continue
		}
		info, err := ParseAddress(sr.Address)
		if err != nil {
			continue
		}
		res := st.ResourceByAddress(info.Address)
		if res == nil {
			res = &Resource{
				Address:  info.Address,
				Module:   info.Module,
				Mode:     string(sr.Mode),
				Type:     sr.Type,
				Name:     sr.Name,
				Provider: sr.ProviderName,
				Cloud:    CloudFor(sr.Type, sr.ProviderName),
				Tainted:  sr.Tainted,
			}
			if res.Mode == "" {
				res.Mode = "managed"
			}
			st.AddResource(res)
		}
		inst := Instance{
			Address:      sr.Address,
			IndexKey:     indexKeyString(sr.Index),
			Attributes:   sr.AttributeValues,
			Sensitive:    sensitiveFromTree(sr.SensitiveValues),
			Dependencies: normalizeDependencies(sr.DependsOn),
			Status:       statusFor(sr),
			Deposed:      sr.DeposedKey,
		}
		res.Instances = append(res.Instances, inst)
		res.Dependencies = appendUnique(res.Dependencies, inst.Dependencies...)
		if sr.Tainted {
			res.Tainted = true
		}
	}
	for _, child := range mod.ChildModules {
		addShowJSONModule(st, child)
	}
}

func statusFor(sr *tfjson.StateResource) string {
	if sr.Tainted {
		return "tainted"
	}
	if sr.DeposedKey != "" {
		return "deposed"
	}
	return ""
}

func sensitiveFromTree(raw json.RawMessage) SensitiveSet {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	set := SensitiveSet{}
	collectSensitive(v, "", set)
	if len(set) == 0 {
		return nil
	}
	return set
}

func collectSensitive(v any, pointer string, set SensitiveSet) {
	switch x := v.(type) {
	case bool:
		if x && pointer != "" {
			set[pointer] = struct{}{}
		}
	case map[string]any:
		for k, e := range x {
			collectSensitive(e, pointer+"/"+escapePointer(k), set)
		}
	case []any:
		for i, e := range x {
			collectSensitive(e, pointer+"/"+strconv.Itoa(i), set)
		}
	}
}
