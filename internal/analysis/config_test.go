package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vedantparmar12/cloudweave/internal/state"
	"github.com/vedantparmar12/cloudweave/internal/tfconfig"
)

// The configuration directory may contain credentials inside
// terraform_remote_state config; only the backend keyword and the whitelisted
// workspace literal may ever reach findings or report data.
const configPlanJSON = `{
 "format_version":"1.2","terraform_version":"1.9.5","complete":true,"applyable":true,
 "resource_changes":[
  {"address":"null_resource.cbd","mode":"managed","type":"null_resource","name":"cbd",
   "change":{"actions":["delete","create"],"before":{"id":"a"},"after":{"id":"b"}}},
  {"address":"null_resource.plain","mode":"managed","type":"null_resource","name":"plain",
   "change":{"actions":["delete","create"],"before":{"id":"c"},"after":{"id":"d"}}},
  {"address":"null_resource.gone","mode":"managed","type":"null_resource","name":"gone",
   "action_reason":"delete_because_no_resource_config",
   "change":{"actions":["delete"],"before":{"id":"e"},"after":null}},
  {"address":"null_resource.stillhere","mode":"managed","type":"null_resource","name":"stillhere",
   "action_reason":"delete_because_no_resource_config",
   "change":{"actions":["delete"],"before":{"id":"f"},"after":null}}
 ]
}`

const configMainTF = `
terraform {
  required_version = ">= 1.9.0"
}

resource "null_resource" "cbd" {
  lifecycle {
    create_before_destroy = true
  }
}

resource "null_resource" "locked" {
  lifecycle {
    prevent_destroy = true
  }
}

resource "null_resource" "web" {
  count = 1
}

resource "null_resource" "stillhere" {
}

data "terraform_remote_state" "prod" {
  backend = "pg"

  config = {
    conn_string = "postgres://cw:CONFIG_SENTINEL_PASSWORD@db.example"
    workspace   = "default"
  }
}
`

func TestConfigDirectoryInsights(t *testing.T) {
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "main.tf"), []byte(configMainTF), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := tfconfig.Load(cfgDir)
	if err != nil {
		t.Fatal(err)
	}

	planPath := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planPath, []byte(configPlanJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := state.LoadPlan(planPath)
	if err != nil {
		t.Fatal(err)
	}

	st := &state.State{Name: "s"}
	for _, addr := range []string{"null_resource.cbd", "null_resource.plain", "null_resource.gone",
		"null_resource.stillhere", "null_resource.locked", "null_resource.web"} {
		st.AddResource(&state.Resource{Address: addr, Mode: "managed", Type: "null_resource",
			Instances: []state.Instance{{Attributes: map[string]any{"id": "v-" + addr}}}})
	}
	st.AddResource(&state.Resource{Address: "data.terraform_remote_state.prod", Mode: "data", Type: "terraform_remote_state",
		Instances: []state.Instance{{Attributes: map[string]any{"outputs": map[string]any{"vpc_id": "vpc-123"}}}}})

	res, err := Analyze([]*state.State{st}, p, Options{PrimaryState: "s", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	byRule := func(rule string) *Finding {
		for i := range res.Findings {
			if res.Findings[i].Rule == rule {
				return &res.Findings[i]
			}
		}
		return nil
	}

	if res.Config == nil || res.Config.Path != cfgDir || res.Config.RequiredVersion != ">= 1.9.0" {
		t.Fatalf("config summary = %+v, want path %q and required_version >= 1.9.0", res.Config, cfgDir)
	}

	cbd := res.Graph.Nodes["s::null_resource.cbd"]
	if cbd == nil || !cbd.CreateBeforeDestroy || cbd.PreventDestroy {
		t.Fatalf("cbd node lifecycle flags = %+v", cbd)
	}
	locked := res.Graph.Nodes["s::null_resource.locked"]
	if locked == nil || !locked.PreventDestroy || locked.CreateBeforeDestroy {
		t.Fatalf("locked node lifecycle flags = %+v", locked)
	}
	web := res.Graph.Nodes["s::null_resource.web"]
	if web == nil || !web.HasCount || web.HasForEach {
		t.Fatalf("web node sizing flags = %+v", web)
	}

	cw603 := byRule("CW603")
	if cw603 == nil {
		t.Fatal("CW603 finding missing")
	}
	if len(cw603.Nodes) != 1 || cw603.Nodes[0] != "s::null_resource.cbd" {
		t.Fatalf("CW603 nodes = %v, want [s::null_resource.cbd] (plain has no create_before_destroy)", cw603.Nodes)
	}
	if cw603.Severity != SevMedium || !strings.Contains(cw603.Title, "create_before_destroy") {
		t.Fatalf("CW603 = %+v", cw603)
	}
	var fixText string
	for _, s := range cw603.Fix {
		fixText += s.Text + " "
	}
	if !strings.Contains(fixText, "create_before_destroy") || !strings.Contains(fixText, "deposed objects") {
		t.Fatalf("CW603 fix = %+v", cw603.Fix)
	}

	cw206 := byRule("CW206")
	if cw206 == nil {
		t.Fatal("CW206 finding missing")
	}
	if !strings.Contains(cw206.Detail, "still declared in the provided configuration directory") ||
		!strings.Contains(cw206.Detail, "null_resource.stillhere") ||
		!strings.Contains(cw206.Detail, "confirmed absent from the provided configuration directory") {
		t.Fatalf("CW206 detail = %q", cw206.Detail)
	}

	cw501 := byRule("CW501")
	if cw501 == nil {
		t.Fatal("CW501 finding missing")
	}
	if !strings.Contains(cw501.Detail, "pg backend") ||
		!strings.Contains(cw501.Detail, `"default" workspace`) ||
		!strings.Contains(cw501.Remediation, "--pg-state") {
		t.Fatalf("CW501 detail = %q remediation = %q", cw501.Detail, cw501.Remediation)
	}

	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "CONFIG_SENTINEL_PASSWORD") || strings.Contains(string(data), "db.example") {
		t.Error("report data leaked the terraform_remote_state conn_string")
	}
}

func TestConfigDirectoryOptional(t *testing.T) {
	// The same plan without a configuration directory must not emit CW603 and
	// must use the plain CW501/CW206 wording.
	planPath := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planPath, []byte(configPlanJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := state.LoadPlan(planPath)
	if err != nil {
		t.Fatal(err)
	}
	st := &state.State{Name: "s"}
	for _, addr := range []string{"null_resource.cbd", "null_resource.gone", "null_resource.stillhere"} {
		st.AddResource(&state.Resource{Address: addr, Mode: "managed", Type: "null_resource",
			Instances: []state.Instance{{Attributes: map[string]any{"id": "v"}}}})
	}
	st.AddResource(&state.Resource{Address: "data.terraform_remote_state.prod", Mode: "data", Type: "terraform_remote_state",
		Instances: []state.Instance{{Attributes: map[string]any{"outputs": map[string]any{"vpc_id": "vpc-123"}}}}})
	res, err := Analyze([]*state.State{st}, p, Options{PrimaryState: "s"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Rule == "CW603" {
			t.Error("CW603 emitted without --config")
		}
		if (f.Rule == "CW206" || f.Rule == "CW501") && strings.Contains(f.Detail, "configuration directory") {
			t.Errorf("%s mentions the configuration directory without --config: %q", f.Rule, f.Detail)
		}
	}
	if res.Config != nil {
		t.Errorf("config summary = %+v, want nil", res.Config)
	}
}

const modulePlanJSON = `{
 "format_version":"1.2","terraform_version":"1.9.5","complete":true,"applyable":true,
 "resource_changes":[
  {"address":"module.vpc[\"a\"].null_resource.cbd","mode":"managed","type":"null_resource","name":"cbd",
   "change":{"actions":["delete","create"],"before":{"id":"a"},"after":{"id":"b"}}},
  {"address":"module.vpc[\"a\"].null_resource.stillhere","mode":"managed","type":"null_resource","name":"stillhere",
   "action_reason":"delete_because_no_resource_config",
   "change":{"actions":["delete"],"before":{"id":"f"},"after":null}},
  {"address":"module.vpc[\"a\"].null_resource.gone","mode":"managed","type":"null_resource","name":"gone",
   "action_reason":"delete_because_no_resource_config",
   "change":{"actions":["delete"],"before":{"id":"e"},"after":null}}
 ]
}`

// The module's terraform_remote_state config carries a sentinel credential that
// must never reach findings or report data.
const moduleVpcTF = `
resource "null_resource" "cbd" {
  lifecycle {
    create_before_destroy = true
  }
}

resource "null_resource" "stillhere" {
}

data "terraform_remote_state" "prod" {
  backend = "pg"

  config = {
    conn_string = "postgres://cw:MODULE_SENTINEL_PASSWORD@db.example"
    workspace   = "default"
  }
}
`

func firstFinding(res *Result, rule string) *Finding {
	for i := range res.Findings {
		if res.Findings[i].Rule == rule {
			return &res.Findings[i]
		}
	}
	return nil
}

func TestConfigModuleInsights(t *testing.T) {
	root := t.TempDir()
	vpc := filepath.Join(root, "vpc")
	if err := os.MkdirAll(vpc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("module \"vpc\" {\n  source = \"./vpc\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vpc, "main.tf"), []byte(moduleVpcTF), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := tfconfig.Load(root)
	if err != nil {
		t.Fatal(err)
	}

	planPath := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planPath, []byte(modulePlanJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := state.LoadPlan(planPath)
	if err != nil {
		t.Fatal(err)
	}

	st := &state.State{Name: "s"}
	for _, addr := range []string{`module.vpc["a"].null_resource.cbd`, `module.vpc["a"].null_resource.stillhere`, `module.vpc["a"].null_resource.gone`} {
		st.AddResource(&state.Resource{Address: addr, Mode: "managed", Type: "null_resource",
			Instances: []state.Instance{{Attributes: map[string]any{"id": "v"}}}})
	}
	st.AddResource(&state.Resource{Address: `module.vpc["a"].data.terraform_remote_state.prod`, Mode: "data", Type: "terraform_remote_state",
		Instances: []state.Instance{{Attributes: map[string]any{"outputs": map[string]any{"vpc_id": "vpc-123"}}}}})

	res, err := Analyze([]*state.State{st}, p, Options{PrimaryState: "s", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}

	cbdID := `s::module.vpc["a"].null_resource.cbd`
	if n := res.Graph.Nodes[cbdID]; n == nil || !n.CreateBeforeDestroy {
		t.Fatalf("module cbd node lifecycle flags = %+v", res.Graph.Nodes[cbdID])
	}
	cw603 := firstFinding(res, "CW603")
	if cw603 == nil {
		t.Fatal("CW603 finding missing for module resource")
	}
	if len(cw603.Nodes) != 1 || cw603.Nodes[0] != cbdID {
		t.Fatalf("CW603 nodes = %v, want [%s]", cw603.Nodes, cbdID)
	}

	cw206 := firstFinding(res, "CW206")
	if cw206 == nil {
		t.Fatal("CW206 finding missing")
	}
	if !strings.Contains(cw206.Detail, "still declared in the provided configuration directory") ||
		!strings.Contains(cw206.Detail, "null_resource.stillhere") ||
		!strings.Contains(cw206.Detail, "confirmed absent from the provided configuration directory") ||
		strings.Contains(cw206.Detail, "not fully confirmed") {
		t.Fatalf("CW206 detail = %q", cw206.Detail)
	}

	cw501 := firstFinding(res, "CW501")
	if cw501 == nil {
		t.Fatal("CW501 finding missing for module data source")
	}
	if !strings.Contains(cw501.Detail, "pg backend") ||
		!strings.Contains(cw501.Detail, `"default" workspace`) ||
		!strings.Contains(cw501.Remediation, "--pg-state") {
		t.Fatalf("CW501 detail = %q remediation = %q", cw501.Detail, cw501.Remediation)
	}

	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "MODULE_SENTINEL_PASSWORD") || strings.Contains(string(data), "db.example") {
		t.Error("report data leaked the module terraform_remote_state conn_string")
	}
}

func TestConfigModuleUnresolvedCaveat(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.tf"),
		[]byte("module \"vpc\" {\n  source = \"hashicorp/vpc/aws\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := tfconfig.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.UnresolvedModules {
		t.Fatal("UnresolvedModules = false, want true")
	}

	planPath := filepath.Join(t.TempDir(), "plan.json")
	plan := `{"format_version":"1.2","terraform_version":"1.9.5","complete":true,"applyable":true,
	 "resource_changes":[{"address":"null_resource.gone","mode":"managed","type":"null_resource","name":"gone",
	  "action_reason":"delete_because_no_resource_config",
	  "change":{"actions":["delete"],"before":{"id":"e"},"after":null}}]}`
	if err := os.WriteFile(planPath, []byte(plan), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := state.LoadPlan(planPath)
	if err != nil {
		t.Fatal(err)
	}
	st := &state.State{Name: "s"}
	st.AddResource(&state.Resource{Address: "null_resource.gone", Mode: "managed", Type: "null_resource",
		Instances: []state.Instance{{Attributes: map[string]any{"id": "v"}}}})

	res, err := Analyze([]*state.State{st}, p, Options{PrimaryState: "s", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	cw206 := firstFinding(res, "CW206")
	if cw206 == nil {
		t.Fatal("CW206 finding missing")
	}
	if !strings.Contains(cw206.Detail, "confirmed absent from the provided configuration directory") ||
		!strings.Contains(cw206.Detail, "not fully confirmed") {
		t.Fatalf("CW206 detail = %q, want absence with unresolved-module caveat", cw206.Detail)
	}
}
