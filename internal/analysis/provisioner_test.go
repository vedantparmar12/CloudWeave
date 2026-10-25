package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vedantparmar12/cloudweave/internal/state"
)

// The plan embeds provisioner commands and values; CloudWeave must keep only
// provisioner types and sizing flags, never the commands or any values.
const provisionerPlanJSON = `{
 "format_version":"1.2","terraform_version":"1.9.5","complete":true,"applyable":true,
 "resource_changes":[
  {"address":"null_resource.web","mode":"managed","type":"null_resource","name":"web",
   "change":{"actions":["update"],"before":{"id":"x"},"after":{"id":"x"}}},
  {"address":"null_resource.plain","mode":"managed","type":"null_resource","name":"plain",
   "change":{"actions":["no-op"],"before":{"id":"y"},"after":{"id":"y"}}}
 ],
 "configuration":{"root_module":{"resources":[
  {"address":"null_resource.web","mode":"managed","type":"null_resource","name":"web",
   "count_expression":{"constant_value":3},
   "provisioners":[{"type":"local-exec","expressions":{"command":{"constant_value":"echo PROVISIONER_SENTINEL_SECRET"}}},
                  {"type":"local-exec","expressions":{"command":{"constant_value":"echo again"}}}]},
  {"address":"null_resource.plain","mode":"managed","type":"null_resource","name":"plain"},
  {"address":"null_resource.each","mode":"managed","type":"null_resource","name":"each",
   "for_each_expression":{"references":["var.set"]}}
 ]}}
}`

func TestProvisionerAndSizingInsights(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(provisionerPlanJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := state.LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ConfigProvisioners["null_resource.web"]; strings.Join(got, ",") != "local-exec" {
		t.Fatalf("provisioner types = %v, want [local-exec]", got)
	}
	if !p.ConfigCounts["null_resource.web"] || !p.ConfigForEach["null_resource.each"] {
		t.Fatalf("sizing flags wrong: counts=%v for_each=%v", p.ConfigCounts, p.ConfigForEach)
	}
	if p.ConfigCounts["null_resource.plain"] || p.ConfigForEach["null_resource.web"] {
		t.Fatal("unexpected sizing flag")
	}

	st := &state.State{Name: "s"}
	for _, addr := range []string{"null_resource.web", "null_resource.plain"} {
		st.AddResource(&state.Resource{Address: addr, Mode: "managed", Type: "null_resource",
			Instances: []state.Instance{{Attributes: map[string]any{"id": "STATE_VALUE_SENTINEL"}}}})
	}
	res, err := Analyze([]*state.State{st}, p, Options{PrimaryState: "s"})
	if err != nil {
		t.Fatal(err)
	}

	var finding *Finding
	for i := range res.Findings {
		if res.Findings[i].Rule == "CW602" {
			finding = &res.Findings[i]
		}
	}
	if finding == nil {
		t.Fatal("CW602 finding missing")
	}
	if len(finding.Nodes) != 1 || finding.Nodes[0] != "s::null_resource.web" || !strings.Contains(finding.Detail, "local-exec") {
		t.Fatalf("CW602 = %+v", finding)
	}
	if len(finding.Fix) < 2 || !strings.Contains(finding.Fix[0].Text, "never executes") {
		t.Fatalf("CW602 fix = %+v", finding.Fix)
	}

	n := res.Graph.Nodes["s::null_resource.web"]
	if len(n.Provisioners) != 1 || n.Provisioners[0] != "local-exec" || !n.HasCount || n.HasForEach {
		t.Fatalf("node metadata = %+v", n)
	}
	nodeJSON, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nodeJSON), `"provisioners":["local-exec"]`) || !strings.Contains(string(nodeJSON), `"has_count":true`) {
		t.Fatalf("node JSON = %s", nodeJSON)
	}

	if res.Simulation == nil {
		t.Fatal("simulation missing")
	}
	var warned bool
	for _, step := range res.Simulation.Steps {
		if step.Node != "s::null_resource.web" {
			continue
		}
		if step.Outcome != OutcomeWarn {
			t.Fatalf("provisioner step outcome = %q", step.Outcome)
		}
		for _, note := range step.Notes {
			if strings.Contains(note, "Provisioners execute only at apply time") {
				warned = true
			}
		}
	}
	if !warned {
		t.Fatal("provisioner simulation note missing")
	}

	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PROVISIONER_SENTINEL_SECRET", "STATE_VALUE_SENTINEL"} {
		if strings.Contains(string(data), forbidden) {
			t.Errorf("report data leaked %q", forbidden)
		}
	}
}
