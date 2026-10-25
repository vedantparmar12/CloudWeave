package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vedantparmar12/cloudweave/internal/analysis"
	"github.com/vedantparmar12/cloudweave/internal/state"
)

func TestHTMLEscapesEmbeddedData(t *testing.T) {
	evil := `x</script><script>alert(1)</script>`
	st := &state.State{Name: evil, Path: "evil.tfstate"}
	st.AddResource(&state.Resource{
		Address: "null_resource.n", Mode: "managed", Type: "null_resource", Name: "n",
		Instances: []state.Instance{{Attributes: map[string]any{"id": "attr-value-must-not-appear", "triggers": map[string]any{"k": evil}}}},
	})
	res, err := analysis.Analyze([]*state.State{st}, nil, analysis.Options{Now: time.Unix(0, 0), Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	rep := Build(res, "test", 100)

	var buf bytes.Buffer
	if err := WriteHTML(&buf, rep); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if strings.Contains(html, "<script>alert(1)") {
		t.Error("state name broke out of the data script tag")
	}
	if strings.Contains(html, "attr-value-must-not-appear") {
		t.Error("attribute value leaked into HTML")
	}
	if strings.Contains(html, "/*CLOUDWEAVE_DATA*/") {
		t.Error("data placeholder not replaced")
	}
	if !strings.Contains(html, "Content-Security-Policy") {
		t.Error("CSP meta tag missing")
	}

	start := strings.Index(html, `<script id="cw-data" type="application/json">`)
	if start < 0 {
		t.Fatal("data script tag not found")
	}
	body := html[start+len(`<script id="cw-data" type="application/json">`):]
	body = body[:strings.Index(body, "</script>")]
	var back Report
	if err := json.Unmarshal([]byte(body), &back); err != nil {
		t.Fatalf("embedded JSON invalid: %v", err)
	}
	if back.States[0].Name != evil || back.Schema != Schema {
		t.Errorf("round trip lost data: %+v", back.States)
	}
}

func TestMarkdownEscapesAndHidesValues(t *testing.T) {
	st := &state.State{Name: "a|b<i>"}
	st.AddResource(&state.Resource{
		Address: "aws_db_instance.db", Mode: "managed", Type: "aws_db_instance", Name: "db",
		Instances: []state.Instance{{Attributes: map[string]any{"password": "hunter2-secret"}}},
	})
	res, err := analysis.Analyze([]*state.State{st}, nil, analysis.Options{Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	rep := Build(res, "test", 10)
	rep.ApplyOrder = []string{"gcp", "azure"}
	rep.Findings = append(rep.Findings, analysis.Finding{
		Rule: "CW999", Severity: analysis.SevHigh, Title: "pipe | and <b>tag</b>\nnewline",
		Nodes: []string{"s::a`b|c"},
	})
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	if strings.Contains(md, "hunter2") {
		t.Error("attribute value leaked into Markdown")
	}
	if strings.Contains(md, "<b>tag") || strings.Contains(md, "<i>") {
		t.Error("raw HTML from input reached Markdown")
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| HIGH") || strings.Contains(line, "CW999") && strings.HasPrefix(line, "|") {
			if n := strings.Count(line, "|") - strings.Count(line, `\|`); n != 5 {
				t.Errorf("table row has %d unescaped pipes: %s", n, line)
			}
		}
	}
	if !strings.Contains(md, "`gcp` → `azure`") {
		t.Error("apply order missing")
	}
}

func TestSimulationAndFixesInReports(t *testing.T) {
	st := &state.State{Name: "s"}
	st.AddResource(&state.Resource{Address: "null_resource.test", Mode: "managed", Type: "null_resource", Instances: []state.Instance{{Attributes: map[string]any{"id": "secret-identifier-sentinel"}}}})
	p := &state.Plan{Changes: []state.Change{{Address: "null_resource.test", Action: state.ActionDelete, Actions: []string{state.ActionDelete}, ActionReason: "delete_because_no_resource_config"}}}
	res, err := analysis.Analyze([]*state.State{st}, p, analysis.Options{PrimaryState: "s"})
	if err != nil {
		t.Fatal(err)
	}
	r := Build(res, "test", 20)
	if r.Simulation == nil || len(r.Simulation.Steps) != 1 || r.Simulation.Steps[0].After != "absent" {
		t.Fatalf("simulation lost: %+v", r.Simulation)
	}
	for _, writer := range []func(*bytes.Buffer) error{
		func(b *bytes.Buffer) error { return WriteHTML(b, r) },
		func(b *bytes.Buffer) error { return WriteJSON(b, r) },
		func(b *bytes.Buffer) error { return WriteMarkdown(b, r) },
	} {
		var buf bytes.Buffer
		if err := writer(&buf); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "secret-identifier-sentinel") {
			t.Fatal("value leaked")
		}
	}
	var found bool
	for _, f := range r.Findings {
		if f.Rule == "CW206" && len(f.Fix) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("remediation missing from report")
	}
}

func TestJSONHasNoAttributeValues(t *testing.T) {
	st := &state.State{Name: "s"}
	st.AddResource(&state.Resource{
		Address: "aws_db_instance.db", Mode: "managed", Type: "aws_db_instance", Name: "db",
		Instances: []state.Instance{{Attributes: map[string]any{"password": "hunter2-secret", "id": "db-1234567890"}}},
	})
	res, err := analysis.Analyze([]*state.State{st}, nil, analysis.Options{Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Build(res, "test", 10)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "hunter2") || strings.Contains(buf.String(), "db-1234567890") {
		t.Error("attribute values leaked into JSON report")
	}
}

func TestMixedSourceReports(t *testing.T) {
	fixture := func(name string) string {
		return filepath.Join("..", "..", "testdata", "multicloud", name)
	}
	for _, source := range []state.Source{state.SourcePostgreSQL, state.SourcePlan} {
		t.Run(string(source), func(t *testing.T) {
			file, err := state.LoadState(fixture("gcp.tfstate"))
			if err != nil {
				t.Fatal(err)
			}
			// A file label must not masquerade as plan provenance.
			file.Name = "plan-prior-state"
			var other *state.State
			format := state.FormatRaw
			if source == state.SourcePlan {
				plan, err := state.LoadPlan(fixture("azure-plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				other = plan.PriorState
				format = state.FormatShowJSON
			} else {
				other, err = state.LoadState(fixture("azure.tfstate"))
				if err != nil {
					t.Fatal(err)
				}
				// The real PG loader is covered by TestLoadPGStateReadOnlyWire.
				other.Source = state.SourcePostgreSQL
				other.Path = ""
			}
			if other == nil {
				t.Fatal("normalized state missing")
			}
			// Renaming a real plan prior state must not lose its provenance.
			other.Name = "azure"
			res, err := analysis.Analyze([]*state.State{file, other}, nil, analysis.Options{
				Now: time.Unix(0, 0), Getenv: func(string) string { return "" },
			})
			if err != nil {
				t.Fatal(err)
			}

			check := func(t *testing.T, summaries []analysis.StateSummary, edges []analysis.Edge) {
				t.Helper()
				if len(summaries) != 2 {
					t.Fatalf("got %d state summaries, want 2", len(summaries))
				}
				for _, s := range summaries {
					switch s.Name {
					case file.Name:
						if s.Source != state.SourceFile || s.Format != state.FormatRaw || s.FromPlan {
							t.Errorf("file provenance lost or inferred from name: %+v", s)
						}
					case other.Name:
						if s.Source != source || s.Format != format || s.FromPlan != (source == state.SourcePlan) {
							t.Errorf("%s provenance lost: %+v", source, s)
						}
					default:
						t.Errorf("unexpected state summary: %+v", s)
					}
				}
				for _, want := range []analysis.Edge{
					{From: analysis.NodeID(other.Name, "data.terraform_remote_state.gcp"), To: analysis.NodeID(file.Name, "google_service_account.bridge"), Kind: analysis.EdgeRemoteState},
					{From: analysis.NodeID(file.Name, "google_service_account_iam_member.workload_identity_user"), To: analysis.NodeID(other.Name, "azurerm_user_assigned_identity.workload"), Kind: analysis.EdgeFederation},
				} {
					found := false
					for _, edge := range edges {
						if edge.From == want.From && edge.To == want.To && edge.Kind == want.Kind {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("cross-source link missing: %+v", want)
					}
				}
			}
			check(t, res.States, res.Graph.Edges)
			rep := Build(res, "test", 100)
			check(t, rep.States, rep.Edges)
			for name, write := range map[string]func(*bytes.Buffer) error{
				"json":     func(b *bytes.Buffer) error { return WriteJSON(b, rep) },
				"html":     func(b *bytes.Buffer) error { return WriteHTML(b, rep) },
				"markdown": func(b *bytes.Buffer) error { return WriteMarkdown(b, rep) },
			} {
				t.Run(name, func(t *testing.T) {
					var buf bytes.Buffer
					if err := write(&buf); err != nil {
						t.Fatal(err)
					}
					text := buf.String()
					for _, sentinel := range []string{"SECRET-KUBECONFIG", "SECRET-STORAGE-KEY", "108234567890123456789", "c0ffee00-1234-4abc-9def-0123456789ab"} {
						if strings.Contains(text, sentinel) {
							t.Error("attribute value leaked into report")
						}
					}
					if name == "markdown" {
						return // Only JSON and embedded HTML data carry state metadata.
					}
					if name == "html" {
						_, body, ok := strings.Cut(text, `<script id="cw-data" type="application/json">`)
						if !ok {
							t.Fatal("embedded report missing")
						}
						text, _, ok = strings.Cut(body, "</script>")
						if !ok {
							t.Fatal("embedded report not terminated")
						}
					}
					if strings.Count(text, `"source":`) != 2 {
						t.Error("source JSON fields missing")
					}
					var back struct {
						States []analysis.StateSummary `json:"states"`
						Edges  []analysis.Edge         `json:"edges"`
					}
					if err := json.Unmarshal([]byte(text), &back); err != nil {
						t.Fatal(err)
					}
					check(t, back.States, back.Edges)
				})
			}
		})
	}
}
