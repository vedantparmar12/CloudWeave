package report

import (
	"bytes"
	"encoding/json"
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
