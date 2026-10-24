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
