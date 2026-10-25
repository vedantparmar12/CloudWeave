package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/vedantparmar12/cloudweave/internal/analysis"
)

const Schema = "cloudweave.report/v1"

const disclaimer = "CloudWeave is a read-only preflight. It never writes or pushes state, takes Terraform locks, or makes cloud API calls. " +
	"Fixes are suggestions only. Pseudo-apply is an offline model, not a guarantee that terraform apply succeeds."

// Report is the serialized analysis. It contains resource metadata, never
// attribute values.
type Report struct {
	Schema      string                  `json:"schema"`
	Version     string                  `json:"tool_version"`
	GeneratedAt string                  `json:"generated_at"`
	Verdict     string                  `json:"verdict"`
	Disclaimer  string                  `json:"disclaimer"`
	Counts      map[string]int          `json:"finding_counts"`
	States      []analysis.StateSummary `json:"states"`
	Plan        *analysis.PlanSummary   `json:"plan,omitempty"`
	Config      *analysis.ConfigSummary `json:"config,omitempty"`
	Findings    []analysis.Finding      `json:"findings"`
	Seeds       []string                `json:"seeds"`
	ApplyOrder  []string                `json:"apply_order,omitempty"`
	Simulation  *analysis.Simulation    `json:"simulation,omitempty"`
	Nodes       []*analysis.Node        `json:"nodes"`
	Edges       []analysis.Edge         `json:"edges"`
	MaxNodes    int                     `json:"max_nodes"`
}

func Build(res *analysis.Result, toolVersion string, maxNodes int) *Report {
	r := &Report{
		Schema:      Schema,
		Version:     toolVersion,
		GeneratedAt: res.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Verdict:     res.Verdict,
		Disclaimer:  disclaimer,
		Counts:      map[string]int{},
		States:      res.States,
		Plan:        res.Plan,
		Config:      res.Config,
		Findings:    res.Findings,
		Seeds:       res.Seeds,
		ApplyOrder:  res.ApplyOrder,
		Simulation:  res.Simulation,
		Nodes:       res.Graph.SortedNodes(),
		Edges:       res.Graph.Edges,
		MaxNodes:    maxNodes,
	}
	for _, f := range res.Findings {
		r.Counts[f.Severity.String()]++
	}
	if r.Edges == nil {
		r.Edges = []analysis.Edge{}
	}
	return r
}

func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

//go:embed template.html
var htmlTemplate string

const dataPlaceholder = "/*CLOUDWEAVE_DATA*/"

// WriteHTML writes a single self-contained HTML file. The data is embedded as
// JSON inside a non-executable script tag; encoding/json escapes <, > and &,
// so state content cannot terminate the tag.
func WriteHTML(w io.Writer, r *Report) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(r); err != nil {
		return err
	}
	if !strings.Contains(htmlTemplate, dataPlaceholder) {
		return fmt.Errorf("report template is missing the data placeholder")
	}
	out := strings.Replace(htmlTemplate, dataPlaceholder, strings.TrimSpace(buf.String()), 1)
	_, err := io.WriteString(w, out)
	return err
}
