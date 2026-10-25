package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/vedantparmar12/cloudweave/internal/state"
)

func fixTestFindings() []Finding {
	var findings []Finding
	for _, rule := range strings.Fields(`
		CW001 CW002 CW003 CW004 CW005 CW006 CW007 CW008 CW011
		CW101 CW102 CW103 CW104 CW201 CW202 CW203 CW204 CW205 CW206
		CW301 CW302 CW303 CW304 CW305 CW306 CW307 CW308 CW309 CW310
		CW311 CW312 CW313 CW314 CW401 CW402 CW403 CW404 CW405 CW406
		CW407 CW408 CW501 CW502 CW503 CW504 CW505 CW601 CW602 CW603`) {
		findings = append(findings, Finding{Rule: rule})
	}
	return append(findings,
		Finding{Rule: "CW205", Title: "Deposed objects left from a failed replacement"},
		Finding{Rule: "CW205", Title: "Tainted resources will be replaced"},
		Finding{Rule: "CW305", Title: "Azure v1 issuer is missing its trailing slash"},
		Finding{Rule: "CW305", Title: "Google issuer in federated credential is not exact"},
		Finding{Rule: "CW312", Title: "Plan updates identity federation resources"},
		Finding{Rule: "CW312", Title: "Plan deletes or replaces identity federation resources"},
		Finding{Rule: "CW402", Title: "GCP uses a static access token"},
	)
}

func fixTestText(steps []FixStep) string {
	var b strings.Builder
	for _, step := range steps {
		b.WriteString(step.Text)
		b.WriteByte('\n')
		b.WriteString(step.Code)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestSafeFixGuidanceForEveryRule(t *testing.T) {
	a := &analyzer{}
	covered := map[string]bool{}
	for _, finding := range fixTestFindings() {
		covered[finding.Rule] = true
		t.Run(finding.Rule+"/"+finding.Title, func(t *testing.T) {
			steps := a.fixFor(&finding)
			if len(steps) < 2 {
				t.Fatalf("missing review notice or useful guidance: %#v", steps)
			}
			for _, step := range steps {
				if strings.TrimSpace(step.Text) == "" {
					t.Error("step has no explanatory text")
				}
			}
			if !strings.Contains(steps[0].Text, "never executes") || !strings.Contains(steps[0].Text, "not ready to run") {
				t.Error("guidance must explain that preflight never executes templates")
			}
		})
	}

	// Discover actual emitted rules, so adding a check cannot silently leave this
	// coverage table behind. Unknown future rules still have a static fallback.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	rulePattern := regexp.MustCompile(`Rule:\s*"(CW[0-9]{3})"`)
	found := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range rulePattern.FindAllStringSubmatch(string(data), -1) {
			found++
			if !covered[match[1]] {
				t.Errorf("rule %s in %s lacks a guidance test", match[1], path)
			}
		}
	}
	if found == 0 {
		t.Fatal("no emitted rules found")
	}
}

func TestSafeFixFallbackAndMissingNodes(t *testing.T) {
	a := &analyzer{}
	for _, finding := range []*Finding{nil, {}, {Rule: "CW999", Remediation: "Review the owner-approved remediation."}} {
		steps := a.fixFor(finding)
		if len(steps) < 2 || steps[1].Code != "" || !strings.Contains(steps[1].Text, "Review") {
			t.Fatalf("missing safe fallback: %#v", steps)
		}
	}
	for _, finding := range fixTestFindings() {
		want := a.fixFor(&finding)
		finding.Nodes = []string{"missing::resource", "another::missing"}
		for _, graph := range []*Graph{nil, NewGraph()} {
			a.g = graph
			if got := a.fixFor(&finding); !reflect.DeepEqual(got, want) {
				t.Errorf("%s guidance depends on missing nodes", finding.Rule)
			}
		}
	}
}

func TestSafeFixNeverInterpolatesInputs(t *testing.T) {
	const (
		metadata = "SENTINEL_METADATA_DO_NOT_RENDER"
		value    = "SENTINEL_VALUE_DO_NOT_RENDER"
		attr     = "SENTINEL_SENSITIVE_ATTR_DO_NOT_RENDER"
	)
	payloads := []string{
		metadata,
		"resource.x'; touch SENTINEL_COMMAND; #",
		"resource.x[\"$(touch SENTINEL_COMMAND)\"]",
		"resource.x[`touch SENTINEL_COMMAND`]",
		"state\nterraform apply -auto-approve # SENTINEL_COMMAND",
		"resource.x\"\n}\nresource \"evil\" \"SENTINEL_HCL\" {",
		"${file(\"SENTINEL_HCL\")}",
		"--help; touch SENTINEL_COMMAND",
		"\x1b[31mSENTINEL_TERMINAL",
	}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			n := &Node{
				ID: payload, State: payload, Address: payload, Module: payload,
				Mode: "managed", Type: payload, Provider: payload,
				Action: state.ActionReplace, ChangedAttrs: []string{attr, "private_key"},
				UnknownAttrs: []string{attr, "client_secret"}, ReplacePaths: []string{attr},
				SensitiveAttrs: 2, Reasons: []string{payload},
			}
			st := &state.State{
				Name: payload, Path: payload, TerraformVersion: payload, Lineage: payload,
				Resources: []*state.Resource{{
					Address: payload, Type: payload, Name: payload, Provider: payload,
					Instances: []state.Instance{{
						Address: payload, IndexKey: payload,
						Attributes: map[string]any{
							attr: value, "id": value, "tenant_id": value, "issuer": value,
							"private_key": value, "client_secret": value,
						},
						Sensitive: state.SensitiveSet{"/" + attr: {}, "/private_key": {}, "/client_secret": {}},
					}},
				}},
				Outputs: []*state.Output{{Name: attr, Value: value, Sensitive: true}},
			}
			a := &analyzer{
				primary: st, states: []*state.State{st},
				plan: &state.Plan{
					Path: payload, TerraformVersion: payload, PriorState: st,
					ChangedOutputs: []string{attr},
					Changes: []state.Change{{
						Address: payload, InstanceAddress: payload, Type: payload,
						Action: state.ActionReplace, ChangedAttrs: []string{attr},
						UnknownAttrs: []string{attr}, ReplacePaths: []string{attr},
					}},
				},
				g: &Graph{Nodes: map[string]*Node{payload: n}},
				opts: Options{RevealIDs: true, Getenv: func(string) string {
					t.Fatal("fix generation must not inspect credentials")
					return ""
				}},
			}
			clean := &analyzer{}
			findings := append(fixTestFindings(), Finding{Rule: "CW999"})
			for _, finding := range findings {
				want := clean.fixFor(&finding)
				finding.Detail = payload + value + attr
				finding.Remediation = payload + value + attr
				finding.Category = payload
				finding.Nodes = []string{payload}
				got := a.fixFor(&finding)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s guidance changed with untrusted metadata", finding.Rule)
				}
				for _, forbidden := range []string{payload, metadata, value, attr, "private_key", "client_secret", "SENTINEL_COMMAND", "SENTINEL_HCL"} {
					if strings.Contains(fixTestText(got), forbidden) {
						t.Errorf("%s leaked an input or sensitive attribute name", finding.Rule)
					}
				}
				// Even an unrecognized/malicious title must not become prose or code.
				finding.Title = payload
				if strings.Contains(fixTestText(a.fixFor(&finding)), payload) {
					t.Errorf("%s interpolated the finding title", finding.Rule)
				}
			}
		})
	}
}

func TestSafeFixOnlyStaticReviewTemplates(t *testing.T) {
	bashPlan := regexp.MustCompile(`^terraform -chdir='<configuration-directory>' plan( -refresh-only)?$`)
	a := &analyzer{}
	for _, finding := range fixTestFindings() {
		for _, step := range a.fixFor(&finding) {
			if step.Code == "" {
				continue
			}
			if strings.HasPrefix(step.Code, "terraform ") && !strings.HasPrefix(step.Code, "terraform {") {
				if !strings.HasPrefix(step.Text, "Bash template") || !bashPlan.MatchString(step.Code) {
					t.Errorf("%s has an unlabeled or unsafe Bash command: %q", finding.Rule, step.Code)
				}
			} else if !strings.HasPrefix(step.Text, "HCL template") {
				t.Errorf("%s has an unlabeled HCL template", finding.Rule)
			}
			for _, forbidden := range []string{
				"terraform apply", "force-unlock", "-target", "state rm", "state push", "untaint",
				"time_sleep", "60s", "create_before_destroy", "prevent_destroy",
				"$(", "`", ";", "local-exec", "remote-exec", "private_key", "client_secret",
			} {
				if strings.Contains(step.Code, forbidden) {
					t.Errorf("%s contains unsafe code %q", finding.Rule, forbidden)
				}
			}
		}
	}
}

func TestSafeFixMigrationAndCredentialSemantics(t *testing.T) {
	a := &analyzer{}
	tests := []struct {
		rule string
		want []string
	}{
		{"CW206", []string{"choose ONE", "Alternative A", "Alternative B", "same state", "cross-state", "Terraform >= 1.7", "protected backups", "moved {", "removed {", "destroy = false", "import {", "exactly one destination owner"}},
		{"CW503", []string{"Choose ONE", "never remove every owner", "only in the relinquishing state", "never in the retained owner's state", "destroy = false", "replan both states"}},
		{"CW201", []string{"independent credential", "staged parallel", "retain the old", "create_before_destroy alone does not", "Switch consumers", "Retire the old", "all consumers are verified"}},
		{"CW312", []string{"independent credential", "before any authentication change", "staged parallel", "Switch consumers", "token exchange", "authorized API access", "all consumers are verified", "do not target federation"}},
		{"CW313", []string{"Separate new grants", "independent credential", "Verify actual propagation", "fixed sleep cannot guarantee", "full, non-targeted plan"}},
		{"CW402", []string{"refreshable CI credential source", "right before the run", "renew or reread", "Raising --apply-window does not extend token lifetime"}},
		{"CW102", []string{"really missing", "permissions", "deletion cause", "If still required", "If intentionally retired", "Do not import or forget"}},
		{"CW205", []string{"verify object health", "Do not clear a taint", "protected backup"}},
		{"CW602", []string{"Provisioners execute only during apply", "never place secrets"}},
		{"CW603", []string{"create_before_destroy", "deposed objects", "confirm consumers can tolerate"}},
		{"CW505", []string{"dependency direction", "refresh the state snapshot", "not treat the unresolved layer group as an execution schedule"}},
	}
	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			text := fixTestText(a.fixFor(&Finding{Rule: tt.rule}))
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Errorf("guidance missing %q", want)
				}
			}
		})
	}
	steps := a.fixFor(&Finding{Rule: "CW205", Title: "Deposed objects left from a failed replacement"})
	if !strings.Contains(fixTestText(steps), "no consumers still use the deposed objects") {
		t.Error("deposed resources need consumer-aware recovery guidance")
	}

	// Multiple duplicated owners must not produce one removal per input node.
	a.g = NewGraph()
	var nodes []string
	for _, id := range []string{"one", "two", "three"} {
		a.g.AddNode(&Node{ID: id, State: id, Address: "resource." + id})
		nodes = append(nodes, id)
	}
	steps = a.fixFor(&Finding{Rule: "CW503", Nodes: nodes})
	var code strings.Builder
	for _, step := range steps {
		code.WriteString(step.Code)
	}
	if strings.Count(code.String(), "removed {") != 1 || strings.Contains(code.String(), "import {") {
		t.Error("duplicate ownership needs one relinquishing-state template, not removals for all owners or an unnecessary import")
	}
}

func TestSafeFixIssuerSelection(t *testing.T) {
	a := &analyzer{}
	for _, tt := range []struct {
		title string
		code  string
	}{
		{"Azure v1 issuer is missing its trailing slash", "oidc {\n  issuer_uri = \"https://sts.windows.net/<tenant-id>/\"\n}"},
		{"Google issuer in federated credential is not exact", "issuer = \"https://accounts.google.com\""},
		{"unknown issuer", ""},
		{"Google issuer in federated credential is not exact; $(evil)", ""},
	} {
		t.Run(tt.title, func(t *testing.T) {
			steps := a.fixFor(&Finding{Rule: "CW305", Title: tt.title})
			if len(steps) != 2 || steps[1].Code != tt.code {
				t.Fatalf("wrong issuer template: %#v", steps)
			}
		})
	}
}

func TestSafeFixAddFixesIsIdempotent(t *testing.T) {
	a := &analyzer{findings: fixTestFindings()}
	original := append([]Finding(nil), a.findings...)
	a.addFixes()
	first, err := json.Marshal(a.findings)
	if err != nil {
		t.Fatal(err)
	}
	a.addFixes()
	second, err := json.Marshal(a.findings)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("addFixes should replace guidance, not accumulate it")
	}
	for i, finding := range a.findings {
		if len(finding.Fix) < 2 {
			t.Errorf("%s lacks guidance", finding.Rule)
		}
		finding.Fix = nil
		if !reflect.DeepEqual(finding, original[i]) {
			t.Errorf("%s changed outside its Fix field", finding.Rule)
		}
	}
	data, err := json.Marshal(FixStep{Text: "Review only."})
	if err != nil || string(data) != `{"text":"Review only."}` {
		t.Fatalf("FixStep JSON API changed: %s, %v", data, err)
	}
}

func TestSafeLegacyRemediationFromFixtures(t *testing.T) {
	migration := []string{
		"independent working credentials", "do not rely on the changing identity or trust",
		"staging parallel identities", "reviewed full, non-targeted plans", "trust in configuration",
		"until all consumers have migrated and verified token exchange and required API authorization",
		"never use targeted federation changes as a shortcut",
	}
	tests := []struct {
		rule      string
		want      []string
		forbidden []string
	}{
		{"CW201", append(append([]string(nil), migration...), "Retain the old object"), []string{"apply this state, then", "immediately plan/apply", "create_before_destroy", " -target"}},
		{"CW312", append(append([]string(nil), migration...), "Retain the old identity"), []string{"Apply federation changes in a separate, earlier run", " -target"}},
		{"CW313", []string{"Separate new grants", "reviewed stages", "independent working credentials", "actual token exchange", "required API authorization", "full, non-targeted", "neither depends_on nor a fixed sleep guarantees propagation"}, []string{"time_sleep", "Add explicit depends_on", "60s"}},
		{"CW205", []string{"root cause", "verify object health", "Do not clear a taint merely to suppress replacement", "manual state change requires owner review", "protected backup", "new full plan afterward"}, []string{"terraform untaint", "untaint it before applying"}},
		{"CW206", []string{"same-state move", "retain destination configuration", "reviewed `moved` block", "cross-state ownership transfer", "pause competing runs", "protected backups", "non-destructive removal only in the relinquishing state", "import into exactly one destination owner", "full plans for both states"}, []string{"If the resource moved, use", "instead of deleting the config"}},
		{"CW503", []string{"Choose one authoritative owner", "keep its configuration and state entry intact", "never remove every owner", "Pause competing runs", "protected backups", "non-destructive removal only in the relinquishing state", "replan both states", "exactly one owner", "no destruction or recreation"}, []string{"terraform state rm", "remove it from the other with a `removed` block"}},
	}
	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			states, plan := loadFixtures(t)
			// The base fixture has no taint or duplicate owner. Add these conditions
			// in memory so the real checks emit findings, not hand-built Finding values.
			for _, resource := range states[0].Resources {
				if resource.Address != "azurerm_resource_group.platform" {
					continue
				}
				switch tt.rule {
				case "CW205":
					resource.Tainted = true
				case "CW503":
					other := &state.State{Name: "other-owner", Lineage: "independent-owner"}
					other.AddResource(resource)
					states = append(states, other)
				}
			}
			res, err := Analyze(states, plan, Options{Now: planTime, Getenv: noEnv})
			if err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, finding := range res.Findings {
				if finding.Rule != tt.rule {
					continue
				}
				found++
				for _, want := range tt.want {
					if !strings.Contains(finding.Remediation, want) {
						t.Errorf("%s remediation missing %q: %s", finding.Title, want, finding.Remediation)
					}
				}
				for _, forbidden := range tt.forbidden {
					if strings.Contains(finding.Remediation, forbidden) {
						t.Errorf("%s remediation contains unsafe guidance %q", finding.Title, forbidden)
					}
				}
			}
			if found == 0 {
				t.Fatal("fixture analysis did not emit the expected finding")
			}
		})
	}
}

func TestSafeFixAnalyzeIntegration(t *testing.T) {
	states, plan := loadFixtures(t)
	res, err := Analyze(states, plan, Options{Now: planTime, Getenv: noEnv, RevealIDs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("fixture analysis produced no findings")
	}
	for _, finding := range res.Findings {
		if len(finding.Fix) < 2 {
			t.Errorf("%s has no useful guidance after Analyze", finding.Rule)
		}
		for _, step := range finding.Fix {
			for _, st := range states {
				for _, resource := range st.Resources {
					if resource.Address != "" && strings.Contains(step.Code, resource.Address) {
						t.Errorf("%s code contains a fixture resource address", finding.Rule)
					}
				}
			}
		}
	}
}
