package analysis

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vedantparmar12/cloudweave/internal/state"
)

var planTime = time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)

func fixture(name string) string {
	return filepath.Join("..", "..", "testdata", "multicloud", name)
}

func loadFixtures(t *testing.T) ([]*state.State, *state.Plan) {
	t.Helper()
	var states []*state.State
	for _, n := range []string{"azure", "gcp"} {
		st, err := state.LoadState(fixture(n + ".tfstate"))
		if err != nil {
			t.Fatal(err)
		}
		st.Name = n
		states = append(states, st)
	}
	plan, err := state.LoadPlan(fixture("azure-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	return states, plan
}

func noEnv(string) string { return "" }

func rules(fs []Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Rule]++
	}
	return out
}

func hasEdge(g *Graph, from, to, kind string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Kind == kind {
			return true
		}
	}
	return false
}

func TestMultiCloudFixture(t *testing.T) {
	states, plan := loadFixtures(t)
	res, err := Analyze(states, plan, Options{Now: planTime, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "block" {
		t.Errorf("verdict = %s", res.Verdict)
	}
	if res.Plan.PrimaryState != "azure" {
		t.Errorf("primary = %s, want azure (auto-detected from prior state IDs)", res.Plan.PrimaryState)
	}

	got := rules(res.Findings)
	for _, r := range []string{"CW201", "CW202", "CW312", "CW101", "CW102", "CW206", "CW310", "CW502", "CW313"} {
		if got[r] == 0 {
			t.Errorf("expected finding %s; got %v", r, got)
		}
	}
	if got["CW305"] != 2 {
		t.Errorf("CW305 count = %d, want 2 (WIF issuer slash + FIC issuer slash)", got["CW305"])
	}
	for _, r := range []string{"CW003", "CW008", "CW503", "CW501"} {
		if got[r] != 0 {
			t.Errorf("unexpected finding %s", r)
		}
	}

	g := res.Graph
	uami := NodeID("azure", "azurerm_user_assigned_identity.workload")
	grant := NodeID("gcp", "google_service_account_iam_member.workload_identity_user")
	if !hasEdge(g, grant, uami, EdgeFederation) {
		t.Error("missing federation edge from GCP grant to Azure managed identity")
	}
	if !hasEdge(g, NodeID("azure", "azuread_application_federated_identity_credential.from_gcp"), NodeID("gcp", "google_service_account.bridge"), EdgeFederation) {
		t.Error("missing federation edge from Azure FIC to GCP service account")
	}
	if !hasEdge(g, NodeID("azure", "data.terraform_remote_state.gcp"), NodeID("gcp", "google_service_account.bridge"), EdgeRemoteState) {
		t.Error("missing remote-state edge to producer resource")
	}

	if n := g.Nodes[uami]; n.Role != RoleSeed || n.Action != state.ActionReplace || n.CrossImp == 0 {
		t.Errorf("uami node = %+v", n)
	}
	if n := g.Nodes[grant]; n.Role != RoleDownstream {
		t.Errorf("GCP grant should be in the change cone, role=%q", n.Role)
	}
	if n := g.Nodes[NodeID("azure", "azurerm_storage_account.logs")]; n.Drift != state.ActionDelete {
		t.Errorf("storage account drift = %q", n.Drift)
	}
	if n := g.Nodes[NodeID("azure", "azurerm_role_assignment.workload_logs_reader")]; n == nil || !n.Planned {
		t.Error("planned create should add a node")
	} else if !hasEdge(g, n.ID, uami, EdgeDependency) {
		t.Error("planned node should get dependency edges from configuration")
	}

	blob, _ := json.Marshal(res.Findings)
	for _, secret := range []string{"SECRET", "c0ffee00-1234-4abc-9def-0123456789ab", "108234567890123456789", "3f2c8a1e-5b7d-4c9a-8e21-6d4b9f0a7c13"} {
		if strings.Contains(string(blob), secret) {
			t.Errorf("findings leak %q", secret)
		}
	}
}

func TestChangeExplanation(t *testing.T) {
	states, plan := loadFixtures(t)
	res, err := Analyze(states, plan, Options{Now: planTime, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	uami := res.Graph.Nodes["azure::azurerm_user_assigned_identity.workload"]
	if uami == nil {
		t.Fatal("uami node missing")
	}
	check := func(name string, got, want []string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	check("uami changed", uami.ChangedAttrs, []string{"location"})
	check("uami unknown", uami.UnknownAttrs, []string{"client_id", "id", "principal_id"})
	check("uami replace", uami.ReplacePaths, []string{"location"})
	check("uami reasons", uami.Reasons, []string{"replace_because_cannot_update"})

	aks := res.Graph.Nodes["azure::azurerm_kubernetes_cluster.aks"]
	check("aks changed", aks.ChangedAttrs, []string{"default_node_pool"})
	check("aks unknown", aks.UnknownAttrs, []string{"identity"})

	b, _ := json.Marshal(res.Graph.SortedNodes())
	for _, secret := range []string{"northeurope", "westeurope", "SECRET"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("node JSON leaks attribute value %q", secret)
		}
	}
}

func TestPlanAgeAndMismatch(t *testing.T) {
	states, plan := loadFixtures(t)
	res, err := Analyze(states[1:], plan, Options{Now: planTime.Add(48 * time.Hour), Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	got := rules(res.Findings)
	if got["CW008"] != 1 || got["CW003"] != 1 {
		t.Errorf("want CW008 and CW003, got %v", got)
	}
	if res.Plan.PrimaryState != "plan-prior-state" {
		t.Errorf("primary = %q", res.Plan.PrimaryState)
	}
	for _, f := range res.Findings {
		if f.Rule == "CW003" && f.Severity != SevHigh {
			t.Errorf("48h old plan severity = %s", f.Severity)
		}
	}
}

func TestPrimaryStateFlag(t *testing.T) {
	states, plan := loadFixtures(t)
	if _, err := Analyze(states, plan, Options{PrimaryState: "nope", Now: planTime, Getenv: noEnv}); err == nil {
		t.Error("unknown --primary-state should fail")
	}
	res, err := Analyze(states, plan, Options{PrimaryState: "azure", Now: planTime, Getenv: noEnv})
	if err != nil || res.Plan.PrimaryState != "azure" {
		t.Fatalf("primary flag: %v %v", err, res)
	}
}

func rg(stateName, lineage, id string) *state.State {
	st := &state.State{Name: stateName, Path: stateName + ".tfstate", Lineage: lineage}
	st.AddResource(&state.Resource{
		Address: "azurerm_resource_group.main", Mode: "managed", Type: "azurerm_resource_group", Name: "main",
		Cloud:     state.CloudAzure,
		Instances: []state.Instance{{Address: "azurerm_resource_group.main", Attributes: map[string]any{"id": id, "name": "rg"}}},
	})
	return st
}

func TestDuplicateOwnershipAndLineage(t *testing.T) {
	id := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"
	res, err := Analyze([]*state.State{rg("a", "l1", id), rg("b", "l2", id)}, nil, Options{Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	if rules(res.Findings)["CW503"] != 1 {
		t.Errorf("want CW503 for doubly-managed resource, got %v", rules(res.Findings))
	}

	res, err = Analyze([]*state.State{rg("a", "same", id), rg("b", "same", id)}, nil, Options{Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	got := rules(res.Findings)
	if got["CW503"] != 0 || got["CW011"] != 1 {
		t.Errorf("snapshots of one state must not be cross-linked: %v", got)
	}
}

func TestGenericValuesDoNotLink(t *testing.T) {
	a := rg("a", "l1", "/subscriptions/x/resourceGroups/one")
	b := &state.State{Name: "b", Lineage: "l2"}
	b.AddResource(&state.Resource{
		Address: "random_pet.p", Mode: "managed", Type: "random_pet", Name: "p",
		Instances: []state.Instance{{Attributes: map[string]any{"id": "rg", "name": "rg"}}},
	})
	res, err := Analyze([]*state.State{a, b}, nil, Options{Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Graph.Edges {
		if e.Kind == EdgeIDMatch {
			t.Errorf("short generic value created edge %+v", e)
		}
	}
}

func jwt(claims map[string]any) string {
	enc := base64.RawURLEncoding
	body, _ := json.Marshal(claims)
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(body) + ".sig"
}

func TestCredentialChecks(t *testing.T) {
	states, plan := loadFixtures(t)
	now := time.Now().UTC()
	token := jwt(map[string]any{"iss": "https://accounts.google.com", "sub": "999", "exp": now.Add(5 * time.Minute).Unix()})
	env := map[string]string{"ARM_OIDC_TOKEN": token, "ARM_TENANT_ID": "11111111-1111-1111-1111-111111111111"}
	res, err := Analyze(states, plan, Options{
		Now: now, CheckCredentials: true, PlanMaxAge: 24 * 365 * time.Hour,
		Getenv: func(k string) string { return env[k] },
	})
	if err != nil {
		t.Fatal(err)
	}
	got := rules(res.Findings)
	for _, r := range []string{"CW402", "CW406", "CW408"} {
		if got[r] != 1 {
			t.Errorf("want %s, got %v", r, got)
		}
	}
	blob, _ := json.Marshal(res.Findings)
	if strings.Contains(string(blob), token) || strings.Contains(string(blob), "11111111-1111-1111-1111-111111111111") {
		t.Error("credential values leaked into findings")
	}

	env["ARM_OIDC_TOKEN"] = jwt(map[string]any{"exp": now.Add(-time.Minute).Unix()})
	res, _ = Analyze(states, plan, Options{Now: now, CheckCredentials: true, Getenv: func(k string) string { return env[k] }})
	if rules(res.Findings)["CW401"] != 1 {
		t.Error("expired token should raise CW401")
	}
}

func TestParseMember(t *testing.T) {
	pool := "projects/1/locations/global/workloadIdentityPools/p"
	tests := []struct{ in, kind, value string }{
		{"principal://iam.googleapis.com/" + pool + "/subject/abc", "subject", "abc"},
		{"principalSet://iam.googleapis.com/" + pool + "/attribute.tid/t1", "attribute.tid", "t1"},
		{"principalSet://iam.googleapis.com/" + pool + "/*", "*", ""},
	}
	for _, tt := range tests {
		p, kind, value, ok := parseMember(tt.in)
		if !ok || p != pool || kind != tt.kind || value != tt.value {
			t.Errorf("parseMember(%q) = %q %q %q %v", tt.in, p, kind, value, ok)
		}
	}
	if _, _, _, ok := parseMember("serviceAccount:a@b"); ok {
		t.Error("non-WIF member parsed")
	}
}

func TestGraphTraversal(t *testing.T) {
	g := NewGraph()
	for _, id := range []string{"a", "b", "c", "d"} {
		g.AddNode(&Node{ID: id})
	}
	// b depends on a, c depends on b, a depends on d
	g.AddEdge(Edge{From: "b", To: "a", Kind: EdgeDependency})
	g.AddEdge(Edge{From: "c", To: "b", Kind: EdgeDependency})
	g.AddEdge(Edge{From: "a", To: "d", Kind: EdgeDependency})
	g.AddEdge(Edge{From: "c", To: "b", Kind: EdgeDependency, Confidence: ConfHigh})
	if len(g.Edges) != 3 {
		t.Errorf("duplicate edge not merged: %d", len(g.Edges))
	}
	down := g.Downstream([]string{"a"})
	if down["b"] != 1 || down["c"] != 2 || len(down) != 2 {
		t.Errorf("downstream = %v", down)
	}
	if up := g.Upstream([]string{"a"}, 1); up["d"] != 1 || len(up) != 1 {
		t.Errorf("upstream = %v", up)
	}
}
