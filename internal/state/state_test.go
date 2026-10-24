package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAddress(t *testing.T) {
	tests := []struct {
		in, addr, module, mode, typ, name string
	}{
		{"aws_instance.web", "aws_instance.web", "", "managed", "aws_instance", "web"},
		{"aws_instance.web[0]", "aws_instance.web", "", "managed", "aws_instance", "web"},
		{`aws_subnet.a["eu.west.1a"]`, "aws_subnet.a", "", "managed", "aws_subnet", "a"},
		{"data.terraform_remote_state.net", "data.terraform_remote_state.net", "", "data", "terraform_remote_state", "net"},
		{`module.vpc[0].aws_subnet.a["x"]`, `module.vpc[0].aws_subnet.a`, "module.vpc[0]", "managed", "aws_subnet", "a"},
		{`module.a["k.1"].module.b.data.google_project.p`, `module.a["k.1"].module.b.data.google_project.p`, `module.a["k.1"].module.b`, "data", "google_project", "p"},
		{"module.data.azurerm_resource_group.rg", "module.data.azurerm_resource_group.rg", "module.data", "managed", "azurerm_resource_group", "rg"},
	}
	for _, tt := range tests {
		info, err := ParseAddress(tt.in)
		if err != nil {
			t.Errorf("ParseAddress(%q): %v", tt.in, err)
			continue
		}
		if info.Address != tt.addr || info.Module != tt.module || info.Mode != tt.mode || info.Type != tt.typ || info.Name != tt.name {
			t.Errorf("ParseAddress(%q) = %+v", tt.in, info)
		}
	}
}

func TestParseAddressInvalid(t *testing.T) {
	for _, in := range []string{"", "aws_instance", "var.x.y", "module.vpc", "module.vpc.output", "foo.module.x.aws_s3_bucket.b", "aws_instance[0].web", "data.x"} {
		if _, err := ParseAddress(in); err == nil {
			t.Errorf("ParseAddress(%q) succeeded, want error", in)
		}
	}
}

func TestProviderAndCloud(t *testing.T) {
	if got := ProviderShort(`provider["registry.terraform.io/hashicorp/azurerm"]`); got != "azurerm" {
		t.Errorf("ProviderShort raw = %q", got)
	}
	if got := ProviderShort("registry.terraform.io/hashicorp/google-beta"); got != "google-beta" {
		t.Errorf("ProviderShort show-json = %q", got)
	}
	if CloudFor("azuread_application", "") != CloudAzure || CloudFor("x", "registry.terraform.io/hashicorp/google") != CloudGCP ||
		CloudFor("random_id", "") != CloudOther {
		t.Error("CloudFor mismatch")
	}
}

func fixture(name string) string {
	return filepath.Join("..", "..", "testdata", "multicloud", name)
}

func TestLoadRawState(t *testing.T) {
	st, err := LoadState(fixture("azure.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Format != FormatRaw || st.Lineage == "" || st.Serial == nil || *st.Serial != 42 {
		t.Fatalf("unexpected metadata: %+v", st)
	}
	aks := st.ResourceByAddress("azurerm_kubernetes_cluster.aks")
	if aks == nil || aks.Cloud != CloudAzure {
		t.Fatal("aks not loaded")
	}
	if !aks.Instances[0].Sensitive.IsSensitive("/kube_config_raw") {
		t.Error("kube_config_raw should be sensitive")
	}
	for _, l := range aks.IdentityLeaves(st.Name) {
		if strings.Contains(l.Value, "SECRET") {
			t.Errorf("sensitive value leaked into identity leaves: %s", l.Path)
		}
	}
	if len(aks.Dependencies) != 2 {
		t.Errorf("aks dependencies = %v", aks.Dependencies)
	}
	rs := st.ResourceByAddress("data.terraform_remote_state.gcp")
	if rs == nil || rs.Mode != "data" {
		t.Fatal("remote state data source missing")
	}
	if outs := rs.RemoteStateOutputs(); outs["bridge_sa_unique_id"] != "108234567890123456789" {
		t.Errorf("remote state outputs not unwrapped: %v", outs)
	}
}

func TestLoadShowJSONState(t *testing.T) {
	doc := `{"format_version":"1.0","terraform_version":"1.9.5","values":{"outputs":{"o":{"sensitive":true,"value":"x"}},
"root_module":{"resources":[{"address":"google_service_account.sa","mode":"managed","type":"google_service_account","name":"sa",
"provider_name":"registry.terraform.io/hashicorp/google","values":{"email":"a@b.iam.gserviceaccount.com","unique_id":"1234567890123"},"sensitive_values":{}}],
"child_modules":[{"address":"module.m[\"a\"]","resources":[{"address":"module.m[\"a\"].google_project_iam_member.r[0]","mode":"managed",
"type":"google_project_iam_member","name":"r","index":0,"provider_name":"registry.terraform.io/hashicorp/google","values":{"member":"x"},
"sensitive_values":{"member":true},"depends_on":["google_service_account.sa"]}]}]}}}`
	path := filepath.Join(t.TempDir(), "show.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Format != FormatShowJSON || len(st.Resources) != 2 || len(st.Outputs) != 1 || !st.Outputs[0].Sensitive {
		t.Fatalf("unexpected state: %+v", st)
	}
	r := st.ResourceByAddress(`module.m["a"].google_project_iam_member.r`)
	if r == nil || r.Module != `module.m["a"]` || r.Instances[0].IndexKey != "0" {
		t.Fatalf("module resource not normalized: %+v", r)
	}
	if !r.Instances[0].Sensitive.IsSensitive("/member") || r.Dependencies[0] != "google_service_account.sa" {
		t.Errorf("sensitive/deps lost: %+v", r.Instances[0])
	}
}

func TestLoadRejectsWrongKind(t *testing.T) {
	if _, err := LoadState(fixture("azure-plan.json")); err == nil || !strings.Contains(err.Error(), "--plan") {
		t.Errorf("LoadState(plan) err = %v", err)
	}
	if _, err := LoadPlan(fixture("gcp.tfstate")); err == nil || !strings.Contains(err.Error(), "--state") {
		t.Errorf("LoadPlan(state) err = %v", err)
	}
	path := filepath.Join(t.TempDir(), "v3.tfstate")
	os.WriteFile(path, []byte(`{"version":3,"resources":[]}`), 0o600)
	if _, err := LoadState(path); err == nil || !strings.Contains(err.Error(), "format version 3") {
		t.Errorf("LoadState(v3) err = %v", err)
	}
}

func TestLoadPlan(t *testing.T) {
	p, err := LoadPlan(fixture("azure-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, c := range p.Changes {
		actions[c.Address] = c.Action
	}
	want := map[string]string{
		"azurerm_user_assigned_identity.workload":      ActionReplace,
		"azurerm_kubernetes_cluster.aks":               ActionUpdate,
		"azurerm_storage_account.logs":                 ActionCreate,
		"azurerm_key_vault.legacy":                     ActionDelete,
		"azurerm_resource_group.platform":              ActionNoop,
		"azurerm_role_assignment.workload_logs_reader": ActionCreate,
	}
	for addr, a := range want {
		if actions[addr] != a {
			t.Errorf("%s action = %q, want %q", addr, actions[addr], a)
		}
	}
	if len(p.Drifts) != 2 || p.Timestamp == nil || p.Complete == nil || !*p.Complete || p.Errored == nil || *p.Errored {
		t.Errorf("plan metadata wrong: drifts=%d ts=%v", len(p.Drifts), p.Timestamp)
	}
	if strings.Join(p.ChangedOutputs, ",") != "workload_client_id,workload_principal_id" {
		t.Errorf("changed outputs = %v", p.ChangedOutputs)
	}
	if p.PriorState == nil || p.PriorState.ResourceByAddress("azurerm_storage_account.logs") != nil {
		t.Error("prior state should be refreshed and omit the drift-deleted storage account")
	}
	var foundRef bool
	for _, r := range p.RemoteStateRefs {
		if r.ResourceAddress == "azuread_application_federated_identity_credential.from_gcp" &&
			r.DataAddress == "data.terraform_remote_state.gcp" && r.Output == "bridge_sa_unique_id" {
			foundRef = true
		}
	}
	if !foundRef {
		t.Errorf("remote state refs = %+v", p.RemoteStateRefs)
	}
	deps := p.ConfigDeps["azurerm_role_assignment.workload_logs_reader"]
	if strings.Join(deps, ",") != "azurerm_storage_account.logs,azurerm_user_assigned_identity.workload" {
		t.Errorf("config deps = %v", deps)
	}
}

func TestParseRemoteStateReference(t *testing.T) {
	tests := []struct{ in, addr, out string }{
		{"data.terraform_remote_state.network.outputs.vpc_id", "data.terraform_remote_state.network", "vpc_id"},
		{"data.terraform_remote_state.network", "data.terraform_remote_state.network", ""},
		{`data.terraform_remote_state.env["prod"].outputs.ids`, "data.terraform_remote_state.env", "ids"},
	}
	for _, tt := range tests {
		addr, out, ok := parseRemoteStateReference(tt.in)
		if !ok || addr != tt.addr || out != tt.out {
			t.Errorf("parseRemoteStateReference(%q) = %q, %q, %v", tt.in, addr, out, ok)
		}
	}
	if _, _, ok := parseRemoteStateReference("data.aws_vpc.main.id"); ok {
		t.Error("non remote-state reference matched")
	}
}

func TestHashValueNormalizes(t *testing.T) {
	if HashValue("ABCDEF01-2345-4678-9ABC-DEF012345678") != HashValue("abcdef01-2345-4678-9abc-def012345678") {
		t.Error("UUIDs should hash case-insensitively")
	}
	if HashValue("Bucket") == HashValue("bucket") {
		t.Error("generic values should stay case-sensitive")
	}
}

func TestRawSensitiveSetFormats(t *testing.T) {
	tests := map[string]string{
		`[[{"type":"get_attr","value":"conn"},{"type":"index","value":{"value":0,"type":"number"}},{"type":"get_attr","value":"pass/word"}]]`: "/conn/0/pass~1word",
		`[["admin_password"]]`:              "/admin_password",
		`{"site_config":[{"secret":true}]}`: "/site_config/0/secret",
	}
	for in, want := range tests {
		set := rawSensitiveSet([]byte(in))
		if !set.IsSensitive(want) || !set.IsSensitive(want+"/child") {
			t.Errorf("rawSensitiveSet(%s) = %v, want %s", in, set, want)
		}
	}
	if rawSensitiveSet([]byte("null")) != nil || rawSensitiveSet(nil) != nil {
		t.Error("empty input should yield nil")
	}
}
