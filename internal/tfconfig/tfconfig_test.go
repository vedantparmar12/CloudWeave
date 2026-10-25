package tfconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// loadFrom writes files into a fresh temp dir and runs Load on it.
func loadFrom(t *testing.T, files map[string]string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return Load(dir)
}

// mustLoad is loadFrom for cases expected to load without error.
func mustLoad(t *testing.T, files map[string]string) *Config {
	t.Helper()
	cfg, err := loadFrom(t, files)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestLoadResourceLifecycleAndMetaArguments(t *testing.T) {
	tests := []struct {
		name string
		tf   string
		want map[string]Resource
	}{
		{
			name: "literal lifecycle flags",
			tf: `
resource "aws_instance" "web" {
  ami = "ami-123"

  lifecycle {
    prevent_destroy       = true
    create_before_destroy = true
  }
}
`,
			want: map[string]Resource{
				"aws_instance.web": {PreventDestroy: true, CreateBeforeDestroy: true},
			},
		},
		{
			name: "literal false flags are accepted as false",
			tf: `
resource "aws_instance" "web" {
  lifecycle {
    prevent_destroy       = false
    create_before_destroy = false
  }
}
`,
			want: map[string]Resource{
				"aws_instance.web": {},
			},
		},
		{
			name: "count and for_each recorded by presence only",
			tf: `
resource "aws_instance" "web" {
  count = var.instance_count
}
resource "aws_s3_bucket" "logs" {
  for_each = toset(var.bucket_names)
}
resource "aws_lb" "app" {
  count = 2
}
`,
			want: map[string]Resource{
				"aws_instance.web":   {Count: true},
				"aws_s3_bucket.logs": {ForEach: true},
				"aws_lb.app":         {Count: true},
			},
		},
		{
			name: "non-literal lifecycle expressions silently skipped",
			tf: `
resource "aws_instance" "web" {
  count = 1
  lifecycle {
    prevent_destroy       = var.lock
    create_before_destroy = local.cbd
  }
}
`,
			want: map[string]Resource{
				"aws_instance.web": {Count: true},
			},
		},
		{
			name: "unknown lifecycle arguments and provisioners tolerated",
			tf: `
resource "aws_instance" "web" {
  lifecycle {
    prevent_destroy = true
    ignore_changes  = ["tags"]
  }

  provisioner "local-exec" {
    command = "echo hi"
  }
}
`,
			want: map[string]Resource{
				"aws_instance.web": {PreventDestroy: true},
			},
		},
		{
			name: "resource without count, for_each or lifecycle",
			tf: `
resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
`,
			want: map[string]Resource{
				"aws_instance.web": {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustLoad(t, map[string]string{"main.tf": tt.tf})
			if !reflect.DeepEqual(cfg.Resources, tt.want) {
				t.Errorf("Resources = %+v, want %+v", cfg.Resources, tt.want)
			}
		})
	}
}

func TestLoadRemoteState(t *testing.T) {
	cfg := mustLoad(t, map[string]string{"main.tf": `
data "terraform_remote_state" "prod" {
  backend = "s3"

  config = {
    bucket    = "cloudweave-prod"
    key       = "prod/terraform.tfstate"
    region    = "eu-west-1"
    workspace = "prod"
  }
}

data "terraform_remote_state" "stage" {
  backend = "azurerm"

  config = {
    resource_group_name = "rg"
    workspace           = var.workspace
  }
}

data "terraform_remote_state" "db" {
  backend = pg
}
`})

	want := map[string]RemoteState{
		// Quoted literal backend keyword with a fully literal config object.
		"data.terraform_remote_state.prod": {Backend: "s3", Workspace: "prod"},
		// Non-literal workspace: the config object is skipped, the backend
		// keyword is still recorded.
		"data.terraform_remote_state.stage": {Backend: "azurerm"},
		// Bare keyword backend, no config at all.
		"data.terraform_remote_state.db": {Backend: "pg"},
	}
	if !reflect.DeepEqual(cfg.RemoteStates, want) {
		t.Errorf("RemoteStates = %+v, want %+v", cfg.RemoteStates, want)
	}
}

func TestLoadRemoteStateCredentialsNeverReachOutput(t *testing.T) {
	const sentinel = "postgres://user:SENTINEL_PASSWORD@db"

	cfg := mustLoad(t, map[string]string{"main.tf": `
data "terraform_remote_state" "db" {
  backend = "pg"

  config = {
    conn_string = "` + sentinel + `"
    workspace   = "default"
    schema      = "public"
  }
}

resource "aws_instance" "web" {
  count = 1
}
`})

	rs, ok := cfg.RemoteStates["data.terraform_remote_state.db"]
	if !ok {
		t.Fatal("missing data.terraform_remote_state.db")
	}
	if rs.Backend != "pg" {
		t.Errorf("Backend = %q, want %q", rs.Backend, "pg")
	}
	if rs.Workspace != "default" {
		t.Errorf("Workspace = %q, want %q", rs.Workspace, "default")
	}

	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal Config: %v", err)
	}
	if strings.Contains(string(blob), sentinel) || strings.Contains(string(blob), "SENTINEL_PASSWORD") {
		t.Errorf("marshaled Config leaks backend config credentials: %s", blob)
	}
	if !strings.Contains(string(blob), `"Backend":"pg"`) || !strings.Contains(string(blob), `"Workspace":"default"`) {
		t.Errorf("marshaled Config lost Backend/Workspace: %s", blob)
	}
}

func TestLoadRequiredVersion(t *testing.T) {
	tests := []struct {
		name string
		tf   string
		want string
	}{
		{
			name: "literal constraint",
			tf: `
terraform {
  required_version = ">= 1.5.0"
}
`,
			want: ">= 1.5.0",
		},
		{
			name: "nested backend and required_providers blocks ignored",
			tf: `
terraform {
  required_version = "~> 1.9"

  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }

  backend "s3" {}
}
`,
			want: "~> 1.9",
		},
		{
			name: "expression value skipped",
			tf: `
terraform {
  required_version = var.tf_version
}
`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustLoad(t, map[string]string{"main.tf": tt.tf})
			if cfg.RequiredVersion != tt.want {
				t.Errorf("RequiredVersion = %q, want %q", cfg.RequiredVersion, tt.want)
			}
		})
	}
}

func TestLoadParseError(t *testing.T) {
	_, err := loadFrom(t, map[string]string{
		"broken.tf": "resource \"aws_instance\" \"web\" {\n  count =\n}\n",
	})
	if err == nil {
		t.Fatal("Load succeeded, want parse error")
	}
	if !strings.Contains(err.Error(), "broken.tf") {
		t.Errorf("error %q does not mention the filename", err)
	}
}

func TestLoadNoTFFiles(t *testing.T) {
	t.Run("only .tf.json files", func(t *testing.T) {
		cfg, err := loadFrom(t, map[string]string{
			"main.tf.json": `{"terraform": {"required_version": ">= 1.0"}}`,
		})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg == nil {
			t.Fatal("nil Config")
		}
		if len(cfg.Resources) != 0 || len(cfg.RemoteStates) != 0 || cfg.RequiredVersion != "" {
			t.Errorf("want empty Config, got %+v", cfg)
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		cfg, err := Load(t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg == nil {
			t.Fatal("nil Config")
		}
		if len(cfg.Resources) != 0 || len(cfg.RemoteStates) != 0 || cfg.RequiredVersion != "" {
			t.Errorf("want empty Config, got %+v", cfg)
		}
	})
}

func TestLoadIgnoresOtherBlocks(t *testing.T) {
	cfg := mustLoad(t, map[string]string{"main.tf": `
module "vpc" {
  source = "hashicorp/vpc/aws"
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

provider "aws" {
  region = var.region
}

locals {
  name = "cloudweave"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
}
`})

	if len(cfg.Resources) != 0 {
		t.Errorf("Resources = %+v, want none", cfg.Resources)
	}
	if len(cfg.RemoteStates) != 0 {
		t.Errorf("RemoteStates = %+v, want none (non-remote-state data blocks are ignored)", cfg.RemoteStates)
	}
	if cfg.RequiredVersion != "" {
		t.Errorf("RequiredVersion = %q, want empty", cfg.RequiredVersion)
	}
	if !cfg.UnresolvedModules {
		t.Error("UnresolvedModules = false, want true for the registry module source")
	}
}

// writeTree writes a nested directory tree of .tf files under root.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, src := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadFollowsLocalModules(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"main.tf": `
terraform {
  required_version = ">= 1.9"
}

module "vpc" {
  source = "./mods/vpc"
}

module "shared" {
  source = "./mods/shared"
}

data "terraform_remote_state" "prod" {
  backend = "s3"

  config = {
    workspace = "prod"
  }
}

resource "aws_instance" "root" {
  count = 1
}
`,
		"mods/vpc/main.tf": `
resource "aws_instance" "web" {
  count = 2

  lifecycle {
    create_before_destroy = true
  }
}

data "terraform_remote_state" "peer" {
  backend = "pg"

  config = {
    conn_string = "postgres://user:MODULE_SENTINEL_PASSWORD@db"
    workspace   = "dev"
  }
}

module "shared" {
  source = "../shared"
}
`,
		"mods/shared/main.tf": `
resource "aws_s3_bucket" "logs" {
  lifecycle {
    prevent_destroy = true
  }
}
`,
	})
	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// shared is reached both directly and through vpc: the diamond records
	// both module-prefixed addresses.
	wantResources := map[string]Resource{
		"aws_instance.root":                           {Count: true},
		"module.vpc.aws_instance.web":                 {CreateBeforeDestroy: true, Count: true},
		"module.shared.aws_s3_bucket.logs":            {PreventDestroy: true},
		"module.vpc.module.shared.aws_s3_bucket.logs": {PreventDestroy: true},
	}
	if !reflect.DeepEqual(cfg.Resources, wantResources) {
		t.Errorf("Resources = %+v, want %+v", cfg.Resources, wantResources)
	}
	wantRemote := map[string]RemoteState{
		"data.terraform_remote_state.prod":            {Backend: "s3", Workspace: "prod"},
		"module.vpc.data.terraform_remote_state.peer": {Backend: "pg", Workspace: "dev"},
	}
	if !reflect.DeepEqual(cfg.RemoteStates, wantRemote) {
		t.Errorf("RemoteStates = %+v, want %+v", cfg.RemoteStates, wantRemote)
	}
	if cfg.RequiredVersion != ">= 1.9" {
		t.Errorf("RequiredVersion = %q", cfg.RequiredVersion)
	}
	if cfg.UnresolvedModules {
		t.Error("UnresolvedModules = true, want false")
	}
}

func TestLoadSkipsUnreadableModuleSources(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"main.tf": `
module "vpc" {
  source = "hashicorp/vpc/aws"
}

module "net" {
  source = var.module_source
}

module "git" {
  source = "git::https://example.com/net.git"
}

module "local" {
  source = "./mods/local"
}
`,
		"mods/local/main.tf": `
resource "aws_instance" "x" {
}
`,
	})
	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]Resource{"module.local.aws_instance.x": {}}
	if !reflect.DeepEqual(cfg.Resources, want) {
		t.Errorf("Resources = %+v, want %+v", cfg.Resources, want)
	}
	if !cfg.UnresolvedModules {
		t.Error("UnresolvedModules = false, want true")
	}
}

func TestLoadModuleSubdirectorySource(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"main.tf": `
module "x" {
  source = "./mods//sub"
}
`,
		"mods/sub/main.tf": `
resource "aws_instance" "s" {
}
`,
	})
	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]Resource{"module.x.aws_instance.s": {}}
	if !reflect.DeepEqual(cfg.Resources, want) {
		t.Errorf("Resources = %+v, want %+v", cfg.Resources, want)
	}
}

func TestLoadMissingLocalModuleIsFatal(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"main.tf": `
module "vpc" {
  source = "./nope"
}
`,
	})
	_, err := Load(root)
	if err == nil {
		t.Fatal("Load succeeded, want error for missing local module")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error %q does not mention the missing module source", err)
	}
}

func TestLoadModuleCycleIsFatal(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/main.tf": `
module "b" {
  source = "../b"
}
`,
		"b/main.tf": `
module "a" {
  source = "../a"
}
`,
	})
	_, err := Load(filepath.Join(root, "a"))
	if err == nil {
		t.Fatal("Load succeeded, want error for module cycle")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error %q does not mention the cycle", err)
	}
}

func TestLoadMergesFiles(t *testing.T) {
	cfg := mustLoad(t, map[string]string{
		"a.tf": `
resource "aws_instance" "web" {
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "logs" {
  for_each = toset(var.names)
}

data "terraform_remote_state" "prod" {
  backend = "s3"

  config = {
    workspace = "prod"
  }
}
`,
		"b.tf": `
resource "aws_instance" "web" {
  count = 2

  lifecycle {
    create_before_destroy = true
  }
}

data "terraform_remote_state" "stage" {
  backend = "gcs"

  config = {
    workspace = "stage"
  }
}
`,
	})

	// b.tf sorts after a.tf, so it wins the duplicate aws_instance.web
	// address outright rather than being merged into a.tf's resource.
	got := cfg.Resources["aws_instance.web"]
	want := Resource{CreateBeforeDestroy: true, Count: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("aws_instance.web = %+v, want %+v", got, want)
	}
	if _, ok := cfg.Resources["aws_s3_bucket.logs"]; !ok {
		t.Error("aws_s3_bucket.logs from a.tf missing after merge")
	}
	if len(cfg.Resources) != 2 {
		t.Errorf("len(Resources) = %d, want 2", len(cfg.Resources))
	}

	wantRemote := map[string]RemoteState{
		"data.terraform_remote_state.prod":  {Backend: "s3", Workspace: "prod"},
		"data.terraform_remote_state.stage": {Backend: "gcs", Workspace: "stage"},
	}
	if !reflect.DeepEqual(cfg.RemoteStates, wantRemote) {
		t.Errorf("RemoteStates = %+v, want %+v", cfg.RemoteStates, wantRemote)
	}
}
