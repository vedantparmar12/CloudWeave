package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(name string) string {
	return filepath.Join("..", "..", "testdata", "multicloud", name)
}

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Execute("test", args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestAnalyzeWritesReports(t *testing.T) {
	dir := t.TempDir()
	html, js := filepath.Join(dir, "r.html"), filepath.Join(dir, "r.json")
	code, out, errs := run("analyze", "-s", "azure="+fixture("azure.tfstate"), "-s", "gcp="+fixture("gcp.tfstate"),
		"-p", fixture("azure-plan.json"), "-o", html, "--json", js)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "CloudWeave preflight: BLOCK") || !strings.Contains(out, "state azure") {
		t.Errorf("summary = %s", out)
	}
	for _, p := range []string{html, js} {
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Errorf("%s not written: %v", p, err)
		}
	}
}

func TestFailOnExitCode(t *testing.T) {
	args := []string{"analyze", "-q", "-s", fixture("azure.tfstate"), "-s", fixture("gcp.tfstate"), "-p", fixture("azure-plan.json")}
	if code, _, _ := run(append(args, "--fail-on", "critical")...); code != 2 {
		t.Errorf("--fail-on critical exit = %d, want 2", code)
	}
	if code, _, _ := run(append(args, "--fail-on", "none")...); code != 0 {
		t.Errorf("--fail-on none exit = %d, want 0", code)
	}
	if code, _, errs := run(append(args, "--fail-on", "bogus")...); code != 1 || !strings.Contains(errs, "fail-on") {
		t.Errorf("bad --fail-on exit = %d: %s", code, errs)
	}
}

func TestRefusesToOverwriteInputs(t *testing.T) {
	dir := t.TempDir()
	src, _ := os.ReadFile(fixture("gcp.tfstate"))
	statePath := filepath.Join(dir, "gcp.json")
	os.WriteFile(statePath, src, 0o600)

	for _, out := range []string{statePath, filepath.Join(dir, "terraform.tfstate"), filepath.Join(dir, "x.tfstate.backup")} {
		code, _, errs := run("analyze", "-q", "-s", statePath, "--json", out)
		if code != 1 || !strings.Contains(errs, "refusing") {
			t.Errorf("output %s: exit %d, %s", out, code, errs)
		}
	}
	after, _ := os.ReadFile(statePath)
	if !bytes.Equal(src, after) {
		t.Fatal("input state was modified")
	}
}

func TestSplitStateSpec(t *testing.T) {
	tests := []struct{ in, name, path string }{
		{"prod=a.tfstate", "prod", "a.tfstate"},
		{"a.tfstate", "", "a.tfstate"},
		{`C:\x\a=b.tfstate`, "", `C:\x\a=b.tfstate`},
		{"dir/a=b.tfstate", "", "dir/a=b.tfstate"},
		{"=a.tfstate", "", "=a.tfstate"},
	}
	for _, tt := range tests {
		n, p := splitStateSpec(tt.in)
		if n != tt.name || p != tt.path {
			t.Errorf("splitStateSpec(%q) = %q, %q", tt.in, n, p)
		}
	}
}

func TestVersionAndErrors(t *testing.T) {
	if code, out, _ := run("version"); code != 0 || !strings.Contains(out, "cloudweave test") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, _, errs := run("analyze"); code != 1 || !strings.Contains(errs, "--state") {
		t.Errorf("no inputs: %d %q", code, errs)
	}
}
