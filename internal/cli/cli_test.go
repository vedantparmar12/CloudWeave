package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
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

func TestMarkdownOutput(t *testing.T) {
	base := []string{"analyze", "-s", "azure=" + fixture("azure.tfstate"), "-s", "gcp=" + fixture("gcp.tfstate"), "-p", fixture("azure-plan.json")}
	code, out, errs := run(append(base, "--markdown", "-")...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.HasPrefix(out, "## CloudWeave preflight") || strings.Contains(out, "CloudWeave preflight: BLOCK") {
		t.Errorf("stdout should hold only Markdown: %s", out)
	}
	if strings.Contains(out, "SECRET") || strings.Contains(out, "northeurope") {
		t.Error("attribute values leaked into Markdown")
	}

	p := filepath.Join(t.TempDir(), "r.md")
	if code, _, errs := run(append(base, "--markdown", p, "--json", p)...); code != 1 || !strings.Contains(errs, "different files") {
		t.Errorf("duplicate outputs: exit %d, %s", code, errs)
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

func TestSimulationBlocksFailOnHigh(t *testing.T) {
	dir := t.TempDir()
	statePath, planPath := filepath.Join(dir, "snapshot.json"), filepath.Join(dir, "plan.json")
	snapshot := `{"version":4,"terraform_version":"1.9.5","resources":[
		{"mode":"managed","type":"null_resource","name":"a","instances":[{"attributes":{"id":"a"},"dependencies":["null_resource.b"]}]},
		{"mode":"managed","type":"null_resource","name":"b","instances":[{"attributes":{"id":"b"},"dependencies":["null_resource.a"]}]}
	]}`
	plan := `{"format_version":"1.2","terraform_version":"1.9.5","complete":true,"applyable":true,"resource_changes":[
		{"address":"null_resource.a","mode":"managed","type":"null_resource","name":"a","change":{"actions":["update"],"before":{"id":"a"},"after":{"id":"a"}}},
		{"address":"null_resource.b","mode":"managed","type":"null_resource","name":"b","change":{"actions":["update"],"before":{"id":"b"},"after":{"id":"b"}}}
	]}`
	for path, data := range map[string]string{statePath: snapshot, planPath: plan} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct {
		threshold string
		code      int
	}{{"high", exitFindings}, {"critical", exitOK}, {"none", exitOK}} {
		code, out, errs := run("analyze", "--state", "s="+statePath, "--primary-state", "s", "--plan", planPath, "--json", "-", "--fail-on", tt.threshold)
		if code != tt.code || errs != "" {
			t.Fatalf("threshold %s: exit %d, errors %q", tt.threshold, code, errs)
		}
		var result struct {
			Verdict  string `json:"verdict"`
			Findings []struct {
				Rule string `json:"rule"`
			} `json:"findings"`
			Simulation struct {
				Blocked int `json:"blocked"`
			} `json:"simulation"`
		}
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if result.Verdict != "review" || result.Simulation.Blocked != 2 || len(result.Findings) != 1 || result.Findings[0].Rule != "CW601" {
			t.Fatalf("unresolved simulation not reflected in verdict: %s", out)
		}
	}
	for path, want := range map[string]string{statePath: snapshot, planPath: plan} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("input changed: %s, %v", path, err)
		}
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

const cliPGSecret = "CLI_PG_SECRET_DO_NOT_PRINT"
const cliPGEmptyState = `{"version":4,"serial":7,"lineage":"pg-cli","resources":[]}`

func cleanCLIPGEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE", "PGAPPNAME",
		"PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT", "PGSSLSNI", "PGSSLROOTCERT",
		"PGSSLPASSWORD", "PGSSLNEGOTIATION", "PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS",
	} {
		t.Setenv(key, "")
	}
}

func TestAnalyzePGStateErrorsDoNotLeak(t *testing.T) {
	cleanCLIPGEnv(t)
	const env = "CLOUDWEAVE_CLI_PG_DSN"
	for _, tt := range []struct{ name, spec, value, want string }{
		{"invalid spec", cliPGSecret, "", "invalid --pg-state"},
		{"direct URL", "prod=postgres://test:" + cliPGSecret + "@localhost/db", "", "invalid --pg-state"},
		{"keyword DSN", "prod=host=localhost password=" + cliPGSecret, "", "invalid --pg-state"},
		{"empty label", "=" + cliPGSecret, "", "invalid --pg-state"},
		{"empty env name", "prod=", "", "invalid --pg-state"},
		{"unset env", "prod=" + env, "", "environment variable is unset or empty"},
		{"blank env", "prod=" + env, " \n\t", "environment variable is unset or empty"},
		{"invalid DSN", "prod=" + env, "postgres://test:" + cliPGSecret + "@localhost:%zz/db", "invalid PostgreSQL state connection configuration"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(env, tt.value)
			if tt.name == "unset env" {
				if err := os.Unsetenv(env); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(t.TempDir(), "report.json")
			code, out, errs := run("analyze", "--pg-state", tt.spec, "--json", path)
			if code != exitError || !strings.Contains(errs, tt.want) {
				t.Fatalf("exit=%d, error=%q; want %q", code, errs, tt.want)
			}
			assertCLIPGNoSecrets(t, out+errs)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Error("report was created on a PostgreSQL input error")
			}
		})
	}
}

func TestAnalyzePGStateReports(t *testing.T) {
	cleanCLIPGEnv(t)
	for _, combined := range []bool{false, true} {
		t.Run(fmt.Sprintf("combined=%t", combined), func(t *testing.T) {
			schema, workspace := "terraform_remote_state", "default"
			payloads := [][]byte{[]byte(cliPGEmptyState)}
			if combined {
				schema, workspace = `Custom".Schema`, `prod'workspace`
				azure, err := os.ReadFile(fixture("azure.tfstate"))
				if err != nil {
					t.Fatal(err)
				}
				payloads = [][]byte{azure, []byte(cliPGEmptyState)}
			}
			dsn, wait := startCLIPGWire(t, schema, workspace, payloads...)
			t.Setenv("CLOUDWEAVE_CLI_PG_DSN", dsn)
			t.Setenv("CLOUDWEAVE_CLI_OTHER_PG_DSN", dsn)
			dir := t.TempDir()
			html, md := filepath.Join(dir, "report.html"), filepath.Join(dir, "report.md")
			args := []string{"analyze", "--pg-state", "prod=CLOUDWEAVE_CLI_PG_DSN", "--json", "-", "--out", html, "--markdown", md}
			if combined {
				args = append(args, "--pg-state", "aux=CLOUDWEAVE_CLI_OTHER_PG_DSN", "--pg-schema", schema, "--pg-workspace", workspace,
					"--state", "gcp="+fixture("gcp.tfstate"), "--plan", fixture("azure-plan.json"), "--primary-state", "prod")
			}
			code, out, errs := run(args...)
			if code != exitOK {
				t.Fatalf("exit %d: %s", code, errs)
			}
			wait()
			var rep struct {
				States []struct{ Name string }
				Plan   *struct {
					PrimaryState string `json:"primary_state"`
				}
			}
			if err := json.Unmarshal([]byte(out), &rep); err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, st := range rep.States {
				names = append(names, st.Name)
			}
			wantNames := []string{"prod"}
			if combined {
				wantNames = []string{"gcp", "prod", "aux"}
				if rep.Plan == nil || rep.Plan.PrimaryState != "prod" {
					t.Error("plan was not analyzed with the named PostgreSQL state")
				}
			}
			if !reflect.DeepEqual(names, wantNames) {
				t.Errorf("state names = %v, want %v", names, wantNames)
			}
			assertCLIPGNoSecrets(t, out+errs)
			if !strings.Contains(out, "PostgreSQL reads still acquire normal database read locks") {
				t.Error("PostgreSQL report must distinguish advisory locks from normal read locks")
			}
			for _, path := range []string{html, md} {
				data, err := os.ReadFile(path)
				if err != nil || len(data) == 0 {
					t.Fatalf("read report: %v", err)
				}
				assertCLIPGNoSecrets(t, string(data))
			}
		})
	}
}

func assertCLIPGNoSecrets(t *testing.T, text string) {
	t.Helper()
	for _, secret := range []string{cliPGSecret, "CLOUDWEAVE_CLI_PG_DSN", "CLOUDWEAVE_CLI_OTHER_PG_DSN", "postgres://", "cloudweave_pg_test_user"} {
		if strings.Contains(text, secret) {
			t.Fatal("PostgreSQL input details leaked into CLI output or a report")
		}
	}
}

func TestAnalyzePGPreservesFileCollisionProtections(t *testing.T) {
	dir := t.TempDir()
	statePath, planPath := filepath.Join(dir, "state.json"), filepath.Join(dir, "plan.json")
	for dst, src := range map[string]string{statePath: fixture("azure.tfstate"), planPath: fixture("azure-plan.json")} {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Validation must happen before any PG connection and must retain both
	// file inputs. An unset PG env also guards against accidental networking.
	t.Setenv("CLOUDWEAVE_CLI_PG_DSN", "")
	for _, path := range []string{statePath, planPath, filepath.Join(dir, "other.tfstate")} {
		for _, flag := range []string{"--json", "--out", "--markdown"} {
			code, _, errs := run("analyze", "--state", "azure="+statePath, "--plan", planPath,
				"--pg-state", "prod=CLOUDWEAVE_CLI_PG_DSN", flag, path)
			if code != exitError || !strings.Contains(errs, "refusing") {
				t.Errorf("mixed-input collision: exit %d, %s", code, errs)
			}
		}
	}
	for dst, src := range map[string]string{statePath: fixture("azure.tfstate"), planPath: fixture("azure-plan.json")} {
		before, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(dst)
		if err != nil || !bytes.Equal(before, after) {
			t.Error("mixed-input analysis modified an input file")
		}
	}
}

func TestAnalyzePGUsesCommandContext(t *testing.T) {
	cleanCLIPGEnv(t)
	dsn, _ := startCLIPGWire(t, "terraform_remote_state", "default", []byte(cliPGEmptyState))
	t.Setenv("CLOUDWEAVE_CLI_PG_DSN", dsn)
	var out, errb bytes.Buffer
	cmd := newRoot("test", &out, &errb)
	cmd.SetArgs([]string{"analyze", "--pg-state", "prod=CLOUDWEAVE_CLI_PG_DSN"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cmd.ExecuteContext(ctx); err == nil || err.Error() != "connect to PostgreSQL state failed" {
		t.Fatalf("canceled command: %v", err)
	}
	assertCLIPGNoSecrets(t, out.String()+errb.String())
}

// A small happy-path wire fake exercises the actual loader through Cobra.
// The state package tests cover driver/server/parse failures in more detail.
func startCLIPGWire(t *testing.T, schema, workspace string, payloads ...[]byte) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		for _, data := range payloads {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			err = serveCLIPGWire(conn, schema, workspace, data)
			conn.Close()
			if err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	return "postgres://cloudweave_pg_test_user:" + cliPGSecret + "@" + listener.Addr().String() + "/test?sslmode=disable", func() {
		t.Helper()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("CLI PostgreSQL wire test did not finish")
		}
	}
}

func serveCLIPGWire(conn net.Conn, schema, workspace string, data []byte) error {
	backend := pgproto3.NewBackend(conn, conn)
	if _, err := backend.ReceiveStartupMessage(); err != nil {
		return err
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0"})
	backend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return err
	}
	var statements []string
	status := byte('I')
	for {
		msg, err := backend.Receive()
		if err != nil {
			return err
		}
		switch msg := msg.(type) {
		case *pgproto3.Query:
			statements = append(statements, msg.String)
			if msg.String == "begin read only" {
				status = 'T'
				backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
			} else if msg.String == "rollback" {
				status = 'I'
				backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("ROLLBACK")})
			} else {
				return fmt.Errorf("unexpected SQL in CLI wire test")
			}
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: status})
		case *pgproto3.Parse:
			statements = append(statements, msg.Query)
			backend.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Bind:
			if len(msg.Parameters) != 1 || string(msg.Parameters[0]) != workspace {
				return fmt.Errorf("CLI did not pass workspace as a bound parameter")
			}
			backend.Send(&pgproto3.BindComplete{})
		case *pgproto3.Describe:
			backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("data"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}}})
		case *pgproto3.Execute:
			backend.Send(&pgproto3.DataRow{Values: [][]byte{data}})
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
		case *pgproto3.Sync:
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: status})
		case *pgproto3.Terminate:
			query := `SELECT data FROM "` + strings.ReplaceAll(schema, `"`, `""`) + `"."states" WHERE name=$1`
			if !reflect.DeepEqual(statements, []string{"begin read only", query, "rollback"}) {
				return fmt.Errorf("CLI did not issue only BEGIN READ ONLY, SELECT, ROLLBACK")
			}
			return nil
		default:
			return fmt.Errorf("unexpected CLI wire message: %T", msg)
		}
		if err := backend.Flush(); err != nil {
			return err
		}
	}
}
