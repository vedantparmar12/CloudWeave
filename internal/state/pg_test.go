package state

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

const pgTestSecret = "PG_TEST_SECRET_DO_NOT_PRINT"
const pgTestData = `{"version":4,"terraform_version":"1.9.5","serial":42,"lineage":"pg-lineage","outputs":{"v":{"value":"plain text","sensitive":false}},"resources":[]}`

// All network tests use a loopback-only fake, never an existing database or
// real credentials. Clear libpq defaults so a developer's environment cannot
// affect the fake connection (including service files and session checks).
func cleanPGTestEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE", "PGAPPNAME",
		"PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT", "PGSSLSNI", "PGSSLROOTCERT",
		"PGSSLPASSWORD", "PGSSLNEGOTIATION", "PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadPGStateValidation(t *testing.T) {
	cleanPGTestEnv(t)
	const env = "CLOUDWEAVE_PG_TEST_DSN"
	tests := []struct {
		name, spec, value, schema, workspace, want string
		unset                                      bool
	}{
		{name: "missing equals", spec: pgTestSecret, want: "invalid --pg-state"},
		{name: "empty name", spec: "=" + env, want: "invalid --pg-state"},
		{name: "empty env", spec: "prod=", want: "invalid --pg-state"},
		{name: "extra equals", spec: "prod=" + env + "=" + pgTestSecret, want: "invalid --pg-state"},
		{name: "URL instead of spec", spec: "postgres://user:" + pgTestSecret + "@localhost/db", want: "invalid --pg-state"},
		{name: "URL instead of env", spec: "prod=postgres://user:" + pgTestSecret + "@localhost/db", want: "invalid --pg-state"},
		{name: "keyword DSN", spec: "prod=host=localhost password=" + pgTestSecret, want: "invalid --pg-state"},
		{name: "unsafe label", spec: pgTestSecret + "/prod=" + env, want: "invalid --pg-state"},
		{name: "numeric env", spec: "prod=1" + pgTestSecret, want: "invalid --pg-state"},
		{name: "env expansion", spec: "prod=$" + pgTestSecret, want: "invalid --pg-state"},
		{name: "env spaces", spec: "prod= " + pgTestSecret, want: "invalid --pg-state"},
		{name: "unset env", unset: true, want: "environment variable is unset or empty"},
		{name: "empty env value", want: "environment variable is unset or empty"},
		{name: "blank env value", value: " \t\n", want: "environment variable is unset or empty"},
		{name: "malformed URL", value: "postgres://user:" + pgTestSecret + "@localhost:%zz/db", want: "invalid PostgreSQL state connection configuration"},
		{name: "malformed keyword", value: "password='" + pgTestSecret, want: "invalid PostgreSQL state connection configuration"},
		{name: "driver option error", value: "host=127.0.0.1 password=" + pgTestSecret + " connect_timeout=invalid", want: "invalid PostgreSQL state connection configuration"},
		{name: "session check SQL", value: "host=127.0.0.1 password=" + pgTestSecret + " target_session_attrs=read-only", want: "do not support target_session_attrs"},
		{name: "NUL schema", schema: pgTestSecret + "\x00", want: "invalid PostgreSQL state schema"},
		{name: "NUL workspace", workspace: pgTestSecret + "\x00", want: "invalid PostgreSQL state workspace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(env, tt.value)
			if tt.unset {
				if err := os.Unsetenv(env); err != nil {
					t.Fatal(err)
				}
			}
			spec, schema, workspace := tt.spec, tt.schema, tt.workspace
			if spec == "" {
				spec = "prod=" + env
			}
			if schema == "" {
				schema = DefaultPGSchema
			}
			if workspace == "" {
				workspace = DefaultPGWorkspace
			}
			st, err := LoadPGState(context.Background(), spec, schema, workspace)
			assertPGError(t, st, err, tt.want)
		})
	}
	for _, args := range [][2]string{{"", "default"}, {DefaultPGSchema, ""}} {
		st, err := LoadPGState(context.Background(), "prod="+env, args[0], args[1])
		assertPGError(t, st, err, "invalid PostgreSQL state")
	}
}

func assertPGError(t *testing.T, st *State, err error, want string) {
	t.Helper()
	if st != nil || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("state=%v, error=%v; want %q", st, err, want)
	}
	if strings.Contains(fmt.Sprintf("%+v", err), pgTestSecret) || errors.Unwrap(err) != nil {
		t.Fatal("error exposes sensitive data or retains a driver/parse error")
	}
}

func TestPGStateQueryQuotesSchema(t *testing.T) {
	for _, tt := range []struct{ schema, want string }{
		{DefaultPGSchema, `SELECT data FROM "terraform_remote_state"."states" WHERE name=$1`},
		{"Mixed.Case", `SELECT data FROM "Mixed.Case"."states" WHERE name=$1`},
		{`x"; DROP TABLE states; --`, `SELECT data FROM "x""; DROP TABLE states; --"."states" WHERE name=$1`},
	} {
		if got := pgStateQuery(tt.schema); got != tt.want {
			t.Errorf("query = %q, want %q", got, tt.want)
		}
	}
}

func TestLoadPGStateReadOnlyWire(t *testing.T) {
	cleanPGTestEnv(t)
	const schema = `custom".schema; --`
	const workspace = `prod'; SELECT pg_advisory_lock(1); --`
	// Even a DSN requesting simple protocol must keep workspace parameterized.
	dsn, done := startPGWire(t, pgWireOptions{data: []byte(pgTestData)})
	t.Setenv("CLOUDWEAVE_PG_TEST_DSN", dsn+"&default_query_exec_mode=simple_protocol")
	st, err := LoadPGState(context.Background(), "prod-eu.1=CLOUDWEAVE_PG_TEST_DSN", schema, workspace)
	if err != nil {
		t.Fatal(err)
	}
	if st.Name != "prod-eu.1" || st.Path != "" || st.Format != FormatRaw || st.Serial == nil || *st.Serial != 42 || st.Lineage != "pg-lineage" || len(st.Outputs) != 1 || st.Outputs[0].Value != "plain text" {
		t.Fatalf("incorrect PostgreSQL state metadata: %+v", st)
	}
	result := awaitPGWire(t, done)
	assertPGStatements(t, result, schema)
	if result.workspace != workspace {
		t.Errorf("workspace was not sent as a bound parameter: %q", result.workspace)
	}
}

func TestLoadPGStateWireErrors(t *testing.T) {
	cleanPGTestEnv(t)
	for _, tt := range []struct {
		name, want string
		opts       pgWireOptions
	}{
		{"connect", "connect to PostgreSQL state failed", pgWireOptions{fail: "connect"}},
		{"begin", "begin read-only PostgreSQL state transaction failed", pgWireOptions{fail: "begin"}},
		{"query", "read PostgreSQL state failed", pgWireOptions{fail: "query"}},
		{"rollback", "rollback PostgreSQL state transaction failed", pgWireOptions{data: []byte(pgTestData), fail: "rollback"}},
		{"missing workspace", "PostgreSQL state workspace not found", pgWireOptions{noRows: true}},
		{"NULL data", "read PostgreSQL state failed", pgWireOptions{}},
		{"bad JSON", "parse PostgreSQL state failed", pgWireOptions{data: []byte(pgTestSecret)}},
		{"trailing JSON", "parse PostgreSQL state failed", pgWireOptions{data: []byte(pgTestData + pgTestSecret)}},
		{"wrong format", "parse PostgreSQL state failed", pgWireOptions{data: []byte(`{"version":3}`)}},
		{"JSON type error", "parse PostgreSQL state failed", pgWireOptions{data: []byte(`{"version":4,"outputs":{"` + pgTestSecret + `":{"sensitive":"bad"}}}`)}},
		{"not base64", "parse PostgreSQL state failed", pgWireOptions{data: []byte(base64.StdEncoding.EncodeToString([]byte(pgTestData)))}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dsn, done := startPGWire(t, tt.opts)
			t.Setenv("CLOUDWEAVE_PG_TEST_DSN", dsn)
			st, err := LoadPGState(context.Background(), "prod=CLOUDWEAVE_PG_TEST_DSN", DefaultPGSchema, DefaultPGWorkspace)
			assertPGError(t, st, err, tt.want)
			result := awaitPGWire(t, done)
			switch tt.opts.fail {
			case "connect":
				if len(result.statements) != 0 {
					t.Fatal("SQL sent after failed connection")
				}
			case "begin":
				// pgx closes a connection whose BEGIN fails; there is no Tx to roll back.
				if !reflect.DeepEqual(result.statements, []string{"begin read only"}) {
					t.Fatalf("unexpected statements: %v", result.statements)
				}
			default:
				assertPGStatements(t, result, DefaultPGSchema)
				if result.workspace != DefaultPGWorkspace {
					t.Errorf("workspace = %q", result.workspace)
				}
			}
		})
	}
}

func TestLoadPGStateCanceledContext(t *testing.T) {
	cleanPGTestEnv(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("CLOUDWEAVE_PG_TEST_DSN", "postgres://test:"+pgTestSecret+"@"+listener.Addr().String()+"/test?sslmode=disable")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st, err := LoadPGState(ctx, "prod=CLOUDWEAVE_PG_TEST_DSN", DefaultPGSchema, DefaultPGWorkspace)
	assertPGError(t, st, err, "connect to PostgreSQL state failed")
}

func TestLoadPGStateConnectDeadline(t *testing.T) {
	cleanPGTestEnv(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.Copy(io.Discard, conn) // Never answer the startup handshake.
	}()
	t.Setenv("CLOUDWEAVE_PG_TEST_DSN", "postgres://test:"+pgTestSecret+"@"+listener.Addr().String()+"/test?sslmode=disable&connect_timeout=120")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	st, err := LoadPGState(ctx, "prod=CLOUDWEAVE_PG_TEST_DSN", DefaultPGSchema, DefaultPGWorkspace)
	assertPGError(t, st, err, "connect to PostgreSQL state failed")
	if time.Since(start) > 2*time.Second {
		t.Error("connection ignored the shorter caller deadline")
	}
	listener.Close()
	<-done
	if pgReadTimeout != 15*time.Second {
		t.Error("PostgreSQL reads must have a 15-second deadline")
	}
}

type pgWireOptions struct {
	data   []byte
	noRows bool
	fail   string
}

type pgWireResult struct {
	statements []string
	workspace  string
	err        error
}

func startPGWire(t *testing.T, opts pgWireOptions) (string, <-chan pgWireResult) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan pgWireResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- pgWireResult{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		done <- servePGWire(conn, opts)
	}()
	return "postgres://test:" + pgTestSecret + "@" + listener.Addr().String() + "/test?sslmode=disable", done
}

func awaitPGWire(t *testing.T, done <-chan pgWireResult) pgWireResult {
	t.Helper()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("fake PostgreSQL server: %v", result.err)
		}
		return result
	case <-time.After(6 * time.Second):
		t.Fatal("fake PostgreSQL server did not finish")
		return pgWireResult{}
	}
}

func assertPGStatements(t *testing.T, result pgWireResult, schema string) {
	t.Helper()
	want := []string{"begin read only", pgStateQuery(schema), "rollback"}
	if !reflect.DeepEqual(result.statements, want) {
		t.Fatalf("SQL = %q; want only BEGIN READ ONLY, parameterized SELECT, ROLLBACK", result.statements)
	}
}

func servePGWire(conn net.Conn, opts pgWireOptions) (result pgWireResult) {
	backend := pgproto3.NewBackend(conn, conn)
	if _, result.err = backend.ReceiveStartupMessage(); result.err != nil {
		return result
	}
	serverError := func() {
		backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "XX000", Message: pgTestSecret, Detail: pgTestSecret, Hint: pgTestSecret})
	}
	if opts.fail == "connect" {
		serverError()
		result.err = backend.Flush()
		return result
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0"})
	backend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	backend.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	backend.Send(&pgproto3.NoticeResponse{Severity: "NOTICE", Code: "00000", Message: pgTestSecret})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if result.err = backend.Flush(); result.err != nil {
		return result
	}
	status := byte('I')
	for {
		msg, err := backend.Receive()
		if errors.Is(err, io.EOF) {
			return result
		}
		if err != nil {
			result.err = err
			return result
		}
		switch msg := msg.(type) {
		case *pgproto3.Query:
			result.statements = append(result.statements, msg.String)
			switch msg.String {
			case "begin read only":
				status = 'T'
				if opts.fail == "begin" {
					serverError()
					status = 'I'
				} else {
					backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
				}
			case "rollback":
				status = 'I'
				if opts.fail == "rollback" {
					serverError()
				} else {
					backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("ROLLBACK")})
				}
			default:
				result.err = fmt.Errorf("unexpected simple query: %q", msg.String)
				return result
			}
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: status})
		case *pgproto3.Parse:
			result.statements = append(result.statements, msg.Query)
			if status != 'T' || msg.Name != "" {
				result.err = errors.New("SELECT was not in a transaction or used a named prepared statement")
				return result
			}
			backend.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Bind:
			if len(msg.Parameters) != 1 {
				result.err = errors.New("expected one workspace parameter")
				return result
			}
			result.workspace = string(msg.Parameters[0])
			backend.Send(&pgproto3.BindComplete{})
		case *pgproto3.Describe:
			backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("data"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}}})
		case *pgproto3.Execute:
			if opts.fail == "query" {
				serverError()
				status = 'E'
			} else if opts.noRows {
				backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 0")})
			} else {
				backend.Send(&pgproto3.DataRow{Values: [][]byte{opts.data}})
				backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			}
		case *pgproto3.Sync:
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: status})
		case *pgproto3.Terminate:
			return result
		default:
			result.err = fmt.Errorf("unexpected protocol message: %T", msg)
			return result
		}
		if result.err = backend.Flush(); result.err != nil {
			return result
		}
	}
}
