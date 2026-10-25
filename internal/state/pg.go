package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

const (
	DefaultPGSchema    = "terraform_remote_state"
	DefaultPGWorkspace = "default"
	pgReadTimeout      = 15 * time.Second
	pgCleanupTimeout   = 5 * time.Second
)

// LoadPGState reads Terraform's pg backend using spec="name=ENV_VAR". Only
// the named environment variable supplies the DSN; neither it nor driver errors
// are exposed to callers. Schema and workspace must be supplied explicitly.
// This avoids Terraform advisory locks, not PostgreSQL's normal read locks.
func LoadPGState(ctx context.Context, spec, schema, workspace string) (st *State, err error) {
	name, env, ok := strings.Cut(spec, "=")
	if !ok || !validPGName(name, false) || !validPGName(env, true) {
		return nil, errors.New("invalid --pg-state: expected name=ENV_VAR (not a connection string)")
	}
	if schema == "" || strings.ContainsRune(schema, 0) || !utf8.ValidString(schema) {
		return nil, errors.New("invalid PostgreSQL state schema")
	}
	if workspace == "" || strings.ContainsRune(workspace, 0) || !utf8.ValidString(workspace) {
		return nil, errors.New("invalid PostgreSQL state workspace")
	}
	dsn, exists := os.LookupEnv(env)
	if !exists || strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL state environment variable is unset or empty")
	}
	config, parseErr := pgx.ParseConfig(dsn)
	if parseErr != nil {
		return nil, errors.New("invalid PostgreSQL state connection configuration")
	}
	// Session-attribute checks can execute extra SQL before BEGIN. Reject them
	// rather than silently changing the requested connection routing semantics.
	if config.ValidateConnect != nil {
		return nil, errors.New("PostgreSQL state connections do not support target_session_attrs checks")
	}
	// Use the extended protocol without statement preparation/caching or SQL
	// interpolation, regardless of query mode options in the DSN.
	config.DefaultQueryExecMode = pgx.QueryExecModeExec

	ctx, cancel := context.WithTimeout(ctx, pgReadTimeout)
	defer cancel()
	conn, connectErr := pgx.ConnectConfig(ctx, config)
	if connectErr != nil {
		return nil, errors.New("connect to PostgreSQL state failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), pgCleanupTimeout)
		defer cancel()
		// Closing also releases any transaction if rollback could not be sent.
		_ = conn.Close(cleanup)
	}()

	tx, beginErr := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if beginErr != nil {
		return nil, errors.New("begin read-only PostgreSQL state transaction failed")
	}
	defer func() {
		// A canceled caller must not prevent the rollback attempt. pgx may have
		// already closed a broken connection, in which case the server aborts it.
		cleanup, cancel := context.WithTimeout(context.Background(), pgCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanup); rollbackErr != nil && err == nil {
			st = nil
			err = errors.New("rollback PostgreSQL state transaction failed")
		}
	}()

	var data string // Terraform pg stores raw state JSON as text, not base64.
	queryErr := tx.QueryRow(ctx, pgStateQuery(schema), workspace).Scan(&data)
	if errors.Is(queryErr, pgx.ErrNoRows) {
		return nil, errors.New("PostgreSQL state workspace not found")
	}
	if queryErr != nil {
		return nil, errors.New("read PostgreSQL state failed")
	}
	// Reject trailing data as well as malformed JSON before the raw decoder.
	if !json.Valid([]byte(data)) {
		return nil, errors.New("parse PostgreSQL state failed")
	}
	st, err = loadRawState("", name, []byte(data))
	if err != nil {
		return nil, errors.New("parse PostgreSQL state failed")
	}
	st.Source = SourcePostgreSQL
	return st, nil
}

func pgStateQuery(schema string) string {
	return "SELECT data FROM " + (pgx.Identifier{schema, "states"}).Sanitize() + " WHERE name=$1"
}

// Names are safe report labels; environment names use portable shell syntax.
// Validate without including any part of the supplied spec in an error.
func validPGName(s string, env bool) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' {
			continue
		}
		if c >= '0' && c <= '9' && (!env || i > 0) {
			continue
		}
		if !env && i > 0 && (c == '.' || c == '-') {
			continue
		}
		return false
	}
	return true
}
