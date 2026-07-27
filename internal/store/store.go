// Package store owns SYNSEC's SQLite database: schema, migrations and
// connection policy.
//
// The driver is modernc.org/sqlite, a pure-Go translation of SQLite. It is
// slower than the cgo binding, by an amount no home network will ever notice,
// and in exchange `GOOS=linux GOARCH=arm64 go build` produces a working
// Raspberry Pi binary from a Windows desktop with no cross-compiler installed.
package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Connection pool sizing. SQLite in WAL mode serves many concurrent readers
// against a single writer; the busy timeout absorbs the brief contention when
// a write lands while a device is polling.
const (
	maxOpenConns    = 4
	maxIdleConns    = 4
	connMaxIdleTime = 5 * time.Minute
	busyTimeoutMS   = 5000
)

// DB is the handle every repository is built on.
type DB struct {
	*sql.DB
	path string
}

// Open prepares the database at path, creating it and its parent directory if
// needed, and brings the schema up to date.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("store: no database path given")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: creating data directory: %w", err)
		}
	}

	handle, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("store: opening database: %w", err)
	}
	handle.SetMaxOpenConns(maxOpenConns)
	handle.SetMaxIdleConns(maxIdleConns)
	handle.SetConnMaxIdleTime(connMaxIdleTime)

	if err := handle.Ping(); err != nil {
		handle.Close()
		return nil, fmt.Errorf("store: connecting to %s: %w", path, err)
	}

	db := &DB{DB: handle, path: path}
	if err := migrate(handle); err != nil {
		handle.Close()
		return nil, err
	}
	return db, nil
}

// OpenMemory returns a private in-memory database, for tests.
func OpenMemory() (*DB, error) {
	handle, err := sql.Open("sqlite", "file::memory:?_pragma=foreign_keys(1)&cache=shared")
	if err != nil {
		return nil, fmt.Errorf("store: opening in-memory database: %w", err)
	}
	// A shared-cache memory database lives only as long as one connection
	// remains open, so the pool must not be allowed to drain it.
	handle.SetMaxOpenConns(1)

	if err := migrate(handle); err != nil {
		handle.Close()
		return nil, err
	}
	return &DB{DB: handle, path: ":memory:"}, nil
}

// Path reports where the database lives, for backups and diagnostics.
func (db *DB) Path() string { return db.path }

// dsn builds the connection string.
//
// busy_timeout and foreign_keys are per-connection settings, so they belong in
// the DSN rather than in a one-off statement after Open: every connection the
// pool creates must carry them, including the ones opened hours later.
func dsn(path string) string {
	pragmas := []string{
		"journal_mode(WAL)",
		fmt.Sprintf("busy_timeout(%d)", busyTimeoutMS),
		"foreign_keys(1)",
		// NORMAL is the documented safe choice under WAL: a crash can cost the
		// last transaction, never the integrity of the database.
		"synchronous(NORMAL)",
	}

	q := make(url.Values, len(pragmas))
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	// SQLite wants forward slashes even on Windows.
	return "file:" + filepath.ToSlash(path) + "?" + q.Encode()
}

// IsConstraintViolation reports whether err comes from a UNIQUE, CHECK or
// foreign key constraint, which callers translate into a friendly message
// rather than a 500.
func IsConstraintViolation(err error) bool {
	if err == nil {
		return false
	}
	// The driver's error type is internal, so the message is what we have.
	return strings.Contains(err.Error(), "constraint failed") ||
		strings.Contains(err.Error(), "UNIQUE constraint") ||
		strings.Contains(err.Error(), "FOREIGN KEY constraint")
}
