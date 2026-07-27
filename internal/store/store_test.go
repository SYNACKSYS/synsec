package store

import (
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "synsec.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenCreatesSchema(t *testing.T) {
	db := openTemp(t)

	want := []string{
		"meta", "key_slots", "users", "sessions", "projects",
		"environments", "secrets", "secret_versions", "service_tokens",
		"audit_log", "schema_migrations",
	}
	for _, table := range want {
		var name string
		err := db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing after Open: %v", table, err)
		}
	}
}

// The whole migration file must land, not just its first statement: some
// drivers stop at the first semicolon in a multi-statement Exec.
func TestMigrationAppliesEveryStatement(t *testing.T) {
	db := openTemp(t)

	var indexes int
	if err := db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'`,
	).Scan(&indexes); err != nil {
		t.Fatalf("counting indexes: %v", err)
	}
	if indexes == 0 {
		t.Fatal("no indexes created: the migration stopped before the end of the file")
	}
}

func TestMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synsec.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	var afterFirst int
	if err := first.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&afterFirst); err != nil {
		t.Fatalf("counting migrations: %v", err)
	}
	first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopening an already migrated database: %v", err)
	}
	defer second.Close()

	var afterSecond int
	if err := second.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&afterSecond); err != nil {
		t.Fatalf("counting migrations: %v", err)
	}

	// The property is that reopening applies nothing further, not that any
	// particular number of migrations exists - that number grows with the
	// schema.
	if afterSecond != afterFirst {
		t.Fatalf("reopening applied %d further migrations", afterSecond-afterFirst)
	}

	available, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if afterFirst != len(available) {
		t.Fatalf("%d migrations recorded, %d on disk", afterFirst, len(available))
	}
}

func TestWALIsEnabled(t *testing.T) {
	db := openTemp(t)

	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("reading journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode is %q, want wal", mode)
	}
}

// Foreign keys are off by default in SQLite and must be enabled per
// connection. Without them, deleting a vault would silently orphan its
// secrets instead of removing them.
func TestForeignKeysAreEnforced(t *testing.T) {
	db := openTemp(t)

	_, err := db.Exec(
		`INSERT INTO secrets (id, project_id, env, name, current_version, created_at, updated_at)
		 VALUES ('s1', 'no-such-project', 'prod', 'x', 1, 0, 0)`,
	)
	if err == nil {
		t.Fatal("inserted a secret referencing a project that does not exist")
	}
	if !IsConstraintViolation(err) {
		t.Fatalf("IsConstraintViolation did not recognise %v", err)
	}
}

func TestDeletingProjectCascades(t *testing.T) {
	db := openTemp(t)

	if _, err := db.Exec(
		`INSERT INTO projects (id, name, wrapped_dek, created_at) VALUES ('p1', 'Maison', x'00', 0)`,
	); err != nil {
		t.Fatalf("inserting project: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO secrets (id, project_id, env, name, current_version, created_at, updated_at)
		 VALUES ('s1', 'p1', 'prod', 'mqtt', 1, 0, 0)`,
	); err != nil {
		t.Fatalf("inserting secret: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM projects WHERE id = 'p1'`); err != nil {
		t.Fatalf("deleting project: %v", err)
	}

	var remaining int
	if err := db.QueryRow(`SELECT count(*) FROM secrets`).Scan(&remaining); err != nil {
		t.Fatalf("counting secrets: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("%d secrets survived the deletion of their vault", remaining)
	}
}

func TestUsernameIsCaseInsensitive(t *testing.T) {
	db := openTemp(t)

	insert := `INSERT INTO users (id, username, password_hash, password_salt, password_params, created_at)
	           VALUES (?, ?, x'00', x'00', '{}', 0)`
	if _, err := db.Exec(insert, "u1", "Cyril"); err != nil {
		t.Fatalf("inserting first user: %v", err)
	}
	if _, err := db.Exec(insert, "u2", "cyril"); err == nil {
		t.Fatal("two users differing only in case were both accepted")
	}
}

func TestOpenMemory(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	defer db.Close()

	var name string
	if err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'projects'`,
	).Scan(&name); err != nil {
		t.Fatalf("schema missing in memory database: %v", err)
	}
}
