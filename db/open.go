package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/glebarez/go-sqlite"
)

// Open opens (and creates if needed) the SQLite database at the given path and
// migrates it to the latest schema version.
//
// The schema is not applied from a single schema.sql file any more: the
// database is the only surviving record of the missions and expenses that
// Foncia's API has since dropped, so it is migrated in place, never recreated.
// db/migrations/ is the source of truth for the schema; see migrate.go.
//
// The path may be:
//
//	/var/lib/foncia/foncia.db          a file on disk
//	:memory:                           a private in-memory database
//	file::memory:?cache=shared         a shared in-memory database
//	file:/var/lib/foncia/foncia.db     an explicit file: URI
//
// The following pragmas are always set:
//
//	busy_timeout(5000)  the HTTP handlers and the sync goroutine write
//	                    concurrently; without this, SQLite returns
//	                    "database is locked" immediately.
//	journal_mode(WAL)   readers don't block the writer.
//	foreign_keys(1)     foreign keys are declared in the migrations but SQLite
//	                    ignores them unless this is turned on. Migrate turns
//	                    them off on its own connection while it rebuilds tables.
//
// The returned *sql.DB must be closed by the caller.
func Open(path string) (*sql.DB, error) {
	dsn, memory := dsn(path)

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("while opening the database %q: %w", path, err)
	}

	// A private in-memory database only lives as long as the connection that
	// created it, so the pool must never hold more than one connection.
	if memory {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	}

	if err := sqlDB.PingContext(context.Background()); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("while connecting to the database %q: %w", path, err)
	}

	if err := Migrate(context.Background(), sqlDB); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("database %q: %w", path, err)
	}

	return sqlDB, nil
}

// pragmas are appended to the DSN. The github.com/glebarez/go-sqlite driver
// turns each `_pragma=foo(bar)` into a `PRAGMA foo=bar` run on every new
// connection.
var pragmas = []string{
	"_pragma=busy_timeout(5000)",
	"_pragma=journal_mode(WAL)",
	"_pragma=foreign_keys(1)",
}

// dsn turns a user-supplied path into a file: URI carrying the pragmas. It also
// reports whether the database is in-memory and unshared, in which case the
// connection pool must be limited to a single connection.
func dsn(path string) (_ string, memoryUnshared bool) {
	uri := path
	if !strings.HasPrefix(uri, "file:") {
		// ":memory:" is not a file name; as a URI it is spelled "file::memory:".
		uri = "file:" + uri
	}

	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	uri += sep + strings.Join(pragmas, "&")

	inMemory := strings.Contains(uri, ":memory:") || strings.Contains(uri, "mode=memory")
	return uri, inMemory && !strings.Contains(uri, "cache=shared")
}
