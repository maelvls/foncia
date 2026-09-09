package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"time"

	"github.com/maelvls/foncia/logutil"
)

// The database is NOT a disposable cache. Foncia's API silently drops older
// missions, work orders and expenses; once that happens this database is the
// only remaining record of them. So the schema is migrated in place, preserving
// every row, and never recreated from scratch.
//
// The version counter is SQLite's own `PRAGMA user_version`, a 32-bit integer
// stored in the database header. It costs no table, it is transactional (so a
// migration and the version bump commit or roll back together), and it is 0 on
// every database that predates this file, which is exactly what migration 1
// expects.

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migration is one step from user_version N-1 to N. It carries EITHER raw SQL
// (the common case, read from migrations/NNNN_name.sql) OR a Go function, for
// the steps SQL cannot express: normalising timestamps through time.Parse, and
// deriving the expense primary key with the very same expenseID that the sync
// uses.
type migration struct {
	version int    // Strictly increasing, starting at 1.
	name    string // Short, for logs and errors.

	sql string                                      // Set for a pure-SQL migration.
	fn  func(ctx context.Context, tx *sql.Tx) error // Set for a Go migration.
}

// migrations must be ordered by version and must never be edited once released:
// a database that already applied version N will never run it again.
var migrations = []migration{
	{
		version: 1,
		name:    "baseline",
		sql:     migrationSQL("0001_baseline.sql"),
	},
	{
		version: 2,
		name:    "strict_schema",
		// Go, not SQL, because the timestamp normalisation and the expense
		// primary key both need Go. The bulk of the work still lives in
		// migrations/0002_strict_schema.sql, which this function executes.
		fn: migrateToStrictSchema,
	},
}

// migrationSQL reads an embedded migration. It panics rather than returning an
// error: a missing file is a build mistake, not a runtime condition.
func migrationSQL(name string) string {
	b, err := migrationsFS.ReadFile("migrations/" + name)
	if err != nil {
		panic(fmt.Sprintf("migration %s is missing from the embedded FS: %v", name, err))
	}
	return string(b)
}

// Migrate brings the database up to the latest schema version. It is
// idempotent: the second call is a no-op.
//
// Every migration runs in its own transaction, and `PRAGMA user_version` is
// bumped inside that same transaction, so an interrupted migration leaves the
// database at the previous version rather than half-way through.
//
// The whole thing runs on a single dedicated *sql.Conn because `PRAGMA
// foreign_keys` is a no-op inside a transaction and must therefore be turned
// off on the connection *before* the transaction begins. Foreign keys have to
// be off: rebuilding a table means dropping the old one while other tables
// still point at it. `PRAGMA foreign_key_check` runs before each commit to
// catch anything that got broken while the checks were off.
func Migrate(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("while getting a dedicated connection for the migrations: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF;"); err != nil {
		return fmt.Errorf("while disabling foreign keys for the migrations: %w", err)
	}
	// The connection goes back to the pool when this function returns, so it
	// must go back with foreign keys enforced, like every other connection.
	defer func() {
		if _, err := conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA foreign_keys = ON;"); err != nil {
			logutil.Errorf("db: could not re-enable foreign keys after the migrations: %v", err)
		}
	}()

	var current int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version;").Scan(&current); err != nil {
		return fmt.Errorf("while reading the schema version: %w", err)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, conn, m); err != nil {
			return fmt.Errorf("while applying migration %d (%s): %w", m.version, m.name, err)
		}
		logutil.Debugf("db: applied migration %d (%s)", m.version, m.name)
	}

	return nil
}

// applyMigration runs one migration and bumps user_version, atomically.
func applyMigration(ctx context.Context, conn *sql.Conn, m migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting the transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The production database already contains 25 orphan contract_documents
	// (their supplier is a legitimate Foncia id that the API stopped
	// returning). Those pre-existing violations must not fail the migration, so
	// what is checked is that the migration does not add any.
	before, err := foreignKeyViolations(ctx, tx)
	if err != nil {
		return err
	}

	switch {
	case m.fn != nil:
		if err := m.fn(ctx, tx); err != nil {
			return err
		}
	case m.sql != "":
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("while running the SQL: %w", err)
		}
	default:
		return fmt.Errorf("migration has neither SQL nor a Go function")
	}

	after, err := foreignKeyViolations(ctx, tx)
	if err != nil {
		return err
	}
	if err := noNewForeignKeyViolations(before, after); err != nil {
		return err
	}

	// PRAGMA does not take bound parameters. m.version is an int we own, so
	// there is nothing to inject.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d;", m.version)); err != nil {
		return fmt.Errorf("while bumping the schema version: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("while committing: %w", err)
	}
	return nil
}

// foreignKeyViolations counts the rows that violate a foreign key, keyed by
// "child table -> parent table". Rowids are deliberately not part of the key: a
// table rebuild renumbers them, so comparing them would flag every migration.
//
// Foreign keys are not enforced while the migrations run, so this is the only
// thing standing between a bad rebuild and silently corrupted data.
func foreignKeyViolations(ctx context.Context, tx *sql.Tx) (map[string]int, error) {
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check;")
	if err != nil {
		return nil, fmt.Errorf("while checking the foreign keys: %w", err)
	}
	defer rows.Close()

	violations := make(map[string]int)
	for rows.Next() {
		// (table, rowid, referenced table, index of the failing FK constraint).
		var table, parent string
		var rowid sql.NullInt64
		var fkid int
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			return nil, fmt.Errorf("while scanning a foreign key violation: %w", err)
		}
		violations[table+" -> "+parent]++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("while iterating over the foreign key violations: %w", err)
	}
	return violations, nil
}

// noNewForeignKeyViolations fails if the migration created a foreign key
// violation, or made an existing one worse. Orphans that were already there are
// tolerated: they are old records that Foncia's API no longer returns, and
// deleting them to satisfy a constraint would lose the only copy.
func noNewForeignKeyViolations(before, after map[string]int) error {
	var worse []string
	for key, n := range after {
		if n > before[key] {
			worse = append(worse, fmt.Sprintf("%s: %d -> %d", key, before[key], n))
		}
	}
	if len(worse) > 0 {
		sort.Strings(worse)
		return fmt.Errorf("the migration would add foreign key violations, refusing to commit: %v", worse)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Migration 2: the Go half.
// -----------------------------------------------------------------------------

// migrateToStrictSchema normalises the data, derives the expense primary keys,
// and then hands over to migrations/0002_strict_schema.sql, which does the
// actual table rebuilds. The order matters: the SQL copies the columns verbatim
// (modulo COALESCE), so everything it copies must already be in its final form.
func migrateToStrictSchema(ctx context.Context, tx *sql.Tx) error {
	if err := normaliseTimestamps(ctx, tx); err != nil {
		return err
	}
	if err := backfillExpenseIDs(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, migrationSQL("0002_strict_schema.sql")); err != nil {
		return fmt.Errorf("while rebuilding the tables: %w", err)
	}
	return nil
}

// timestampColumns lists every column that db.go reads back through parseTime,
// which only accepts time.RFC3339Nano.
var timestampColumns = []struct{ table, column string }{
	{"missions", "started_at"},
	{"work_orders", "repair_date_start"},
	{"work_orders", "repair_date_end"},
	{"account_documents", "created_at"},
	{"expenses", "date"},
}

// normaliseTimestamps rewrites every stored timestamp as UTC time.RFC3339Nano.
//
// The one value known to need it is the default that account_documents.created_at
// was given when the column was added: "0001-01-01 00:00:00 +0000 UTC". That is
// Go's time.Time{} printed with String(), which parseTime rejects; it becomes
// "0001-01-01T00:00:00Z".
//
// Values that already round-trip are left byte-identical, so this is a no-op on
// the vast majority of rows.
func normaliseTimestamps(ctx context.Context, tx *sql.Tx) error {
	for _, c := range timestampColumns {
		type fix struct {
			rowid int64
			value string
		}
		var fixes []fix

		rows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT rowid, %s FROM %s;", c.column, c.table))
		if err != nil {
			return fmt.Errorf("while reading %s.%s: %w", c.table, c.column, err)
		}
		for rows.Next() {
			var rowid int64
			var raw sql.NullString
			if err := rows.Scan(&rowid, &raw); err != nil {
				rows.Close()
				return fmt.Errorf("while scanning %s.%s: %w", c.table, c.column, err)
			}
			normalised := normaliseTimestamp(c.table, c.column, raw.String)
			if raw.Valid && normalised == raw.String {
				continue
			}
			fixes = append(fixes, fix{rowid: rowid, value: normalised})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("while iterating over %s.%s: %w", c.table, c.column, err)
		}
		rows.Close()

		for _, f := range fixes {
			_, err := tx.ExecContext(ctx,
				fmt.Sprintf("UPDATE %s SET %s = ? WHERE rowid = ?;", c.table, c.column), f.value, f.rowid)
			if err != nil {
				return fmt.Errorf("while normalising %s.%s of rowid %d: %w", c.table, c.column, f.rowid, err)
			}
		}
		if len(fixes) > 0 {
			logutil.Debugf("db: migration 2 normalised %d timestamp(s) in %s.%s", len(fixes), c.table, c.column)
		}
	}
	return nil
}

// timestampLayouts are tried in order. RFC3339Nano first because that is what
// formatTime writes; then Go's time.Time.String() layout, which is where
// "0001-01-01 00:00:00 +0000 UTC" comes from; then a couple of shapes that a
// hand-edited database might contain.
var timestampLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05.999999999 -0700",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// normaliseTimestamp never fails: a timestamp nobody can parse becomes the zero
// time rather than aborting a migration that is preserving years of data. It is
// logged so that it can be looked at afterwards.
func normaliseTimestamp(table, column, raw string) string {
	if raw == "" {
		return formatTime(time.Time{})
	}
	for _, layout := range timestampLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return formatTime(t)
		}
	}
	logutil.Errorf("db: migration 2 could not parse %s.%s = %q, storing the zero time instead",
		table, column, raw)
	return formatTime(time.Time{})
}

// backfillExpenseIDs adds the `id` column to the old expenses table and fills it
// with expenseID, the very function the sync uses. Getting this wrong would not
// break anything visibly; it would just make the next sync insert a duplicate of
// every single expense.
//
// It cannot be done in SQL: expenseID hashes formatTime(date), and formatTime
// re-renders the date in UTC RFC3339Nano, which SQLite's string functions cannot
// reproduce.
func backfillExpenseIDs(ctx context.Context, tx *sql.Tx) error {
	hasID, err := hasColumn(ctx, tx, "expenses", "id")
	if err != nil {
		return err
	}
	if !hasID {
		// NOT NULL with a default is allowed by ADD COLUMN; the empty string is
		// a placeholder that the loop below overwrites on every row.
		if _, err := tx.ExecContext(ctx, `ALTER TABLE expenses ADD COLUMN id TEXT NOT NULL DEFAULT '';`); err != nil {
			return fmt.Errorf("while adding expenses.id: %w", err)
		}
	}

	type row struct {
		rowid int64
		id    string
	}
	var ids []row
	seen := make(map[string]int64)

	rows, err := tx.QueryContext(ctx, "SELECT rowid, "+expenseColumns+" FROM expenses;")
	if err != nil {
		return fmt.Errorf("while reading the expenses: %w", err)
	}
	for rows.Next() {
		var rowid int64
		var e ExpenseDocumentDB
		var date string
		err := rows.Scan(&rowid, &e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath,
			&e.HashFile, &e.Source, &e.AccountingKey.Allocation, &e.AccountingKey.ExpenseType)
		if err != nil {
			rows.Close()
			return fmt.Errorf("while scanning an expense: %w", err)
		}
		// normaliseTimestamps ran first, so this always parses.
		e.Date, err = parseTime("date", date)
		if err != nil {
			rows.Close()
			return fmt.Errorf("while parsing the date of expense rowid %d: %w", rowid, err)
		}

		id := expenseID(e)
		if other, dup := seen[id]; dup {
			// Keeping the first one matches what the sync does: the second
			// upsert of an identical expense updates the row instead of adding
			// one. INSERT OR IGNORE in the SQL half drops the loser.
			logutil.Errorf("db: migration 2: expenses rowid %d derives the same id as rowid %d (%q, %s); keeping the first",
				rowid, other, e.Label, formatTime(e.Date))
			continue
		}
		seen[id] = rowid
		ids = append(ids, row{rowid: rowid, id: id})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("while iterating over the expenses: %w", err)
	}
	rows.Close()

	for _, r := range ids {
		if _, err := tx.ExecContext(ctx, "UPDATE expenses SET id = ? WHERE rowid = ?;", r.id, r.rowid); err != nil {
			return fmt.Errorf("while setting the id of expense rowid %d: %w", r.rowid, err)
		}
	}
	logutil.Debugf("db: migration 2 derived %d expense id(s)", len(ids))

	return nil
}

// hasColumn tells whether the table already has the column. It exists so that
// migration 2 also works on a database that a development build already created
// with the new shape but with user_version still at 0.
func hasColumn(ctx context.Context, tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s);", table))
	if err != nil {
		return false, fmt.Errorf("while listing the columns of %s: %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return false, fmt.Errorf("while scanning the columns of %s: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("while iterating over the columns of %s: %w", table, err)
	}
	return false, nil
}
