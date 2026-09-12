package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prodDBPath is a copy of the real production database. It is not committed
// (it holds the co-ownership's data), so the tests that use it skip when it is
// absent, which is the case in CI.
const prodDBPath = "/Users/mvalais/.claude/jobs/c0e12b5a/tmp/prod.sqlite"

func userVersion(t *testing.T, sqlDB *sql.DB) int {
	t.Helper()
	var v int
	require.NoError(t, sqlDB.QueryRow("PRAGMA user_version;").Scan(&v))
	return v
}

func latestVersion() int {
	return migrations[len(migrations)-1].version
}

// tableSQL returns the CREATE TABLE statement SQLite stored for the table.
func tableSQL(t *testing.T, sqlDB *sql.DB, table string) string {
	t.Helper()
	var stmt string
	require.NoError(t, sqlDB.QueryRow(
		"SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?;", table).Scan(&stmt))
	return stmt
}

func indexNames(t *testing.T, sqlDB *sql.DB) []string {
	t.Helper()
	rows, err := sqlDB.Query("SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%';")
	require.NoError(t, err)
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		names = append(names, name)
	}
	require.NoError(t, rows.Err())
	sort.Strings(names)
	return names
}

func count(t *testing.T, sqlDB *sql.DB, table string) int {
	t.Helper()
	var n int
	require.NoError(t, sqlDB.QueryRow("SELECT COUNT(*) FROM "+table+";").Scan(&n))
	return n
}

func TestMigrate(t *testing.T) {
	t.Run("a fresh database ends up at the latest version with the final schema", func(t *testing.T) {
		sqlDB := openTest(t)

		assert.Equal(t, latestVersion(), userVersion(t, sqlDB))

		// Every table is STRICT and has a real primary key.
		for _, table := range []string{"missions", "suppliers", "work_orders", "contract_documents", "account_documents", "expenses"} {
			stmt := tableSQL(t, sqlDB, table)
			assert.Contains(t, stmt, "STRICT", "%s must be STRICT", table)
			assert.Regexp(t, `\bid\s+TEXT PRIMARY KEY NOT NULL`, stmt, "%s must have a TEXT primary key", table)
		}

		// contract_documents.supplier_id must NOT have a foreign key: all 25
		// rows in production are orphans of suppliers the API stopped
		// returning, and they must keep showing.
		assert.NotContains(t, tableSQL(t, sqlDB, "contract_documents"), "FOREIGN KEY")
		assert.Contains(t, tableSQL(t, sqlDB, "work_orders"), "FOREIGN KEY (mission_id) REFERENCES missions (id)")

		assert.Equal(t, []string{
			"idx_account_documents_category",
			"idx_account_documents_hash_file",
			"idx_contract_documents_hash_file",
			"idx_contract_documents_supplier_id",
			"idx_expenses_hash_file",
			"idx_expenses_invoice_id",
			"idx_missions_started_at",
			"idx_work_orders_mission_id",
			"idx_work_orders_supplier_id",
		}, indexNames(t, sqlDB), "idx_entries_started_at must have been renamed")
	})

	t.Run("migrating twice is a no-op", func(t *testing.T) {
		sqlDB := openTest(t)
		before := userVersion(t, sqlDB)
		schemaBefore := tableSQL(t, sqlDB, "expenses")

		require.NoError(t, Migrate(t.Context(), sqlDB))
		require.NoError(t, Migrate(t.Context(), sqlDB))

		assert.Equal(t, before, userVersion(t, sqlDB))
		assert.Equal(t, schemaBefore, tableSQL(t, sqlDB, "expenses"))
	})

	t.Run("foreign keys are enforced again once the migrations are done", func(t *testing.T) {
		sqlDB := openTest(t)

		// Every connection in the pool must have foreign_keys on, including the
		// one Migrate borrowed.
		for range 3 {
			var on int
			require.NoError(t, sqlDB.QueryRow("PRAGMA foreign_keys;").Scan(&on))
			assert.Equal(t, 1, on)
		}

		_, err := sqlDB.Exec(`INSERT INTO work_orders (id, mission_id, number, label, repair_date_start,
			repair_date_end, supplier_id, supplier_name, supplier_activity)
			VALUES ('wo', 'nope', '', '', '', '', '', '', '');`)
		assert.Error(t, err, "work_orders.mission_id must still be a foreign key")
	})

	t.Run("STRICT rejects a string in expenses.amount", func(t *testing.T) {
		sqlDB := openTest(t)
		_, err := sqlDB.Exec(`INSERT INTO expenses (id, invoice_id, label, amount, date, file_path,
			hash_file, source, accounting_allocation, accounting_expense_type)
			VALUES ('e', '', '', 'not a number', '', '', '', '', '', '');`)
		assert.Error(t, err)
	})
}

func TestNormaliseTimestamp(t *testing.T) {
	t.Run("the account_documents.created_at default becomes RFC3339Nano", func(t *testing.T) {
		// "0001-01-01 00:00:00 +0000 UTC" is Go's time.Time{} printed with
		// String(); parseTime would reject it.
		got := normaliseTimestamp("account_documents", "created_at", "0001-01-01 00:00:00 +0000 UTC")
		assert.Equal(t, "0001-01-01T00:00:00Z", got)

		_, err := parseTime("created_at", got)
		assert.NoError(t, err)
	})

	t.Run("already valid values are left byte-identical", func(t *testing.T) {
		for _, s := range []string{
			"2024-07-01T21:59:59Z",
			"2023-09-11T13:42:41.68Z",
			"2024-09-02T10:36:26.938Z",
			"0001-01-01T00:00:00Z",
		} {
			assert.Equal(t, s, normaliseTimestamp("expenses", "date", s))
		}
	})

	t.Run("an offset is converted to UTC so that the text sorts chronologically", func(t *testing.T) {
		assert.Equal(t, "2024-01-01T07:00:00Z", normaliseTimestamp("missions", "started_at", "2024-01-01T09:00:00+02:00"))
	})

	t.Run("garbage becomes the zero time rather than failing the migration", func(t *testing.T) {
		assert.Equal(t, "0001-01-01T00:00:00Z", normaliseTimestamp("expenses", "date", "not a date"))
		assert.Equal(t, "0001-01-01T00:00:00Z", normaliseTimestamp("expenses", "date", ""))
	})
}

// openProdCopy copies the production database to a temp file and opens it,
// which runs the migrations. The copy is mandatory: the original must stay
// untouched.
func openProdCopy(t *testing.T) *sql.DB {
	t.Helper()
	if _, err := os.Stat(prodDBPath); err != nil {
		t.Skipf("no copy of the production database at %s, skipping", prodDBPath)
	}

	raw, err := os.ReadFile(prodDBPath)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "prod.sqlite")
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	sqlDB, err := Open(path)
	require.NoError(t, err, "migrating the production database must succeed")
	t.Cleanup(func() { _ = sqlDB.Close() })
	return sqlDB
}

// prodRowCounts is what the production database holds today. The migration must
// not lose a single row: Foncia's API drops older items, so for many of these
// rows this database is the only record left.
var prodRowCounts = map[string]int{
	"missions":           463,
	"suppliers":          16,
	"work_orders":        369,
	"contract_documents": 25,
	"account_documents":  237,
	"expenses":           2021,
}

func TestMigrateProductionDatabase(t *testing.T) {
	ctx := context.Background()
	sqlDB := openProdCopy(t)

	t.Run("every row is preserved", func(t *testing.T) {
		for table, want := range prodRowCounts {
			assert.Equal(t, want, count(t, sqlDB, table), "row count of %s changed", table)
		}
	})

	t.Run("the schema version is the latest", func(t *testing.T) {
		assert.Equal(t, latestVersion(), userVersion(t, sqlDB))
	})

	t.Run("no foreign key is violated", func(t *testing.T) {
		rows, err := sqlDB.QueryContext(ctx, "PRAGMA foreign_key_check;")
		require.NoError(t, err)
		defer rows.Close()
		assert.False(t, rows.Next(), "PRAGMA foreign_key_check must be empty")
		require.NoError(t, rows.Err())
	})

	t.Run("every expense has a non-empty, unique id", func(t *testing.T) {
		var empty int
		require.NoError(t, sqlDB.QueryRow("SELECT COUNT(*) FROM expenses WHERE id = '';").Scan(&empty))
		assert.Zero(t, empty)

		var distinct int
		require.NoError(t, sqlDB.QueryRow("SELECT COUNT(DISTINCT id) FROM expenses;").Scan(&distinct))
		assert.Equal(t, prodRowCounts["expenses"], distinct)
	})

	t.Run("every stored timestamp parses as RFC3339Nano", func(t *testing.T) {
		for _, c := range timestampColumns {
			rows, err := sqlDB.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM %s;", c.column, c.table))
			require.NoError(t, err)
			for rows.Next() {
				var s string
				require.NoError(t, rows.Scan(&s))
				_, err := parseTime(c.column, s)
				require.NoError(t, err, "%s.%s = %q", c.table, c.column, s)
			}
			require.NoError(t, rows.Err())
			rows.Close()
		}
	})

	t.Run("the queries the handlers use all work", func(t *testing.T) {
		expenses, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		assert.Len(t, expenses, prodRowCounts["expenses"])

		missions, err := GetMissionsDB(ctx, sqlDB)
		require.NoError(t, err)
		assert.Len(t, missions, prodRowCounts["missions"])

		accountDocs, err := GetAccountDocumentsDB(ctx, sqlDB)
		require.NoError(t, err)
		assert.Len(t, accountDocs, prodRowCounts["account_documents"])

		contractDocs, err := GetSupplierContractDocsDB(ctx, sqlDB)
		require.NoError(t, err)
		assert.Len(t, contractDocs, prodRowCounts["contract_documents"],
			"the 25 orphan contract documents must survive")

		suppliers, err := GetSuppliersDB(ctx, sqlDB)
		require.NoError(t, err)
		assert.Len(t, suppliers, prodRowCounts["suppliers"])
	})

	t.Run("work orders are still attached to their missions", func(t *testing.T) {
		missions, err := GetMissionsDB(ctx, sqlDB)
		require.NoError(t, err)
		var workOrders int
		for _, m := range missions {
			workOrders += len(m.WorkOrders)
		}
		assert.Equal(t, prodRowCounts["work_orders"], workOrders)
	})

	// This is the test that matters most. The backfilled expenses.id has to be
	// byte-for-byte what LegacyExpenseID computes, or the next sync inserts a second
	// copy of all 2021 expenses instead of updating them.
	t.Run("re-upserting the migrated expenses does not duplicate them", func(t *testing.T) {
		before, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, before, prodRowCounts["expenses"])

		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, before...))

		after, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		assert.Len(t, after, prodRowCounts["expenses"],
			"the ids derived by the migration must match LegacyExpenseID")
	})
}

func TestMigratedExpenseIDMatchesExpenseID(t *testing.T) {
	ctx := context.Background()

	// Build a database in the *old* shape, insert an expense the way the old
	// code did (no id column at all), migrate, then upsert the same expense
	// again. If the backfilled id disagreed with LegacyExpenseID, we would end up
	// with two rows.
	path := filepath.Join(t.TempDir(), "old.sqlite")
	raw, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)

	_, err = raw.ExecContext(ctx, migrationSQL("0001_baseline.sql"))
	require.NoError(t, err)

	// Note the plain RFC3339 date with a non-UTC offset: formatTime would
	// render it differently, which is exactly why the id cannot be derived in
	// SQL.
	_, err = raw.ExecContext(ctx, `INSERT INTO expenses (invoice_id, label, amount, date, file_path,
		hash_file, source, accounting_allocation, accounting_expense_type)
		VALUES ('', 'ELECO', 79200, '2024-06-30T02:00:00+02:00', '', '66dafe199f013b45ee991c96',
		        'accounting', 'CHARGES UNITAIRES C', 'CONTRAT EXTRACTEURS');`)
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	sqlDB, err := Open(path)
	require.NoError(t, err)
	defer sqlDB.Close()

	got, err := GetExpensesDB(ctx, sqlDB)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.True(t, got[0].Date.Equal(time.Date(2024, 6, 30, 0, 0, 0, 0, time.UTC)),
		"the date must have been normalised to UTC")

	var id string
	require.NoError(t, sqlDB.QueryRow("SELECT id FROM expenses;").Scan(&id))
	assert.Equal(t, LegacyExpenseID(got[0]), id, "the backfilled id must be what LegacyExpenseID computes")

	// The next sync sees the same expense again.
	require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, got[0]))

	after, err := GetExpensesDB(ctx, sqlDB)
	require.NoError(t, err)
	assert.Len(t, after, 1, "the expense must be updated, not duplicated")
}
