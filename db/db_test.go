package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAmount_String(t *testing.T) {
	t.Run("negative amounts are prefixed with a minus sign", func(t *testing.T) {
		assert.Equal(t, "-1,00 €", Amount(-100).String())
		assert.Equal(t, "-12345,67 €", Amount(-1234567).String(), "no thousand separator")
		assert.Equal(t, "-1234567,90 €", Amount(-123456790).String())
	})

	t.Run("positive amounts use a French decimal comma", func(t *testing.T) {
		assert.Equal(t, "0,00 €", Amount(0).String())
		assert.Equal(t, "0,07 €", Amount(7).String())
		assert.Equal(t, "1,00 €", Amount(100).String())
		assert.Equal(t, "1234567,90 €", Amount(123456790).String())
	})
}

func TestMissionNumber(t *testing.T) {
	assert.Equal(t, "OSMIL805898844", MissionNumber("Ordre de service N° OSMIL805898844 – 2NRT POMPE ENVIRONNEMENT"))
	assert.Equal(t, "", MissionNumber("Ordre de service sans numéro"))
}

// openTest opens a fresh in-memory database with the schema applied.
func openTest(t *testing.T) *sql.DB {
	t.Helper()
	sqlDB, err := Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return sqlDB
}

func TestOpen(t *testing.T) {
	t.Run("in-memory database has the pragmas and the schema", func(t *testing.T) {
		sqlDB := openTest(t)

		var foreignKeys int
		require.NoError(t, sqlDB.QueryRow("PRAGMA foreign_keys;").Scan(&foreignKeys))
		assert.Equal(t, 1, foreignKeys, "foreign keys must be enforced")

		var busyTimeout int
		require.NoError(t, sqlDB.QueryRow("PRAGMA busy_timeout;").Scan(&busyTimeout))
		assert.Equal(t, 5000, busyTimeout)

		empty, err := IsEmptyDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.True(t, empty)
	})

	t.Run("file database is created and uses WAL", func(t *testing.T) {
		sqlDB, err := Open(filepath.Join(t.TempDir(), "foncia.db"))
		require.NoError(t, err)
		defer sqlDB.Close()

		var journalMode string
		require.NoError(t, sqlDB.QueryRow("PRAGMA journal_mode;").Scan(&journalMode))
		assert.Equal(t, "wal", journalMode)
	})

	t.Run("shared in-memory database", func(t *testing.T) {
		sqlDB, err := Open("file::memory:?cache=shared")
		require.NoError(t, err)
		defer sqlDB.Close()

		require.NoError(t, Migrate(t.Context(), sqlDB), "the migrations must be idempotent")
	})
}

func TestSaveMissionsToDB(t *testing.T) {
	ctx := context.Background()

	t.Run("no missions is not a syntax error", func(t *testing.T) {
		sqlDB := openTest(t)
		require.NoError(t, SaveMissionsToDB(ctx, sqlDB))
		require.NoError(t, SaveWorkOrdersToDB(ctx, sqlDB, nil))
	})

	t.Run("syncing the same mission twice updates instead of failing", func(t *testing.T) {
		sqlDB := openTest(t)
		started := time.Date(2024, 4, 24, 22, 0, 0, 0, time.UTC)

		mission := MissionDB{
			ID: "64850e8019d5d64c415d13dd", Number: "7000YRK51", Kind: "Incident",
			Label: "VALIDATION DEVIS", Status: "OPEN", StartedAt: started, Description: "BONJOUR",
		}
		require.NoError(t, SaveMissionsToDB(ctx, sqlDB, mission))

		// Second sync: same ID, updated status.
		mission.Status = "FINISHED"
		require.NoError(t, SaveMissionsToDB(ctx, sqlDB, mission))

		got, err := GetMissionsDB(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, got, 1, "the mission must be updated, not duplicated")
		assert.Equal(t, "FINISHED", got[0].Status)
		assert.True(t, got[0].StartedAt.Equal(started))
	})

	t.Run("times are stored in UTC so that they sort chronologically", func(t *testing.T) {
		sqlDB := openTest(t)
		paris := time.FixedZone("CEST", 2*60*60)

		older := MissionDB{ID: "older", StartedAt: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)}
		// 2024-01-01T09:00:00+02:00 is 07:00 UTC, i.e. *before* `older`, even
		// though "2024-01-01T09:00:00+02:00" > "2024-01-01T10:00:00Z" as text.
		newer := MissionDB{ID: "newer", StartedAt: time.Date(2024, 1, 1, 9, 0, 0, 0, paris)}
		require.NoError(t, SaveMissionsToDB(ctx, sqlDB, older, newer))

		got, err := GetMissionsDB(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, []string{"older", "newer"}, []string{got[0].ID, got[1].ID},
			"ORDER BY started_at DESC must be chronological")
	})
}

func TestSaveWorkOrdersToDB(t *testing.T) {
	ctx := context.Background()
	sqlDB := openTest(t)

	// The foreign key on work_orders.mission_id is now enforced, so the mission
	// has to exist first.
	require.NoError(t, SaveMissionsToDB(ctx, sqlDB, MissionDB{ID: "mission-1", StartedAt: time.Unix(0, 0).UTC()}))
	require.NoError(t, UpsertSuppliersToDB(ctx, sqlDB, []SupplierDB{{ID: "sup-1", Name: "2NRT", Activity: "PLOM"}}))

	wo := WorkOrderDB{
		ID: "wo-1", MissionID: "mission-1", Number: "OSMIL802702875", Label: "DEMANDE INTERVENTION",
		RepairDateStart: time.Date(2022, 10, 18, 22, 0, 0, 0, time.UTC),
		RepairDateEnd:   time.Date(2022, 10, 19, 22, 0, 0, 0, time.UTC),
		Supplier:        SupplierDB{ID: "sup-1", Name: "2NRT", Activity: "PLOM"},
	}
	require.NoError(t, SaveWorkOrdersToDB(ctx, sqlDB, []WorkOrderDB{wo}))

	// Same work order again, with a new label.
	wo.Label = "INTERVENTION TERMINEE"
	require.NoError(t, SaveWorkOrdersToDB(ctx, sqlDB, []WorkOrderDB{wo}))

	missions, err := GetMissionsDB(ctx, sqlDB)
	require.NoError(t, err)
	require.Len(t, missions, 1)
	require.Len(t, missions[0].WorkOrders, 1, "the work order must be updated, not duplicated")
	assert.Equal(t, "INTERVENTION TERMINEE", missions[0].WorkOrders[0].Label)
	assert.Equal(t, "2NRT", missions[0].WorkOrders[0].Supplier.Name)
	assert.True(t, missions[0].WorkOrders[0].RepairDateStart.Equal(wo.RepairDateStart))
}

func TestUpsertSuppliersToDB(t *testing.T) {
	ctx := context.Background()
	sqlDB := openTest(t)

	require.NoError(t, UpsertSuppliersToDB(ctx, sqlDB, []SupplierDB{{ID: "sup-1", Name: "OLD NAME", Activity: "PLOM"}}))
	require.NoError(t, UpsertSuppliersToDB(ctx, sqlDB, []SupplierDB{{ID: "sup-1", Name: "NEW NAME", Activity: "ISOL"}}))

	got, err := GetSuppliersDB(ctx, sqlDB)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "NEW NAME", got[0].Name, "the supplier's name must be updated")
	assert.Equal(t, "ISOL", got[0].Activity)
}

func TestUpsertContractDocumentsWithDB(t *testing.T) {
	ctx := context.Background()
	sqlDB := openTest(t)

	require.NoError(t, UpsertSuppliersToDB(ctx, sqlDB, []SupplierDB{{ID: "sup-1", Name: "2NRT", Activity: "PLOM"}}))

	doc := SupplierContractDocumentDB{ID: "doc-1", SupplierID: "sup-1", HashFile: "hash-1"}
	require.NoError(t, UpsertContractDocumentsWithDB(ctx, sqlDB, []SupplierContractDocumentDB{doc}))

	doc.FilePath = "contracts/2NRT.pdf"
	require.NoError(t, UpsertContractDocumentsWithDB(ctx, sqlDB, []SupplierContractDocumentDB{doc}))

	got, err := GetSupplierContractDocsDB(ctx, sqlDB)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, doc, got[0])

	one, err := GetSupplierContractByHashFileDB(ctx, sqlDB, "hash-1")
	require.NoError(t, err)
	assert.Equal(t, doc, one)

	bySupplier, err := GetSupplierContractBySupplierIDDB(ctx, sqlDB, "sup-1")
	require.NoError(t, err)
	assert.Equal(t, []SupplierContractDocumentDB{doc}, bySupplier)

	suppliers, err := GetSuppliersDB(ctx, sqlDB)
	require.NoError(t, err)
	require.Len(t, suppliers, 1)
	assert.Equal(t, []SupplierContractDocumentDB{doc}, suppliers[0].Documents)
}

func TestUpsertAccountDocumentsWithDB(t *testing.T) {
	ctx := context.Background()
	sqlDB := openTest(t)

	doc := AccountDocumentDB{
		ID: "64850e8057dcdd65a89cc462", HashFile: "64850e8057dcdd65a89cc462",
		MimeType: "application/pdf", Category: DocumentCategoryReportVisit,
		CreatedAt: time.Date(2022, 10, 13, 10, 15, 0, 0, time.UTC),
	}
	require.NoError(t, UpsertAccountDocumentsWithDB(ctx, sqlDB, []AccountDocumentDB{doc}))

	// The file path shows up once the document has been downloaded.
	doc.FilePath = "reports/CRvisite.pdf"
	require.NoError(t, UpsertAccountDocumentsWithDB(ctx, sqlDB, []AccountDocumentDB{doc}))

	got, err := GetAccountDocumentsDB(ctx, sqlDB)
	require.NoError(t, err)
	require.Len(t, got, 1, "the document must be updated, not duplicated")
	assert.Equal(t, doc, got[0])

	byHash, err := GetAccountDocumentByHashFileDB(ctx, sqlDB, string(doc.HashFile))
	require.NoError(t, err)
	assert.Equal(t, doc, byHash)

	byCategory, err := GetAccountDocumentByCategoryDB(ctx, sqlDB, DocumentCategoryReportVisit)
	require.NoError(t, err)
	assert.Equal(t, []AccountDocumentDB{doc}, byCategory)

	none, err := GetAccountDocumentByCategoryDB(ctx, sqlDB, DocumentCategoryInvoice)
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestIsEmptyDB(t *testing.T) {
	ctx := context.Background()
	sqlDB := openTest(t)

	empty, err := IsEmptyDB(ctx, sqlDB)
	require.NoError(t, err)
	assert.True(t, empty)

	require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, ExpenseDocumentDB{ID: "x", Label: "x", Date: time.Unix(0, 0).UTC()}))
	empty, err = IsEmptyDB(ctx, sqlDB)
	require.NoError(t, err)
	assert.False(t, empty)

	require.NoError(t, RmLastExpenseDB(sqlDB))
	empty, err = IsEmptyDB(ctx, sqlDB)
	require.NoError(t, err)
	assert.True(t, empty)
}

func TestRmLastMissionDB(t *testing.T) {
	ctx := context.Background()
	sqlDB := openTest(t)

	require.NoError(t, SaveMissionsToDB(ctx, sqlDB,
		MissionDB{ID: "old", StartedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)},
		MissionDB{ID: "recent", StartedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
	))
	require.NoError(t, SaveWorkOrdersToDB(ctx, sqlDB, []WorkOrderDB{{
		ID: "wo-1", MissionID: "recent", RepairDateStart: time.Unix(0, 0).UTC(), RepairDateEnd: time.Unix(0, 0).UTC(),
	}}))

	require.NoError(t, RmLastMissionDB(sqlDB))

	got, err := GetMissionsDB(ctx, sqlDB)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "old", got[0].ID)
}

func TestMergeSupplierContractDocs(t *testing.T) {
	previous := []SupplierContractDocumentDB{
		{ID: "kept", SupplierID: "sup-1", HashFile: "h1", FilePath: "contracts/kept.pdf"},
		{ID: "changed", SupplierID: "sup-1", HashFile: "h2", FilePath: "contracts/changed.pdf"},
		{ID: "gone", SupplierID: "sup-1", HashFile: "h3"},
	}
	current := []SupplierContractDocumentDB{
		{ID: "kept", SupplierID: "sup-1", HashFile: "h1"},
		{ID: "changed", SupplierID: "sup-2", HashFile: "h2"},
		{ID: "new", SupplierID: "sup-1", HashFile: "h4"},
	}

	missing, updated, removed := MergeSupplierContractDocs(previous, current)

	assert.Equal(t, []SupplierContractDocumentDB{{ID: "new", SupplierID: "sup-1", HashFile: "h4"}}, missing)
	assert.Equal(t, []SupplierContractDocumentDB{
		// The file path is carried over from the DB.
		{ID: "changed", SupplierID: "sup-2", HashFile: "h2", FilePath: "contracts/changed.pdf"},
	}, updated, "'kept' only differs by its file path, so it isn't an update")
	assert.Equal(t, []SupplierContractDocumentDB{{ID: "gone", SupplierID: "sup-1", HashFile: "h3"}}, removed)
}

func TestMergeAccountDocumentsDB(t *testing.T) {
	createdAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	previous := []AccountDocumentDB{
		{ID: "kept", HashFile: "h1", Category: DocumentCategoryInvoice, CreatedAt: createdAt, FilePath: "a.pdf"},
		{ID: "changed", HashFile: "h2", Category: DocumentCategoryUnknown, CreatedAt: createdAt, FilePath: "b.pdf"},
		{ID: "gone", HashFile: "h3", CreatedAt: createdAt},
	}
	current := []AccountDocumentDB{
		{ID: "kept", HashFile: "h1", Category: DocumentCategoryInvoice, CreatedAt: createdAt},
		{ID: "changed", HashFile: "h2", Category: DocumentCategoryConvocation, CreatedAt: createdAt},
		{ID: "new", HashFile: "h4", CreatedAt: createdAt},
	}

	missing, updated, removed := MergeAccountDocumentsDB(previous, current)

	assert.Equal(t, []AccountDocumentDB{{ID: "new", HashFile: "h4", CreatedAt: createdAt}}, missing)
	assert.Equal(t, []AccountDocumentDB{
		{ID: "changed", HashFile: "h2", Category: DocumentCategoryConvocation, CreatedAt: createdAt, FilePath: "b.pdf"},
	}, updated)
	assert.Equal(t, []AccountDocumentDB{{ID: "gone", HashFile: "h3", CreatedAt: createdAt}}, removed)
}

func TestMergeExpense(t *testing.T) {
	oldFromDB := ExpenseDocumentDB{Label: "ELECO", FilePath: "invoices/ELECO.pdf"}
	newFromAPI := ExpenseDocumentDB{Label: "ELECO", HashFile: "h1"}

	merged := Merge(oldFromDB, newFromAPI)
	assert.Equal(t, ExpenseDocumentDB{Label: "ELECO", HashFile: "h1", FilePath: "invoices/ELECO.pdf"}, merged)
	assert.True(t, newFromAPI.Equal(merged), "Equal ignores the file path")
}

func TestForeignKeysAreEnforced(t *testing.T) {
	ctx := context.Background()
	sqlDB := openTest(t)

	err := SaveWorkOrdersToDB(ctx, sqlDB, []WorkOrderDB{{
		ID: "wo-1", MissionID: "does-not-exist", RepairDateStart: time.Unix(0, 0).UTC(), RepairDateEnd: time.Unix(0, 0).UTC(),
	}})
	assert.Error(t, err, "work_orders.mission_id references missions(id)")
}
func TestUpsertExpensesWithDB(t *testing.T) {
	ctx := context.Background()
	date := time.Date(2024, 6, 30, 22, 0, 0, 0, time.UTC)

	expense := ExpenseDocumentDB{
		ID:    "66dafe19a1b2c3d4e5f60718",
		Label: "ELECO", Amount: 79200, Date: date, Source: SourceAccounting,
		AccountingKey: AccountingKey{Allocation: "CHARGES UNITAIRES C", ExpenseType: "CONTRAT EXTRACTEURS"},
	}

	t.Run("no expenses is a no-op", func(t *testing.T) {
		sqlDB := openTest(t)
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB))
	})

	t.Run("an expense without an id is refused", func(t *testing.T) {
		sqlDB := openTest(t)
		noID := expense
		noID.ID = ""
		err := UpsertExpensesWithDB(ctx, sqlDB, noID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has no id")
	})

	t.Run("syncing the same expense twice is idempotent", func(t *testing.T) {
		sqlDB := openTest(t)
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, expense))
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, expense))

		got, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, expense, got[0])
	})

	t.Run("every field but the id is updated in place", func(t *testing.T) {
		// Foncia relabels, re-dates and reallocates lines after the fact; the
		// id is what ties the versions together.
		sqlDB := openTest(t)
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, expense))

		changed := expense
		changed.Label = "ELECO - CONTRAT EXTRACTEURS 2024"
		changed.Date = date.Add(24 * time.Hour)
		changed.Amount = 79300
		changed.AccountingKey.Allocation = "CHARGES UNITAIRES D"
		changed.AccountingKey.ExpenseType = "TRAVAUX ENTRETIEN"
		changed.Source = SourceRepairs
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, changed))

		got, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, got, 1, "the expense must be updated, not inserted a second time")
		assert.Equal(t, changed, got[0])
	})

	t.Run("the hash file showing up on a later sync updates the row", func(t *testing.T) {
		sqlDB := openTest(t)
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, expense))

		withHash := expense
		withHash.HashFile = "66dafe199f013b45ee991c96"
		withHash.InvoiceID = "6615521aac44b7c09440aeaa"
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, withHash))

		got, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, withHash, got[0])

		byHash, err := GetExpensesByHashFileDB(ctx, sqlDB, string(withHash.HashFile))
		require.NoError(t, err)
		assert.Equal(t, []ExpenseDocumentDB{withHash}, byHash)

		byInvoice, err := GetExpensesByInvoiceID(ctx, sqlDB, withHash.InvoiceID)
		require.NoError(t, err)
		assert.Equal(t, []ExpenseDocumentDB{withHash}, byInvoice)
	})

	t.Run("an invoice split across two allocations is two lines with two ids", func(t *testing.T) {
		sqlDB := openTest(t)
		a, b := expense, expense
		a.HashFile, b.HashFile = "6615521a0ee3bdcd450363fa", "6615521a0ee3bdcd450363fa"
		a.InvoiceID, b.InvoiceID = "6615521aac44b7c09440aeaa", "6615521aac44b7c09440aeaa"
		b.ID = "64850e80f7df27ce148231fc"
		b.AccountingKey.Allocation = "CHARGES UNITAIRES D"
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, a, b))
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, a, b))

		got, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		assert.Len(t, got, 2)

		byHash, err := GetExpensesByHashFileDB(ctx, sqlDB, string(a.HashFile))
		require.NoError(t, err)
		assert.Len(t, byHash, 2, "both lines share the PDF")
	})

	t.Run("the file path is persisted", func(t *testing.T) {
		sqlDB := openTest(t)
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, expense))

		downloaded := expense
		downloaded.FilePath = "invoices/ELECO.pdf"
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, downloaded))

		got, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "invoices/ELECO.pdf", got[0].FilePath)
		assert.Equal(t, "ELECO.pdf", got[0].Filename())
	})

	t.Run("an empty source and an empty hash file scan back without a NULL error", func(t *testing.T) {
		sqlDB := openTest(t)
		bare := ExpenseDocumentDB{ID: "6aa37115444a8644bdf6434d", Label: "RELIQUAT DE REPARTITION", Amount: 2, Date: date}
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, bare))

		got, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, bare, got[0])
	})
}

func TestLegacyExpenseID(t *testing.T) {
	date := time.Date(2024, 6, 30, 0, 0, 0, 0, time.UTC)
	key := AccountingKey{Allocation: "CHARGES UNITAIRES C", ExpenseType: "CONTRAT EXTRACTEURS"}
	e := ExpenseDocumentDB{Label: "ELECO", Amount: 79200, Date: date, AccountingKey: key, HashFile: "hA"}

	t.Run("is a 64-character hex string, unlike a 24-character Foncia id", func(t *testing.T) {
		assert.Len(t, LegacyExpenseID(e), 64)
	})

	t.Run("ignores the id and the file path", func(t *testing.T) {
		other := e
		other.ID = "whatever"
		other.FilePath = "a.pdf"
		assert.Equal(t, LegacyExpenseID(e), LegacyExpenseID(other))
	})

	t.Run("depends on the hash file", func(t *testing.T) {
		other := e
		other.HashFile = "hB"
		assert.NotEqual(t, LegacyExpenseID(e), LegacyExpenseID(other))
	})

	t.Run("depends on the allocation", func(t *testing.T) {
		other := e
		other.AccountingKey.Allocation = "CHARGES UNITAIRES D"
		assert.NotEqual(t, LegacyExpenseID(e), LegacyExpenseID(other))
	})

	t.Run("the time zone does not change it", func(t *testing.T) {
		paris := time.FixedZone("CEST", 2*60*60)
		other := e
		other.Date = date.In(paris)
		assert.Equal(t, LegacyExpenseID(e), LegacyExpenseID(other))
	})

	t.Run("LegacyExpenseIDs also gives the id derived without the hash file", func(t *testing.T) {
		withoutHash := e
		withoutHash.HashFile = ""
		assert.Equal(t, []string{LegacyExpenseID(e), LegacyExpenseID(withoutHash)}, LegacyExpenseIDs(e))
		assert.Equal(t, []string{LegacyExpenseID(withoutHash)}, LegacyExpenseIDs(withoutHash), "no hash file, no second candidate")
	})
}

func TestRekeyExpense(t *testing.T) {
	ctx := context.Background()
	date := time.Date(2024, 6, 30, 0, 0, 0, 0, time.UTC)
	legacy := ExpenseDocumentDB{
		Label: "ELECO", Amount: 79200, Date: date, Source: SourceAccounting, FilePath: "invoices/ELECO.pdf",
		AccountingKey: AccountingKey{Allocation: "CHARGES UNITAIRES C", ExpenseType: "CONTRAT EXTRACTEURS"},
	}
	legacy.ID = LegacyExpenseID(legacy)

	t.Run("gives the row its new id and keeps everything else", func(t *testing.T) {
		sqlDB := openTest(t)
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, legacy))

		rekeyed, err := RekeyExpense(ctx, sqlDB, legacy.ID, "66dafe19a1b2c3d4e5f60718")
		require.NoError(t, err)
		assert.True(t, rekeyed)

		got, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		want := legacy
		want.ID = "66dafe19a1b2c3d4e5f60718"
		assert.Equal(t, []ExpenseDocumentDB{want}, got)
	})

	t.Run("no row with the old id is not an error", func(t *testing.T) {
		sqlDB := openTest(t)
		rekeyed, err := RekeyExpense(ctx, sqlDB, legacy.ID, "66dafe19a1b2c3d4e5f60718")
		require.NoError(t, err)
		assert.False(t, rekeyed)
	})

	t.Run("a row that already has the new id is left alone, and so is the legacy row", func(t *testing.T) {
		sqlDB := openTest(t)
		fresh := legacy
		fresh.ID = "66dafe19a1b2c3d4e5f60718"
		fresh.FilePath = ""
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, legacy, fresh))

		rekeyed, err := RekeyExpense(ctx, sqlDB, legacy.ID, fresh.ID)
		require.NoError(t, err)
		assert.False(t, rekeyed)

		got, err := GetExpensesDB(ctx, sqlDB)
		require.NoError(t, err)
		assert.Len(t, got, 2, "neither row may be lost")
	})

	t.Run("empty ids are refused", func(t *testing.T) {
		sqlDB := openTest(t)
		_, err := RekeyExpense(ctx, sqlDB, "", "x")
		require.Error(t, err)
		_, err = RekeyExpense(ctx, sqlDB, "x", "")
		require.Error(t, err)
	})
}
