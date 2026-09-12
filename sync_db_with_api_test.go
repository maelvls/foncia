package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncExpensesWithDB(t *testing.T) {
	t.Run("api returns the same thing twice", func(t *testing.T) {
		// A bulk sync, then the very same payload again: the second run must
		// report nothing new and must not duplicate anything.
		const count = 264
		var expenses []map[string]any
		for i := range count {
			expenses = append(expenses, with(
				fmt.Sprintf("%024x", i+2_000_000),
				fmt.Sprintf("FOURNISSEUR %03d", i),
				fmt.Sprintf("2024-01-%02dT09:35:13.195Z", i%28+1),
				fmt.Sprintf("%024x", i),
				fmt.Sprintf("%024x", i+1_000_000),
			))
		}

		sqlDB := withRealDB(t)
		srv := withMockServer(t, withRGDDResp(expenses))

		newExpenses, err := syncExpensesWithDB(t.Context(), srv.Client(), sqlDB, srv.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, newExpenses, count)
		assert.Len(t, expensesInDB, count)
		hasNoDuplicates(t, expensesInDB)

		newExpenses, err = syncExpensesWithDB(t.Context(), srv.Client(), sqlDB, srv.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		expensesInDB, err = db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, newExpenses, 0)
		assert.Len(t, expensesInDB, count)
		hasNoDuplicates(t, expensesInDB)
	})

	t.Run("api returns a new expense", func(t *testing.T) {
		sqlDB := withRealDB(t)
		before := withMockServer(t, withRGDDResp([]map[string]any{
			with("64b50b50c3d5a0f1e2b4c6d8", "SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
		}))
		newExpenses, err := syncExpensesWithDB(t.Context(), before.Client(), sqlDB, before.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, newExpenses, 1)
		assert.Len(t, expensesInDB, 1)

		after := withMockServer(t, withRGDDResp([]map[string]any{
			with("64b50b50c3d5a0f1e2b4c6d8", "SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
			with("66eda634f0a1b2c3d4e5f607", "SARL SMF SERVICES - CONTRAT MAINTENANCE DU PORTAIL AUTOMATIQUE - 08/07/24", "2024-09-20T16:43:33.138Z", "66eda6344b41c38804f77fc1", "66eda634eb168575f218d58c"),
		}))

		newExpenses, err = syncExpensesWithDB(t.Context(), after.Client(), sqlDB, after.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		expensesInDB, err = db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, newExpenses, 1)
		assert.Len(t, expensesInDB, 2)

		newExpenses, err = syncExpensesWithDB(t.Context(), after.Client(), sqlDB, after.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		expensesInDB, err = db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, newExpenses, 0)
		assert.Len(t, expensesInDB, 2)
	})

	t.Run("a relabelled expense is updated in place, not stored twice", func(t *testing.T) {
		// This is the whole point of keying on Foncia's id: before, a label
		// change produced a second row, since the label was part of the key.
		sqlDB := withRealDB(t)
		before := withMockServer(t, withRGDDResp([]map[string]any{
			with("64b50b50c3d5a0f1e2b4c6d8", "SMF SERVICES", "2023-07-17T09:35:13.195Z", "", ""),
		}))
		newExpenses, err := syncExpensesWithDB(t.Context(), before.Client(), sqlDB, before.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		require.Len(t, newExpenses, 1)

		// Same id; the label changed, the date moved, and the hash file
		// finally showed up.
		after := withMockServer(t, withRGDDResp([]map[string]any{
			with("64b50b50c3d5a0f1e2b4c6d8", "SARL SMF SERVICES - CONTRAT MAINTENANCE DU PORTAIL", "2023-07-18T00:00:00.000Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
		}))
		newExpenses, err = syncExpensesWithDB(t.Context(), after.Client(), sqlDB, after.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		assert.Len(t, newExpenses, 0, "a changed expense is not a new expense")

		expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Equal(t, []db.ExpenseDocumentDB{{
			ID:            "64b50b50c3d5a0f1e2b4c6d8",
			InvoiceID:     "64b50b50a33ee7526c060933",
			Label:         "SARL SMF SERVICES - CONTRAT MAINTENANCE DU PORTAIL",
			Date:          withDate("2023-07-18T00:00:00.000Z"),
			HashFile:      "64b50b500f443f809d4ea649",
			Amount:        db.Amount(10000),
			Source:        "accounting",
			AccountingKey: db.AccountingKey{Allocation: "CHARGES GENERALES", ExpenseType: "CONTRAT D'ENTRETIEN"},
		}}, expensesInDB)
	})

	t.Run("a row stored under a legacy id is re-keyed to the Foncia id", func(t *testing.T) {
		// The production database was filled before Foncia's id was used; its
		// rows carry a hash of their contents as id. The first sync that sees
		// such an expense with its Foncia id must adopt the existing row
		// (keeping its file path) rather than insert a second one.
		sqlDB := withRealDB(t)
		legacy := db.ExpenseDocumentDB{
			InvoiceID:     "64b50b50a33ee7526c060933",
			Label:         "SMF SERVICES",
			Date:          withDate("2023-07-17T09:35:13.195Z"),
			HashFile:      "64b50b500f443f809d4ea649",
			Amount:        db.Amount(10000),
			Source:        "accounting",
			AccountingKey: db.AccountingKey{Allocation: "CHARGES GENERALES", ExpenseType: "CONTRAT D'ENTRETIEN"},
			FilePath:      "invoices/SMF SERVICES.pdf",
		}
		legacy.ID = db.LegacyExpenseID(legacy)
		require.NoError(t, db.UpsertExpensesWithDB(t.Context(), sqlDB, legacy))

		srv := withMockServer(t, withRGDDResp([]map[string]any{
			with("64b50b50c3d5a0f1e2b4c6d8", "SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
		}))
		newExpenses, err := syncExpensesWithDB(t.Context(), srv.Client(), sqlDB, srv.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		assert.Len(t, newExpenses, 0, "a re-keyed expense is not a new expense")

		expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		want := legacy
		want.ID = "64b50b50c3d5a0f1e2b4c6d8"
		assert.Equal(t, []db.ExpenseDocumentDB{want}, expensesInDB, "the row must have been re-keyed, and its file path kept")

		// And the next sync is a plain no-op.
		newExpenses, err = syncExpensesWithDB(t.Context(), srv.Client(), sqlDB, srv.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		assert.Len(t, newExpenses, 0)
		expensesInDB, err = db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, expensesInDB, 1)
	})

	t.Run("a legacy row that predates its hash file is re-keyed too", func(t *testing.T) {
		// Under the legacy scheme, a row stored before its PDF was attached
		// had an id derived without the hash file. It must still be found.
		sqlDB := withRealDB(t)
		legacy := db.ExpenseDocumentDB{
			Label:         "SMF SERVICES",
			Date:          withDate("2023-07-17T09:35:13.195Z"),
			Amount:        db.Amount(10000),
			Source:        "accounting",
			AccountingKey: db.AccountingKey{Allocation: "CHARGES GENERALES", ExpenseType: "CONTRAT D'ENTRETIEN"},
		}
		legacy.ID = db.LegacyExpenseID(legacy)
		require.NoError(t, db.UpsertExpensesWithDB(t.Context(), sqlDB, legacy))

		srv := withMockServer(t, withRGDDResp([]map[string]any{
			with("64b50b50c3d5a0f1e2b4c6d8", "SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
		}))
		newExpenses, err := syncExpensesWithDB(t.Context(), srv.Client(), sqlDB, srv.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		assert.Len(t, newExpenses, 0)

		expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		require.Len(t, expensesInDB, 1)
		assert.Equal(t, "64b50b50c3d5a0f1e2b4c6d8", expensesInDB[0].ID)
		assert.Equal(t, db.HashFile("64b50b500f443f809d4ea649"), expensesInDB[0].HashFile, "the hash file must have been attached")
	})

	t.Run("the same id returned twice is stored once", func(t *testing.T) {
		sqlDB := withRealDB(t)
		srv := withMockServer(t, withRGDDResp([]map[string]any{
			with("64b50b50c3d5a0f1e2b4c6d8", "SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
			with("64b50b50c3d5a0f1e2b4c6d8", "SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
		}))
		newExpenses, err := syncExpensesWithDB(t.Context(), srv.Client(), sqlDB, srv.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		assert.Len(t, newExpenses, 1)
		expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, expensesInDB, 1)
	})
}

func withDate(date string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, date)
	if err != nil {
		panic(err)
	}
	return t
}

// hasNoDuplicates fails when two rows have the same contents, the id aside.
func hasNoDuplicates(t *testing.T, expenses []db.ExpenseDocumentDB) {
	t.Helper()
	seen := make(map[db.ExpenseDocumentDB]int)
	for i, e := range expenses {
		e.ID = ""
		if j, ok := seen[e]; ok {
			t.Errorf("#%d and #%d are duplicates: %v", j, i, e)
			t.FailNow()
		}
		seen[e] = i
	}
}

func withRealDB(t *testing.T) *sql.DB {
	sqlDB, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	return sqlDB
}

// withMockServer serves one accounting period whose RGDD answer is
// getRGDDResp, no repair budget, and no document URL. Any other query, in
// particular the old getBuildingAccountingCurrent, is answered with a 500 so
// that the test fails if the sync ever calls it again.
func withMockServer(t *testing.T, getRGDDResp []byte) *httptest.Server {
	t.Helper()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		bytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		if !strings.Contains(string(bytes), "query getDocumentURL") {
			t.Logf("Request: %s %s, body: %s", r.Method, r.URL, string(bytes)[:40])
		}

		switch {
		case strings.Contains(string(bytes), "query getAccountingPeriods"):
			_, _ = w.Write([]byte(`
				{
				  "data": {
				    "coownerAccount": {
				      "uuid": "eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9",
				      "trusteeCouncil": {
				        "accountingPeriods": {
				          "totalCount": null,
				          "pageInfo": {"startCursor": "eyJwYWdlTnVtYmVyIjoxLCJpdGVtc1BlclBhZ2UiOjEwfQ","endCursor": "eyJwYWdlTnVtYmVyIjoyLCJpdGVtc1BlclBhZ2UiOjEwfQ","hasPreviousPage": false,"hasNextPage": false},
				          "edges": [
				            {"node": {"id": "672b266b8cc9fc7a75f4b886", "name": "01/07/2026", "openingDate": "2026-06-30T22:00:00.000Z", "closingDate": "2027-06-30T21:59:59.999Z", "status": "OPEN"}}
				          ]
				        }
				      }
				    }
				  }
				}
			`))
		case strings.Contains(string(bytes), "query getBuildingAccountingRGDD"):
			_, _ = w.Write(getRGDDResp)
		case strings.Contains(string(bytes), "query getRepairBudgets"):
			_, _ = w.Write([]byte(`{"data":{"repairBudgets":[]}}`))
		case strings.Contains(string(bytes), "query getDocumentURL"):
			_, _ = w.Write([]byte(`{"data":{"documentURL":""}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(fmt.Appendf([]byte{}, "unexpected request: %s", string(bytes)))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// with builds one RGDD expense line. An empty hashFile stands for a line with
// no PDF attached yet (piece: null), and an empty invoiceID for invoiceId: null.
func with(id, label, date, hashFile, invoiceID string) map[string]any {
	e := map[string]any{
		"id":         id,
		"label":      label,
		"date":       date,
		"toAllocate": map[string]any{"value": 10000, "currency": "EUR"},
	}
	if hashFile != "" {
		e["piece"] = map[string]any{"hashFile": hashFile, "category": "invoices", "id": hashFile}
	} else {
		e["piece"] = nil
	}
	if invoiceID != "" {
		e["invoiceId"] = invoiceID
	} else {
		e["invoiceId"] = nil
	}
	return e
}

func withRGDDResp(expenses []map[string]any) []byte {
	v := map[string]any{
		"data": map[string]any{
			"coownerAccount": map[string]any{
				"uuid": "eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9",
				"trusteeCouncil": map[string]any{
					"pastAccountingRGDD": map[string]any{
						"totalToAllocate":  map[string]any{"value": 4183445, "currency": "EUR"},
						"totalVat":         map[string]any{"value": 466511, "currency": "EUR"},
						"totalRecoverable": map[string]any{"value": 2670460, "currency": "EUR"},
						"allocations": []map[string]any{{
							"id":          "64850e8065ec657db8c1f5e7",
							"name":        "CHARGES GENERALES",
							"code":        "001",
							"toAllocate":  map[string]any{"value": 2250024, "currency": "EUR"},
							"vat":         map[string]any{"value": 297373, "currency": "EUR"},
							"recoverable": map[string]any{"value": 1681799, "currency": "EUR"},
							"expenseTypes": []map[string]any{{
								"id":           "5e5dafddd60067a5bbfdde69",
								"allocationId": "64850e8065ec657db8c1f5e7",
								"name":         "CONTRAT D'ENTRETIEN",
								"code":         "100",
								"toAllocate":   map[string]any{"value": 29700, "currency": "EUR"},
								"vat":          map[string]any{"value": 2700, "currency": "EUR"},
								"recoverable":  map[string]any{"value": 29700, "currency": "EUR"},
								"expenses":     expenses,
							}},
						}},
					},
				},
			},
		},
	}

	bytes, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return bytes
}
