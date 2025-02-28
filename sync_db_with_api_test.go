package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dnaeon/go-vcr/recorder"
	_ "github.com/glebarez/go-sqlite"
	"github.com/goccy/go-yaml"
	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/undent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "embed"
)

// Load from disk api/mock/realGetAccountingCurrent.json using Go's embed.FS
//
//go:embed api/mock/getAccountingCurrent.json
var realGetAccountingCurrent []byte

func TestSyncExpensesWithDB(t *testing.T) {
	t.Run("api returns the same thing twice", func(t *testing.T) {
		sqlDB := withRealDB(t)
		srv := withMockServer(t, realGetAccountingCurrent, []byte(`{}`))

		newExpenses, err := syncExpensesWithDB(t.Context(), srv.Client(), sqlDB, srv.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, newExpenses, 264)
		assert.Len(t, expensesInDB, 264)

		newExpenses, err = syncExpensesWithDB(t.Context(), srv.Client(), sqlDB, srv.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		expensesInDB, err = db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, newExpenses, 0)
		assert.Len(t, expensesInDB, 264)
	})

	t.Run("api returns a new expense", func(t *testing.T) {
		sqlDB := withRealDB(t)
		before := withMockServer(t, withAccountingCurrentResp([]map[string]any{
			with("SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
		}), withRGDDResp(nil))
		newExpenses, err := syncExpensesWithDB(t.Context(), before.Client(), sqlDB, before.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, newExpenses, 1)
		assert.Len(t, expensesInDB, 1)

		after := withMockServer(t, withAccountingCurrentResp([]map[string]any{
			with("SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
			with("SARL SMF SERVICES - CONTRAT MAINTENANCE DU PORTAIL AUTOMATIQUE - 08/07/24", "2024-09-20T16:43:33.138Z", "66eda6344b41c38804f77fc1", "66eda634eb168575f218d58c"),
		}), withRGDDResp(nil),
		)

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

	t.Run("deduplication when GetBuildingAccountingCurrent overlaps with GetBuildingAccountingRGDD", func(t *testing.T) {
		sqlDB := withRealDB(t)
		before := withMockServer(t, withAccountingCurrentResp([]map[string]any{
			with("SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
		}), withRGDDResp([]map[string]any{
			with("SMF SERVICES", "2023-07-17T09:35:13.195Z", "64b50b500f443f809d4ea649", "64b50b50a33ee7526c060933"),
		}))
		newExpenses, err := syncExpensesWithDB(t.Context(), before.Client(), sqlDB, before.URL+"/graphql", "fake", "not-used")
		require.NoError(t, err)
		expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Equal(t, 1, len(newExpenses))
		assert.Equal(t, []db.ExpenseDocumentDB{{
			InvoiceID:     "64b50b50a33ee7526c060933",
			Label:         "SMF SERVICES",
			Date:          withDate("2023-07-17T09:35:13.195Z"),
			HashFile:      "64b50b500f443f809d4ea649",
			Amount:        db.Amount(10000),
			Source:        "accounting",
			AccountingKey: db.AccountingKey{Allocation: "CHARGES GENERALES", ExpenseType: "CONTRAT D'ENTRETIEN"},
		}}, expensesInDB)
		hasNoDuplicates(t, expensesInDB)
	})
}

func TestSyncExpensesWithDBVCR(t *testing.T) {
	t.Skip("this test takes forever, only ever run it manually")
	mode := recorder.ModeReplaying
	var authenticated http.RoundTripper
	if os.Getenv("RECORD") != "" {
		mode = recorder.ModeRecording
		token := os.Getenv("FONCIA_TOKEN")
		if token == "" {
			t.Fatal("FONCIA_TOKEN is not set")
		}
		authenticated = api.AuthenticatedClientToken(api.Token(token)).Transport
	}

	switch mode {
	case recorder.ModeRecording:
		t.Logf("mode: recording")
	case recorder.ModeReplaying:
		t.Logf("mode: replaying")
	default:
		t.Logf("mode: %v", mode)
	}

	r, err := recorder.NewAsMode("sync_expenses_vcr", mode, authenticated)
	require.NoError(t, err)
	defer r.Stop()

	sqlDB := withRealDB(t)

	uuid := "eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9"
	invoicesDir := "invoices"

	newExpenses, err := syncExpensesWithDB(t.Context(), &http.Client{Transport: r}, sqlDB, graphqlURL, uuid, invoicesDir)
	require.NoError(t, err)
	expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
	require.NoError(t, err)
	assert.Equal(t, 1067, len(newExpenses))
	assert.Equal(t, 1067, len(expensesInDB))
	hasNoDuplicates(t, expensesInDB)

	r, _ = recorder.NewAsMode("sync_expenses_vcr", mode, authenticated)
	newExpenses, err = syncExpensesWithDB(t.Context(), &http.Client{Transport: r}, sqlDB, graphqlURL, uuid, invoicesDir)
	require.NoError(t, err)
	expensesInDB, err = db.GetExpensesDB(t.Context(), sqlDB)
	require.NoError(t, err)
	assert.Equal(t, 0, newExpenses)
	assert.Equal(t, 1067, expensesInDB)
	hasNoDuplicates(t, expensesInDB)
}

func withDate(date string) time.Time {
	t, err := time.Parse(time.RFC3339, date)
	if err != nil {
		panic(err)
	}
	return t
}
func hasNoDuplicates(t *testing.T, expenses []db.ExpenseDocumentDB) {
	t.Helper()
	seen := make(map[db.ExpenseDocumentDB]int)
	for i, e := range expenses {
		if j, ok := seen[e]; ok {
			t.Errorf("#%d and #%d are duplicates: %v", j, i, e)
			t.FailNow()
		}
		seen[e] = i
	}
}

func withRealDB(t *testing.T) *sql.DB {
	sqlDB, err := sql.Open("sqlite", "file::memory:")
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	err = db.InitAndUpdateDB(t.Context(), sqlDB)
	require.NoError(t, err)
	return sqlDB
}

func withMockServer(t *testing.T, getAccountingCurrentResp []byte, getRGDDResp []byte) *httptest.Server {
	t.Helper()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		bytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		if !strings.Contains(string(bytes), "query getDocumentURL") {
			t.Logf("Request: %s %s, body: %s", r.Method, r.URL, string(bytes)[:40])
		}

		switch {
		case strings.Contains(string(bytes), "query getBuildingAccountingCurrent"):
			_, _ = w.Write(getAccountingCurrentResp)
		case strings.Contains(string(bytes), "query getAccountingPeriods"):
			_, _ = w.Write([]byte(undent.Undent(`
				{
				  "data": {
				    "coownerAccount": {
				      "uuid": "eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9",
				      "trusteeCouncil": {
				        "accountingPeriods": {
				          "totalCount": null,
				          "pageInfo": {"startCursor": "eyJwYWdlTnVtYmVyIjoxLCJpdGVtc1BlclBhZ2UiOjEwfQ","endCursor": "eyJwYWdlTnVtYmVyIjoyLCJpdGVtc1BlclBhZ2UiOjEwfQ","hasPreviousPage": false,"hasNextPage": false},
				          "edges": [
				            {"node": {"id": "672b266b8cc9fc7a75f4b886", "name": "01/07/2024", "openingDate": "2024-06-30T22:00:00.000Z", "closingDate": "2025-06-30T21:59:59.999Z", "status": "OPEN"}}
				          ]
				        }
				      }
				    }
				  }
				}
			`)))
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

func with(label, date, hashFile, invoiceID string) map[string]any {
	return map[string]any{
		"invoiceId": invoiceID,
		"label":     label,
		"date":      date,
		"piece": map[string]any{
			"hashFile": hashFile, "category": "invoices", "id": hashFile,
		},
		"amount":     map[string]any{"value": 10000, "currency": "EUR", "__typename": "Debit"}, // for getAccountingCurrent
		"toAllocate": map[string]any{"value": 10000, "currency": "EUR"},                        // for getAccountingRGDD
	}
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

func withAccountingCurrentResp(expenses []map[string]any) []byte {
	v := map[string]any{
		"data": map[string]any{
			"coownerAccount": map[string]any{
				"uuid": "eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9",
				"trusteeCouncil": map[string]any{
					"bankBalance": map[string]any{"value": 10417523, "currency": "EUR"},
					"accountingCurrent": map[string]any{
						"id": "648ae397d369781df20f28f4",
						"allocations": []map[string]any{{
							"id":   "64850e80ec471885a8b0821a",
							"name": "CHARGES GENERALES",
							"code": "001",
							"expenseTypes": []map[string]any{{
								"id":       "5e5dafddd60067a5bbfdde69",
								"name":     "CONTRAT D'ENTRETIEN",
								"code":     "100",
								"expenses": expenses,
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

func toJSON(yamlStr string) string {
	var v map[string]any
	err := yaml.Unmarshal([]byte(yamlStr), &v)
	if err != nil {
		panic(err)
	}

	bytes, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(bytes)
}
