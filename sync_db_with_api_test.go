package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dnaeon/go-vcr/recorder"
	_ "github.com/glebarez/go-sqlite"
	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "embed"
)

// Load from disk api/mock/getAccountingCurrent.json using Go's embed.FS
//
//go:embed api/mock/getAccountingCurrent.json
var getAccountingCurrent []byte

func mockGraphQLServer(t *testing.T) *httptest.Server {
	t.Helper()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		bytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		// Also show the first 30 bytes
		t.Logf("Request: %s %s, body: %s", r.Method, r.URL, string(bytes)[:30])

		switch {
		case strings.Contains(string(bytes), "query getBuildingAccountingCurrent"):
			_, _ = w.Write(getAccountingCurrent)
		case strings.Contains(string(bytes), "query getAccountingPeriods"):
			_, _ = w.Write([]byte(`{"data":{"accountingPeriods":[]}}`))
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

func TestSyncExpensesWithDB(t *testing.T) {
	sqlDB, err := sql.Open("sqlite", "file::memory:?cache=shared") // In-memory SQLite
	require.NoError(t, err)
	defer sqlDB.Close()
	err = db.InitAndUpdateDB(t.Context(), sqlDB)
	require.NoError(t, err)

	srv := mockGraphQLServer(t)
	defer srv.Close()

	newExpenses, err := syncExpensesWithDB(t.Context(), srv.Client(), sqlDB, srv.URL+"/graphql", "fake", "not-used")
	require.NoError(t, err)

	expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
	require.NoError(t, err)
	require.Len(t, expensesInDB, len(newExpenses))

	assert.Len(t, expensesInDB, 264)

	// There are no duplicates in expensesInDB.
	foundInDB := make(map[db.ExpenseDocumentDB]struct{})
	for _, exp := range expensesInDB {
		_, found := foundInDB[exp]
		require.False(t, found, "duplicate expense in DB: %v", exp)
		foundInDB[exp] = struct{}{}
	}
}

func TestSyncExpensesWithDBVCR(t *testing.T) {
	t.Skip("haven't finished making this test work as it requires a real uuid")
	r, err := recorder.New("sync_expenses_vcr")
	require.NoError(t, err)
	defer r.Stop()

	sqlDB, err := sql.Open("sqlite", "file::memory:?cache=shared") // In-memory SQLite
	require.NoError(t, err)
	defer sqlDB.Close()

	client := &http.Client{Transport: r}

	uuid := "test-uuid"
	invoicesDir := "test-invoices" // Doesn't matter since we don't download

	newExpenses, err := syncExpensesWithDB(t.Context(), client, sqlDB, graphqlURL, uuid, invoicesDir)
	require.NoError(t, err)

	expensesInDB, err := db.GetExpensesDB(t.Context(), sqlDB)
	require.NoError(t, err)
	require.Len(t, expensesInDB, len(newExpenses))
}
