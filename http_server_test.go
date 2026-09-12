package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The "header" sub-template is parsed by ServeHTTP, which the tests don't call
// since they only exercise addHandlers. Without it, executing the index
// template fails with `no such template "header"`. html/template refuses to
// have new templates added to a set that has already been executed, so this is
// done exactly once for the whole test binary.
var parseHeaderOnce sync.Once

func withHeaderTemplate(t *testing.T) {
	t.Helper()
	parseHeaderOnce.Do(func() {
		_, err := tmpl.New("header").Parse(headerHTML)
		require.NoError(t, err)
	})
}

// failingClient is an HTTP client that fails the test as soon as anything tries
// to use it. None of the cases below is supposed to reach out to Foncia.
func failingClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("the handler unexpectedly made an HTTP request to %s", r.URL)
		return nil, fmt.Errorf("no network calls allowed in this test")
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	sqlDB, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return sqlDB
}

// newTestMux builds the same mux that ServeHTTP builds, minus the listener, the
// base path and the network.
func newTestMux(t *testing.T, sqlDB *sql.DB) *http.ServeMux {
	t.Helper()
	withHeaderTemplate(t)

	lastSync := func() (time.Time, error) {
		return time.Date(2024, 7, 1, 12, 0, 0, 0, time.UTC), nil
	}

	mux := http.NewServeMux()
	err := addHandlers(mux, sqlDB, failingClient(t), "some-uuid", "" /* basePath */, t.TempDir(), lastSync)
	require.NoError(t, err)
	return mux
}

// do runs one request against the mux. It deliberately doesn't recover from a
// panic: a panicking handler must fail the test loudly (this is what the
// /dl/invoiceid regression used to do).
func do(t *testing.T, mux *http.ServeMux, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

// seedExpenseWithFile writes a real PDF in a temporary directory and records an
// expense pointing at it. It returns the path of the file on disk.
func seedExpenseWithFile(t *testing.T, sqlDB *sql.DB, hashFile, invoiceID, filename, contents string) string {
	t.Helper()

	filePath := filepath.Join(t.TempDir(), filename)
	require.NoError(t, os.WriteFile(filePath, []byte(contents), 0o600))

	err := db.UpsertExpensesWithDB(t.Context(), sqlDB, db.ExpenseDocumentDB{
		ID:            "66eda634f0a1b2c3d4e5f607",
		Label:         "SARL SMF SERVICES - CONTRAT MAINTENANCE",
		Amount:        db.Amount(41049), // 410,49 €
		Date:          time.Date(2024, 9, 20, 16, 43, 33, 0, time.UTC),
		FilePath:      filePath,
		HashFile:      db.HashFile(hashFile),
		InvoiceID:     invoiceID,
		Source:        db.SourceAccounting,
		AccountingKey: db.AccountingKey{Allocation: "CHARGES GENERALES", ExpenseType: "CONTRAT D'ENTRETIEN"},
	})
	require.NoError(t, err)

	return filePath
}

func TestDLHandler(t *testing.T) {
	t.Run("unknown invoice ID returns 404 instead of panicking", func(t *testing.T) {
		// GetExpensesByInvoiceID returns an empty non-nil slice when nothing
		// matches, which used to make the handler index expenses[0] and panic.
		mux := newTestMux(t, openTestDB(t))

		rec := do(t, mux, "GET", "/dl/invoiceid/000000000000000000000000")

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("unknown invoice ID with a filename returns 404", func(t *testing.T) {
		mux := newTestMux(t, openTestDB(t))

		rec := do(t, mux, "GET", "/dl/invoiceid/000000000000000000000000/whatever.pdf")

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("unknown hash file returns 404 for every type", func(t *testing.T) {
		mux := newTestMux(t, openTestDB(t))

		// "doc" is included on purpose: the lookup fails before the handler
		// gets a chance to download anything from Foncia.
		for _, typ := range []string{"invoice", "contract", "doc"} {
			t.Run(typ, func(t *testing.T) {
				rec := do(t, mux, "GET", "/dl/"+typ+"/000000000000000000000000")

				assert.Equal(t, http.StatusNotFound, rec.Code)
			})
		}
	})

	t.Run("unknown type returns 404", func(t *testing.T) {
		mux := newTestMux(t, openTestDB(t))

		rec := do(t, mux, "GET", "/dl/nonsense/abc")

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("known hash file without a filename redirects, then serves the file", func(t *testing.T) {
		const hash = "66eda6344b41c38804f77fc1"
		const contents = "%PDF-1.4 pretend this is an invoice"
		sqlDB := openTestDB(t)
		filePath := seedExpenseWithFile(t, sqlDB, hash, "66eda634eb168575f218d58c", "facture-2024-09.pdf", contents)
		mux := newTestMux(t, sqlDB)

		rec := do(t, mux, "GET", "/dl/invoice/"+hash)

		require.Equal(t, http.StatusFound, rec.Code)
		location := rec.Header().Get("Location")
		assert.Equal(t, "/dl/invoice/"+hash+"/"+filepath.Base(filePath), location)

		// Now follow the canonical URL.
		rec = do(t, mux, "GET", location)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, contents, rec.Body.String())
		assert.Equal(t, "private, max-age=300", rec.Header().Get("Cache-Control"))
	})

	t.Run("known hash file with the wrong filename redirects to the right one", func(t *testing.T) {
		const hash = "66eda6344b41c38804f77fc1"
		sqlDB := openTestDB(t)
		filePath := seedExpenseWithFile(t, sqlDB, hash, "66eda634eb168575f218d58c", "facture-2024-09.pdf", "content")
		mux := newTestMux(t, sqlDB)

		rec := do(t, mux, "GET", "/dl/invoice/"+hash+"/wrong-name.pdf")

		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/dl/invoice/"+hash+"/"+filepath.Base(filePath), rec.Header().Get("Location"))
	})

	t.Run("known invoice ID is served through the invoiceid endpoint", func(t *testing.T) {
		const invoiceID = "66eda634eb168575f218d58c"
		const contents = "%PDF-1.4 another invoice"
		sqlDB := openTestDB(t)
		filePath := seedExpenseWithFile(t, sqlDB, "66eda6344b41c38804f77fc1", invoiceID, "facture-2024-10.pdf", contents)
		mux := newTestMux(t, sqlDB)

		rec := do(t, mux, "GET", "/dl/invoiceid/"+invoiceID+"/"+filepath.Base(filePath))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, contents, rec.Body.String())
	})

	t.Run("an expense known but never downloaded returns 404 instead of looping", func(t *testing.T) {
		// An empty file path used to make path.Base return "." and the handler
		// redirect to the very URL that was requested.
		const hash = "66eda6344b41c38804f77fc2"
		sqlDB := openTestDB(t)
		err := db.UpsertExpensesWithDB(t.Context(), sqlDB, db.ExpenseDocumentDB{
			ID:       "66eda634f0a1b2c3d4e5f608",
			Label:    "EXPENSE WITHOUT A FILE ON DISK",
			Amount:   db.Amount(1000),
			Date:     time.Date(2024, 9, 20, 16, 43, 33, 0, time.UTC),
			HashFile: db.HashFile(hash),
			Source:   db.SourceAccounting,
		})
		require.NoError(t, err)
		mux := newTestMux(t, sqlDB)

		rec := do(t, mux, "GET", "/dl/invoice/"+hash)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestIndexHandler(t *testing.T) {
	t.Run("renders the index page", func(t *testing.T) {
		mux := newTestMux(t, openTestDB(t))

		rec := do(t, mux, "GET", "/")

		require.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html"),
			"unexpected Content-Type %q", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "<html")
	})

	t.Run("renders the index page with the seeded items", func(t *testing.T) {
		sqlDB := openTestDB(t)
		seedExpenseWithFile(t, sqlDB, "66eda6344b41c38804f77fc1", "66eda634eb168575f218d58c", "facture-2024-09.pdf", "content")
		mux := newTestMux(t, sqlDB)

		rec := do(t, mux, "GET", "/")

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "SARL SMF SERVICES - CONTRAT MAINTENANCE")
	})

	t.Run("an unknown filter returns 400, not 500", func(t *testing.T) {
		mux := newTestMux(t, openTestDB(t))

		rec := do(t, mux, "GET", "/?filter=nonsense")

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html"),
			"unexpected Content-Type %q", rec.Header().Get("Content-Type"))
	})

	t.Run("the known filters return 200", func(t *testing.T) {
		mux := newTestMux(t, openTestDB(t))

		for _, filter := range []string{"expenses", "missions", "visits", "ag"} {
			t.Run(filter, func(t *testing.T) {
				rec := do(t, mux, "GET", "/?filter="+filter)

				assert.Equal(t, http.StatusOK, rec.Code)
			})
		}
	})

	t.Run("a non-GET request returns 405", func(t *testing.T) {
		mux := newTestMux(t, openTestDB(t))

		rec := do(t, mux, "POST", "/")

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}

func TestKeyedMutex(t *testing.T) {
	// waitFor fails the test rather than letting it hang forever.
	waitFor := func(t *testing.T, c <-chan struct{}, msg string) {
		t.Helper()
		select {
		case <-c:
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out: %s", msg)
		}
	}

	t.Run("two lockers of the same key are serialised", func(t *testing.T) {
		k := &keyedMutex{}

		unlock := k.Lock("same-key")

		acquired := make(chan struct{})
		go func() {
			unlock := k.Lock("same-key")
			close(acquired)
			unlock()
		}()

		// The second locker must not get through while the first holds the key.
		select {
		case <-acquired:
			t.Fatal("the second Lock on the same key should have blocked")
		case <-time.After(5 * time.Millisecond):
		}

		unlock()
		waitFor(t, acquired, "the second Lock should have gone through once the first was released")
	})

	t.Run("two different keys do not block each other", func(t *testing.T) {
		k := &keyedMutex{}

		unlock := k.Lock("key-a")
		defer unlock()

		done := make(chan struct{})
		go func() {
			unlockB := k.Lock("key-b")
			unlockB()
			close(done)
		}()

		waitFor(t, done, "locking a different key should not have blocked")
	})

	t.Run("concurrent lockers of the same key never overlap", func(t *testing.T) {
		k := &keyedMutex{}

		const goroutines = 50
		counter := 0 // Deliberately not atomic: -race catches any overlap.
		var wg sync.WaitGroup
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				unlock := k.Lock("hot-key")
				defer unlock()
				counter++
			}()
		}

		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		waitFor(t, done, "the goroutines should all have finished")

		assert.Equal(t, goroutines, counter)
	})
}
