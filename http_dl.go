package main

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/maelvls/foncia/db"
)

// documentLookups maps the <type> segment of /dl/<type>/<id>/<filename> to the
// lookup that turns that id into a path on disk. The four lookups used to be
// four near-identical `case` arms in the handler.
//
// The /invoice endpoint historically relies on hash files, which is why a
// second endpoint /invoiceid was added to support invoice IDs.
var documentLookups = map[string]func(ctx context.Context, sqlDB *sql.DB, id string) (string, error){
	"invoice": func(ctx context.Context, sqlDB *sql.DB, id string) (string, error) {
		expenses, err := db.GetExpensesByHashFileDB(ctx, sqlDB, id)
		if err != nil {
			return "", fmt.Errorf("while getting expense by hash file: %w", err)
		}
		if len(expenses) == 0 {
			return "", fmt.Errorf("no expense with hash file %q", id)
		}
		return expenses[0].FilePath, nil
	},
	"invoiceid": func(ctx context.Context, sqlDB *sql.DB, id string) (string, error) {
		expenses, err := db.GetExpensesByInvoiceID(ctx, sqlDB, id)
		if err != nil {
			return "", fmt.Errorf("while getting expense by invoice ID: %w", err)
		}
		// This used to test `expenses == nil`, but the query returns an empty
		// non-nil slice when nothing matches, so an unknown invoice ID made the
		// handler panic on expenses[0].
		if len(expenses) == 0 {
			return "", fmt.Errorf("no expense with invoice ID %q", id)
		}
		return expenses[0].FilePath, nil
	},
	"contract": func(ctx context.Context, sqlDB *sql.DB, id string) (string, error) {
		doc, err := db.GetSupplierContractByHashFileDB(ctx, sqlDB, id)
		if err != nil {
			return "", fmt.Errorf("while getting contract by hash file: %w", err)
		}
		return doc.FilePath, nil
	},
	"doc": func(ctx context.Context, sqlDB *sql.DB, id string) (string, error) {
		doc, err := db.GetAccountDocumentByHashFileDB(ctx, sqlDB, id)
		if err != nil {
			return "", fmt.Errorf("while getting account document by hash file: %w", err)
		}
		return doc.FilePath, nil
	},
}

// downloadLocks serialises the on-demand downloads of a given document so that
// two simultaneous clicks don't write the same .part file at the same time.
var downloadLocks = &keyedMutex{}

// keyedMutex hands out one mutex per key. Callers must call the returned func
// to release. Keys are never removed, which is fine here: the number of
// documents is in the hundreds.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func (k *keyedMutex) Lock(key string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*sync.Mutex)
	}
	mu, ok := k.m[key]
	if !ok {
		mu = &sync.Mutex{}
		k.m[key] = mu
	}
	k.mu.Unlock()

	mu.Lock()
	return mu.Unlock
}
