package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
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

// errNotDownloaded means that the document is known but that its file isn't on
// disk, and that it can't be downloaded on demand either.
var errNotDownloaded = errors.New("this file hasn't been downloaded yet")

// resolveDocument returns the path on disk of the document that
// /dl/<typ>/<id> points to. It is shared by the /dl handler and the MCP
// read_document tool.
func resolveDocument(ctx context.Context, sqlDB *sql.DB, client *http.Client, invoicesDir, typ, id string) (string, error) {
	lookup, known := documentLookups[typ]
	if !known {
		return "", fmt.Errorf("unknown document type %q, must be one of invoice, invoiceid, contract, doc", typ)
	}

	filePath, err := lookup(ctx, sqlDB, id)
	if err != nil {
		return "", err
	}

	// The PDF isn't necessarily on disk: unless --download-ag-documents is
	// set, the general assembly documents are only indexed, not downloaded,
	// since some of the convocations weigh tens of megabytes. We used to
	// send the browser to the pre-signed URL that Foncia hands out, but
	// that makes the link depend on the API being reachable and on our
	// token still being valid; when the token had expired, the link simply
	// answered "not found". Let's download the PDF instead, remember where
	// we put it, and serve it from disk from now on.
	if typ == "doc" && (filePath == "" || !fileExists(filePath)) {
		// Two browsers clicking the same never-downloaded document at once
		// would otherwise write the same .part file concurrently. Let the
		// second one wait and then find the file already on disk.
		unlock := downloadLocks.Lock(id)
		defer unlock()

		doc, err := db.GetAccountDocumentByHashFileDB(ctx, sqlDB, id)
		if err != nil {
			return "", fmt.Errorf("while getting account document %q: %w", id, err)
		}
		if doc.FilePath != "" && fileExists(doc.FilePath) {
			return doc.FilePath, nil
		}
		filePath, err = downloadAccountDocument(ctx, sqlDB, client, invoicesDir, doc)
		if err != nil {
			return "", fmt.Errorf("while downloading the document %s: %w", id, err)
		}
	}

	if filePath == "" {
		return "", errNotDownloaded
	}
	return filePath, nil
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
