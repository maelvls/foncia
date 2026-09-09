package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

type MissionOrExpense struct {
	Mission         *db.MissionDB
	Expense         *db.ExpenseDocumentDB
	AccountDocument *db.AccountDocumentDB
}

type tmlpData struct {
	BasePath   string
	SyncStatus string
	NtfyTopic  string
	Items      []MissionOrExpense
	Version    string
	Filter     string
}

var tmpl = template.Must(template.New("base").Parse(indexHTML))

type tmlpErrData struct {
	Error   string
	Version string
}

var tmlpErr = template.Must(template.New("").Parse(errorHTML))

// logRequests logs every incoming request. It wraps the whole mux rather than
// each handler individually.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logutil.Debugf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

// Serve the HTTP UI. This func is blocking and can be unblocked by cancelling
// the context. The `basePath` should always start with a slash and not end with
// a slash. If you want to given an empty base path, don't give "/". Instead,
// give "".
func ServeHTTP(ctx context.Context, db *sql.DB, httpListen net.Listener, client *http.Client, uuid, basePath, invoicesDir string, lastSync func() (time.Time, error), htmlHeader string) error {
	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		return fmt.Errorf("base path must start with a slash or be an empty string")
	}
	if strings.HasSuffix(basePath, "/") {
		return fmt.Errorf("base path must not end with a slash; if you want to give the base path /, give an empty string instead")
	}

	headerContents := headerHTML
	if htmlHeader != "" {
		headerContents = htmlHeader
	}
	_, err := tmpl.New("header").Parse(headerContents)
	if err != nil {
		return fmt.Errorf("while parsing HTML header file %s: %w", *htmlHeaderFile, err)
	}

	// HTTP server to serve the list of missions and expenses.
	// We mount all handlers under basePath using StripPrefix so they work behind a subpath.
	rootMux := http.NewServeMux()
	subMux := http.NewServeMux()
	s := http.Server{
		Handler:           rootMux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		// Close() would cut in-flight downloads off mid-file. Give them a
		// moment to finish instead.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.Shutdown(shutdownCtx)
	}()

	err = addHandlers(subMux, db, client, uuid, basePath, invoicesDir, lastSync)
	if err != nil {
		return fmt.Errorf("while adding handlers: %w", err)
	}

	mountPath := basePath
	if mountPath == "" {
		mountPath = "/"
	}
	// Ensure mount path ends with slash for proper subtree handling.
	if !strings.HasSuffix(mountPath, "/") {
		mountPath += "/"
	}
	rootMux.Handle(mountPath, logRequests(onlyAllowedUsers(http.StripPrefix(strings.TrimRight(mountPath, "/"), subMux))))

	logutil.Infof("listening on %v", httpListen.Addr())
	logutil.Infof("url: http://%s%s", httpListen.Addr(), basePath)

	err = s.Serve(httpListen)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("while serving HTTP: %w", err)
	}

	return nil
}

func addHandlers(mux *http.ServeMux, sqlDB *sql.DB, client *http.Client, uuid, basePath, invoicesDir string, lastSync func() (time.Time, error)) error {
	// Download a PDF. The /invoice endpoint historically relies on hash files,
	// that's why a second endpoint /invoiceid was added to support invoice IDs.
	//
	//  GET /dl/invoice/660d79500178f21ab3ffc357/invoice.pdf
	//                  <----------------------><---------->
	//                         <hash_file>        <filename> (optional)
	//
	//  GET /dl/contract/660d79500178f21ab3ffc357/contract.pdf
	//                   <----------------------><----------->
	//                          <hash_file>        <filename> (optional)
	//
	//  GET /dl/invoiceid/660d79500178f21ab3ffc357/invoice.pdf
	//                    <----------------------><----------->
	//                          <invoice_id>        <filename> (optional)
	//
	//  GET /dl/doc/660d79500178f21ab3ffc357/invoice.pdf
	//              <----------------------> <---------->
	//              <account_document's id>    <filename> (optional)
	//
	// The 'optional' above means that we return a 302 Redirect if <filename>
	// hasn't been given or is incorrect. That's super useful when the user only
	// has the hash file, then they can get the filename by following the
	// redirect. For example, if the user has the hash file:
	//
	//  GET /dl/invoice/660d79500178f21ab3ffc357     (ending / is optional)
	//
	// the user will redirected to:
	//
	//  GET /dl/invoice/660d79500178f21ab3ffc357/invoice.pdf
	dl := func(w http.ResponseWriter, r *http.Request) {
		typ := r.PathValue("typ")
		hashFile := r.PathValue("hash")
		fileNameInURL := r.PathValue("filename")

		lookup, known := documentLookups[typ]
		if !known {
			logutil.Errorf("invalid download type %q in %q", typ, r.URL.Path)
			http.Error(w, "not found: URL must be of the form /dl/(invoice|invoiceid|contract|doc)/<id>[/<filename>]", http.StatusNotFound)
			return
		}

		filePathReal, err := lookup(r.Context(), sqlDB, hashFile)
		if err != nil {
			logutil.Errorf("while looking up %s %q: %v", typ, hashFile, err)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// The PDF isn't necessarily on disk: unless --download-ag-documents is
		// set, the general assembly documents are only indexed, not downloaded,
		// since some of the convocations weigh tens of megabytes. We used to
		// send the browser to the pre-signed URL that Foncia hands out, but
		// that makes the link depend on the API being reachable and on our
		// token still being valid; when the token had expired, the link simply
		// answered "not found". Let's download the PDF instead, remember where
		// we put it, and serve it from disk from now on.
		if typ == "doc" && (filePathReal == "" || !fileExists(filePathReal)) {
			// Two browsers clicking the same never-downloaded document at once
			// would otherwise write the same .part file concurrently. Let the
			// second one wait and then find the file already on disk.
			unlock := downloadLocks.Lock(hashFile)
			defer unlock()

			doc, err := db.GetAccountDocumentByHashFileDB(r.Context(), sqlDB, hashFile)
			if err != nil {
				logutil.Errorf("while getting account document %q: %v", hashFile, err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if doc.FilePath != "" && fileExists(doc.FilePath) {
				filePathReal = doc.FilePath
			} else {
				filePathReal, err = downloadAccountDocument(r.Context(), sqlDB, client, invoicesDir, doc)
				if err != nil {
					logutil.Errorf("while downloading the document %s: %v", hashFile, err)
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
			}
		}

		// path.Base("") returns ".", and http.Redirect cleans that away, which
		// means an empty file path used to make us redirect to the very URL
		// that was requested: an infinite redirect loop. Let's tell the truth
		// instead.
		if filePathReal == "" {
			logutil.Errorf("no file on disk for %q", r.URL.Path)
			http.Error(w, "not found: this file hasn't been downloaded yet", http.StatusNotFound)
			return
		}

		// Let's redirect if the file path in the URL is not the same as the
		// real file path. The filePath may contain a relative path, so we only
		// keep the filename and remove the directory part.
		fileNameReal := path.Base(filePathReal)
		if fileNameInURL != fileNameReal {
			http.Redirect(w, r, basePath+"/dl/"+typ+"/"+hashFile+"/"+fileNameReal, http.StatusFound)
			return
		}

		// These PDFs are private to the co-owners; make sure no shared proxy
		// caches them on the way out.
		w.Header().Set("Cache-Control", "private, max-age=300")
		logutil.Infof("serving file %q for %s", filePathReal, r.RemoteAddr)
		http.ServeFile(w, r, filePathReal)
	}
	mux.HandleFunc("GET /dl/{typ}/{hash}", dl)
	mux.HandleFunc("GET /dl/{typ}/{hash}/{filename...}", dl)

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		filterParam := r.URL.Query().Get("filter")

		const (
			filterShowAll  = ""
			filterExpenses = "expenses"
			filterMissions = "missions"
			filterVisits   = "visits" // Account documents with the category "reportVisit"
			filterAG       = "ag"     // Account documents attached to a general assembly.
		)

		var f filter
		switch filterParam {
		case filterShowAll:
			f = filter{} // Zero value = show all.
		case filterExpenses:
			f = filter{HideExpenses: false, HideMissions: true, HideDocs: true}
		case filterMissions:
			f = filter{HideExpenses: true, HideMissions: false, HideDocs: true}
		case filterVisits:
			f = filter{HideExpenses: true, HideMissions: true, HideDocs: false,
				DocCategories: []db.DocumentCategory{db.DocumentCategoryReportVisit}}
		case filterAG:
			f = filter{HideExpenses: true, HideMissions: true, HideDocs: false,
				DocCategories: db.GeneralAssemblyCategories}
		default:
			renderErr(w, http.StatusBadRequest, fmt.Sprintf("Invalid filter: %q", filterParam))
			return
		}

		filteredItems, err := fetchFromDB(ctx, sqlDB, f)
		if err != nil {
			logutil.Errorf("while listing: %v", err)
			renderErr(w, http.StatusInternalServerError, "Erreur interne, voir les logs du serveur.")
			return
		}

		var statusMsg string
		when, err := lastSync()
		switch {
		// A failed sync is worth reporting even when we have no timestamp for
		// it; this used to be hidden behind the "never synced" case.
		case err != nil && when.IsZero():
			statusMsg = fmt.Sprintf("La dernière synchro a échoué. Erreur : %v", err)
		case err != nil:
			statusMsg = fmt.Sprintf("La dernière synchro a échoué il y a %s. Erreur : %v", time.Since(when).Truncate(time.Second), err)
		case when.IsZero():
			statusMsg = "Aucune synchro n'a été faite."
		default:
			statusMsg = fmt.Sprintf("La dernière synchro a réussi il y a %s.", time.Since(when).Truncate(time.Second))
		}

		// Render into a buffer first. Writing straight to the ResponseWriter
		// commits a 200 as soon as the first byte goes out, so a template that
		// failed halfway used to be served as a successful but truncated page.
		var page bytes.Buffer
		err = tmpl.Execute(&page, tmlpData{
			BasePath:   basePath,
			SyncStatus: statusMsg,
			NtfyTopic:  *ntfyTopic,
			Items:      filteredItems,
			Version:    version + " (" + date + ")",
			Filter:     filterParam,
		})
		if err != nil {
			logutil.Errorf("executing template: %v", err)
			renderErr(w, http.StatusInternalServerError, "Erreur interne, voir les logs du serveur.")
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := page.WriteTo(w); err != nil {
			logutil.Errorf("writing the page: %v", err)
		}
	})

	mux.HandleFunc("GET /coowners", coownersEndpoint(client, uuid))

	return nil
}

// Zero value = show all.
type filter struct {
	HideExpenses bool
	HideMissions bool
	HideDocs     bool

	// When non-empty, only the account documents having one of these categories
	// are shown. Empty means "all categories".
	DocCategories []db.DocumentCategory
}

func fetchFromDB(ctx context.Context, sqlDB *sql.DB, f filter) ([]MissionOrExpense, error) {
	var missions []db.MissionDB
	var err error

	if !f.HideMissions {
		missions, err = db.GetMissionsDB(ctx, sqlDB)
		if err != nil {
			return nil, fmt.Errorf("while listing missions: %w", err)
		}
	}

	var expenses []db.ExpenseDocumentDB
	if !f.HideExpenses {
		expenses, err = db.GetExpensesDB(ctx, sqlDB)
		if err != nil {
			return nil, fmt.Errorf("while listing expenses: %w", err)
		}
	}

	var accDocs []db.AccountDocumentDB
	if !f.HideDocs {
		accDocs, err = db.GetAccountDocumentsDB(ctx, sqlDB)
		if err != nil {
			return nil, fmt.Errorf("while listing account documents: %w", err)
		}
		accDocs = keepCategories(accDocs, f.DocCategories)
	}

	combined := combineAndSort(missions, expenses, accDocs)
	return combined, nil
}

// keepCategories keeps the documents whose category is in `categories`. An
// empty `categories` means "keep everything".
// downloadAccountDocument downloads the PDF of an account document to
// invoicesDir and records where it landed in the database, so that the next
// requests are served straight from disk without touching the Foncia API. It
// returns the path of the file on disk.
func downloadAccountDocument(ctx context.Context, sqlDB *sql.DB, client *http.Client, invoicesDir string, doc db.AccountDocumentDB) (string, error) {
	// I found that the graphql query 'getDocumentURL' returns an empty URL if
	// the hashFile is empty.
	if doc.HashFile == "" {
		return "", fmt.Errorf("the document %s has no hash file, so it can't be downloaded", doc.ID)
	}

	filename, fileURL, err := api.GetDocumentURL(ctx, client, graphqlURL, doc.HashFile)
	if err != nil {
		return "", fmt.Errorf("while getting the URL of the document: %w", err)
	}
	filePath := path.Join(invoicesDir, filename)

	if !fileExists(filePath) {
		// The pre-signed URL is authenticated with one of its query parameters,
		// so an unauthenticated client is enough to download it.
		err = api.Download(ctx, &http.Client{Timeout: 5 * time.Minute}, fileURL, filePath)
		if err != nil {
			return "", fmt.Errorf("while downloading the document: %w", err)
		}
		logutil.Infof("downloaded the document %s to %q", doc.ID, filePath)
	}

	doc.FilePath = filePath
	err = db.UpsertAccountDocumentsWithDB(ctx, sqlDB, []db.AccountDocumentDB{doc})
	if err != nil {
		// The PDF is on disk, so let's still serve it; we will just have to
		// look its URL up again on the next request.
		logutil.Errorf("while remembering the path of the document %s: %v", doc.ID, err)
	}

	return filePath, nil
}

func keepCategories(docs []db.AccountDocumentDB, categories []db.DocumentCategory) []db.AccountDocumentDB {
	if len(categories) == 0 {
		return docs
	}
	keep := make(map[db.DocumentCategory]struct{}, len(categories))
	for _, c := range categories {
		keep[c] = struct{}{}
	}
	var kept []db.AccountDocumentDB
	for _, d := range docs {
		if _, found := keep[d.Category]; found {
			kept = append(kept, d)
		}
	}
	return kept
}

func combineAndSort(missions []db.MissionDB, expenses []db.ExpenseDocumentDB, accDocs []db.AccountDocumentDB) []MissionOrExpense {
	// Combine them.
	var combined []MissionOrExpense
	for _, m := range missions {
		m := m
		combined = append(combined, MissionOrExpense{Mission: &m})
	}
	for _, e := range expenses {
		e := e
		combined = append(combined, MissionOrExpense{Expense: &e})
	}
	for _, a := range accDocs {
		a := a
		combined = append(combined, MissionOrExpense{AccountDocument: &a})
	}

	sort.Slice(combined, func(i, j int) bool {
		di, dj := time.Time{}, time.Time{}
		if combined[i].Mission != nil {
			di = combined[i].Mission.StartedAt
		}
		if combined[i].Expense != nil {
			di = combined[i].Expense.Date
		}
		if combined[i].AccountDocument != nil {
			di = combined[i].AccountDocument.CreatedAt
		}

		if combined[j].Mission != nil {
			dj = combined[j].Mission.StartedAt
		}
		if combined[j].Expense != nil {
			dj = combined[j].Expense.Date
		}
		if combined[j].AccountDocument != nil {
			dj = combined[j].AccountDocument.CreatedAt
		}
		return di.After(dj)
	})

	return combined
}

// renderErr writes an error page. The status and the Content-Type have to be
// set before the body is written, which the call sites used to get wrong. The
// message is shown to the user, so keep internal error text out of it.
func renderErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := tmlpErr.Execute(w, tmlpErrData{Error: msg, Version: version}); err != nil {
		logutil.Errorf("executing error template: %v", err)
	}
}

// onlyAllowedUsers is defence in depth behind the OAuth-terminating reverse
// proxy. The pages list the co-owners' names and postal addresses, and today
// nothing in this process checks who is asking: if the proxy were ever
// misconfigured or bypassed, everything would be served to anyone.
//
// It is off unless --allowed-users is given, so the default behaviour is
// unchanged. Check what your proxy actually sets before turning it on, and set
// --auth-header to match; the proxy MUST also strip that header from incoming
// requests, otherwise a client can simply send it themselves.
func onlyAllowedUsers(next http.Handler) http.Handler {
	allowed := make(map[string]bool)
	for _, u := range strings.Split(*allowedUsers, ",") {
		u = strings.TrimSpace(strings.ToLower(u))
		if u != "" {
			allowed[u] = true
		}
	}
	if len(allowed) == 0 {
		return next
	}

	logutil.Infof("restricting access to %d user(s) based on the %s header", len(allowed), *authHeader)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := strings.TrimSpace(strings.ToLower(r.Header.Get(*authHeader)))
		if user == "" || !allowed[user] {
			logutil.Errorf("refusing request from %s: %s is %q", r.RemoteAddr, *authHeader, user)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
