package main

import (
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

	"github.com/cloudmailin/cloudmailin-go"
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

var defaultHeaderTmpl = `
<p>
	Notifications: <a href="https://ntfy.sh/{{.NtfyTopic}}">https://ntfy.sh/{{.NtfyTopic}}</a>.
	<small>Statut : {{.SyncStatus}}</small>
</p>
`

var tmpl = template.Must(template.New("base").Parse(`
<!DOCTYPE html>
<html>
<head>
<title>Suivi des factures et ordres de service de la copro TERRA NOSTRA 2</title>
<meta charset="utf-8">
	<style>
		table {
			border-collapse: collapse;
			width: 100%;
			font-family: Arial, sans-serif;
			color: #444;
			font-size: 0.9em;
			border: 1px solid #f2f2f2;
		}

		table th {
			background: #f2f2f2;
			padding: 10px;
			font-weight: bold;
			text-align: left;
			border-top: 1px solid #e6e6e6;
		}

		table td {
			padding: 10px;
			border-top: 1px solid #e6e6e6;
			text-align: left;
		}

		table tr:nth-child(even) {
			background: #f8f8f8;
		}

		table tr:hover {
			background: #f2f2f2;
		}
	</style>
</head>
<body>
	<h1>Suivi des factures et ordres de service de la copro TERRA NOSTRA 2</h1>

	{{ template "header" . }}

	<form action="/" method="GET">
		<input type="radio" id="all" name="filter" value="" {{if eq .Filter ""}}checked{{end}}>
		<label for="all">Tous</label>

		<input type="radio" id="expenses" name="filter" value="expenses" {{if eq .Filter "expenses"}}checked{{end}}>
		<label for="expenses">Factures (compte courant et compte travaux)</label>

		<input type="radio" id="missions" name="filter" value="missions" {{if eq .Filter "missions"}}checked{{end}}>
		<label for="missions">Ordres de mission et ordres de réparation</label>

		<input type="radio" id="visits" name="filter" value="visits" {{if eq .Filter "visits"}}checked{{end}}>
		<label for="visits">Rapports de visite</label>

		<input type="submit" value="Filtrer">
	</form>

	<table>
		<thead>
			<tr>
				<th>Date</th>
				<th>Type et statut</th>
				<th>Label</th>
				<th>Description</th>
				<th>Facture ou ordre de service</th>
			</tr>
		</thead>
		<tbody>
			{{range .Items}}
				{{with .Mission}}
				<tr id="{{ .ID }}">
					<td><a href="{{$.BasePath}}#{{ .ID }}">{{.StartedAt.Format "02 Jan 2006"}}</a></td>
					<td>{{ .KindFrench }} </br><small>{{ .StatusFrench }}</small></td>
					<td>{{.Label}}</td>
					<td><small>{{.Description}}</small></td>
					<td>
						<small>
							{{range .WorkOrders}}
								{{.Number}}
								{{.Label}}
								{{.RepairDateEnd.Format "02/01/2006"}}
								{{.Supplier.Name}}
								{{.Supplier.Activity}}</br>
								{{range .Supplier.Documents}}
									(<small><a href="{{$.BasePath}}/dl/contract/{{.HashFile}}/{{.FilePath}}">{{.FilePath}}</a></small>)
								{{end}}
							{{end}}
						</small>
					</td>
				</tr>
				{{end}}
				{{with .Expense}}
				<tr id="{{or .HashFile .InvoiceID}}">
					<td><a href="{{$.BasePath}}#{{ or .HashFile .InvoiceID }}">{{.Date.Format "02 Jan 2006"}}</a></td>
					<td>Facture
						{{if eq .Source "repairs"}}
							</br>
							<small>(compte travaux)</small>
						{{end}}
						{{if .AccountingKey}}
							</br>
							<small><small>{{.AccountingKey.Allocation}},
							{{.AccountingKey.ExpenseType}}</small></small>
						{{end}}
					</td>
					<td>{{.Label}}</td>
					<td><small>
						{{.Amount}}
					</small></td>
					{{if .FilePath}}
						<td><small>
						{{if .HashFile}}
							<a href="{{$.BasePath}}/dl/invoice/{{.HashFile}}/{{.Filename}}">{{.Filename}}</a>
						{{else if .InvoiceID}}
							<a href="{{$.BasePath}}/dl/invoiceid/{{.InvoiceID}}/{{.Filename}}">{{.Filename}}</a>
						{{end}}
						</small></td>
					{{else if .HashFile}}
						<td><small>PDF en attente de téléchargement</small></td>
					{{else}}
						<td><small>Pas de PDF</small></td>
					{{end}}
				</tr>
				{{end}}
				{{with .AccountDocument}}
				<tr id="{{.ID}}">
					<td><a href="{{$.BasePath}}#{{.ID}}">{{.CreatedAt.Format "02 Jan 2006"}}</a></td>
					<td>Document</td>
					<td>{{.CategoryFrench}}</td>
					<td><small>{{.MimeType}}</small></td>
					{{if .FilePath}}
						<td><small><a href="{{$.BasePath}}/dl/doc/{{.HashFile}}/{{.Filename}}">{{.Filename}}</a></small></td>
					{{else}}
						<td><small>PDF en attente de téléchargement</small></td>
					{{end}}
				</tr>
				{{end}}
			{{end}}
		</tbody>
	</table>
	<div>
		<small>Version: {{.Version}}</small>
	</div>
</body>
</html>
`))

type tmlpErrData struct {
	Error   string
	Version string
}

var tmlpErr = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
<head>
<title>Error</title>
<meta charset="utf-8">
</head>
<body>
	<h1>Error</h1>
	<p>{{.Error}}</p>
	<div>
		<small>Version: {{.Version}}</small>
	</div>
</body>
</html>
`))

func logRequest(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logutil.Debugf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next(w, r)
	}
}

// Serve the HTTP UI. This func is blocking and can be unblocked by cancelling
// the context. The `basePath` should always start with a slash and not end with
// a slash. If you want to given an empty base path, don't give "/". Instead,
// give "".
func ServeHTTP(ctx context.Context, db *sql.DB, httpListen net.Listener, client *http.Client, uuid, basePath string, lastSync func() (time.Time, error), htmlHeader string) error {
	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		return fmt.Errorf("base path must start with a slash or be an empty string")
	}
	if strings.HasSuffix(basePath, "/") {
		return fmt.Errorf("base path must not end with a slash; if you want to give the base path /, give an empty string instead")
	}

	headerContents := defaultHeaderTmpl
	if htmlHeader != "" {
		headerContents = htmlHeader
	}
	_, err := tmpl.New("header").Parse(headerContents)
	if err != nil {
		return fmt.Errorf("while parsing HTML header file %s: %w", *htmlHeaderFile, err)
	}

	// HTTP server to serve the list of missions and expenses.
	mux := http.NewServeMux()
	s := http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	err = addHandlers(mux, db, client, uuid, basePath, lastSync)
	if err != nil {
		return fmt.Errorf("while adding handlers: %w", err)
	}

	logutil.Infof("listening on %v", httpListen.Addr())
	logutil.Infof("url: http://%s%s", httpListen.Addr(), basePath)

	err = s.Serve(httpListen)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("while serving HTTP: %w", err)
	}

	return nil
}

func addHandlers(mux *http.ServeMux, sqlDB *sql.DB, client *http.Client, uuid, basePath string, lastSync func() (time.Time, error)) error {
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
	mux.HandleFunc("/dl/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		logutil.Debugf("download request: %s %s", r.Method, r.URL.Path)
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get filename and hash file.
		urlPath, found := strings.CutPrefix(r.URL.Path, "/dl/")
		if !found {
			logutil.Errorf("was expecting a path like /dl/(invoice|contract)/<hash_file>/<filename> but got %q", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		parts := strings.Split(urlPath, "/")
		var typ, hashFile, fileNameInURL string
		switch len(parts) {
		case 2:
			typ = parts[0]
			hashFile = parts[1]
		case 3:
			typ = parts[0]
			hashFile = parts[1]
			fileNameInURL = parts[2]
		default:
			logutil.Errorf("invalid path %q, must be of: /dl/invoice/<hash_file>, /dl/invoiceid/<hash_file>, /dl/contract/<invoice_id> or /dl/doc/<account_document_id>. It may be followed by /<filename>", r.URL.Path)
			http.Error(w, "not found, URL must be of: /dl/invoice/<hash_file>, /dl/invoiceid/<hash_file>, /dl/contract/<invoice_id> or /dl/doc/<account_document_id>. It may be followed by /<filename>", http.StatusNotFound)
			return
		}

		var filePathReal string
		switch typ {
		case "invoice":
			expenses, err := db.GetExpensesByHashFileDB(context.Background(), sqlDB, hashFile)
			if err != nil || len(expenses) == 0 {
				logutil.Errorf("while getting expense by hash file: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			filePathReal = expenses[0].FilePath
		case "invoiceid":
			expenses, err := db.GetExpensesByInvoiceID(context.Background(), sqlDB, hashFile)
			if err != nil || expenses == nil {
				logutil.Errorf("while getting expense by invoice ID: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			filePathReal = expenses[0].FilePath
		case "contract":
			doc, err := db.GetSupplierContractByHashFileDB(context.Background(), sqlDB, hashFile)
			if err != nil {
				logutil.Errorf("while getting document by hash file: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			filePathReal = doc.FilePath
		case "doc":
			doc, err := db.GetAccountDocumentByHashFileDB(context.Background(), sqlDB, hashFile)
			if err != nil {
				logutil.Errorf("while getting account document by hash file: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			filePathReal = doc.FilePath
		default:
			http.Error(w, "not found, URL must start with either /dl/invoice/, /dl/invoiceid/, /dl/contract/ or /dl/doc/", http.StatusNotFound)
			logutil.Errorf("invalid path %q, must start with /dl/invoice/, /dl/invoiceid/, /dl/contract/ or /dl/doc/", r.URL.Path)
			return
		}

		// Let's redirect if the file path in the URL is not the same as the
		// real file path. The filePath may contain a relative path, so we only
		// keep the filename and remove the directory part.
		fileNameReal := path.Base(filePathReal)
		if fileNameInURL != fileNameReal {
			http.Redirect(w, r, "/dl/"+typ+"/"+hashFile+"/"+fileNameReal, http.StatusFound)
			return
		}

		// Otherwise, let's serve the file.
		logutil.Infof("serving file %q for %s", filePathReal, r.RemoteAddr)
		http.ServeFile(w, r, filePathReal)
	}))

	mux.HandleFunc("/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		filterParam := r.URL.Query().Get("filter")

		const (
			filterShowAll  = ""
			filterExpenses = "expenses"
			filterMissions = "missions"
			filterVisits   = "visits" // Account documents with the category "reportVisit"
		)

		var f filter
		switch filterParam {
		case filterShowAll:
			f = filter{} // Zero value = show all.
		case filterExpenses:
			f = filter{HideExpenses: false, HideMissions: true, HideVisits: true}
		case filterMissions:
			f = filter{HideExpenses: true, HideMissions: false, HideVisits: true}
		case filterVisits:
			f = filter{HideExpenses: true, HideMissions: true, HideVisits: false}
		default:
			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{Error: fmt.Sprintf("Invalid filter: %q", filterParam), Version: version})
			return
		}

		filteredItems, err := fetchFromDB(ctx, sqlDB, f)
		if err != nil {
			logutil.Errorf("while listing: %v", err)

			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{Error: fmt.Sprintf("Error while listing: %s", err), Version: version})

			return
		}

		w.Header().Set("Content-Type", "text/html")

		var statusMsg string
		when, err := lastSync()
		switch {
		case when.IsZero():
			statusMsg = "Aucune synchro n'a été faite."
		case err != nil:
			statusMsg = fmt.Sprintf("La dernière synchro a échoué il y a %s. Erreur : %v", time.Since(when).Truncate(time.Second), err)
		default:
			statusMsg = fmt.Sprintf("La dernière synchro a réussi il y a %s.", time.Since(when).Truncate(time.Second))
		}

		err = tmpl.Execute(w, tmlpData{
			BasePath:   basePath,
			SyncStatus: statusMsg,
			NtfyTopic:  *ntfyTopic,
			Items:      filteredItems,
			Version:    version + " (" + date + ")",
			Filter:     filterParam,
		})
		if err != nil {
			logutil.Errorf("executing template: %v", err)
			return
		}
	}))

	mux.HandleFunc("/coowners", coownersEndpoint(client, uuid))

	mux.HandleFunc("/cloudmailingwebhook", logRequest(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		message, err := cloudmailin.ParseIncoming(r.Body)
		if err != nil {
			http.Error(w, "while parsing message: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}

		// Output the first instance of the message-id in the headers to show
		// that we correctly parsed the message. We could also use the helper
		// message.Headers.MessageID().
		logutil.Infof("received message: message-id %s, sub: %s", message.Headers.MessageID(), message.Headers.Subject())

		tx, err := sqlDB.Begin()
		if err != nil {
			http.Error(w, "while starting transaction: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		logutil.Infof("message: %#v", message)
	}))

	return nil
}

// Zero value = show all.
type filter struct {
	HideExpenses bool
	HideMissions bool
	HideVisits   bool
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
	if !f.HideVisits {
		accDocs, err = db.GetAccountDocumentsDB(ctx, sqlDB)
		if err != nil {
			return nil, fmt.Errorf("while listing account documents: %w", err)
		}
	}

	combined := combineAndSort(missions, expenses, accDocs)
	return combined, nil
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
