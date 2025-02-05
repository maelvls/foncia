package main

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cloudmailin/cloudmailin-go"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

type MissionOrExpense struct {
	Mission *db.MissionDB
	Expense *db.ExpenseDocumentDB
}

type tmlpData struct {
	BasePath   string
	SyncStatus string
	NtfyTopic  string
	Items      []MissionOrExpense
	Version    string
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
					<td>{{ .Kind }} {{ .Number }}</br><small>{{ .Status }}</small></td>
					<td>{{.Label}}</td>
					<td><small>{{.Description}}</small></td>
					<td>
						<small>
							{{range .WorkOrders}}
								{{.Number}}
								{{.Label}}
								{{.RepairDateStart.Format "02/01/2006"}}–{{.RepairDateEnd.Format "02/01/2006"}}
								{{.Supplier.Name}}
								{{.Supplier.Activity}}</br>
								{{range .Supplier.Documents}}
									(<small><a href="{{$.BasePath}}/dl/contract/{{.HashFile}}/{{.Filename}}">{{.Filename}}</a></small>)
								{{end}}
							{{end}}
						</small>
					</td>
				</tr>
				{{end}}
				{{with .Expense}}
				<tr id="{{or .HashFile .InvoiceID}}">
					<td><a href="{{$.BasePath}}#{{ or .HashFile .InvoiceID }}">{{.Date.Format "02 Jan 2006"}}</a></td>
					<td>Facture</td>
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
func ServeHTTP(ctx context.Context, db *sql.DB, httpListen net.Listener, basePath string, lastSync func() (time.Time, error), htmlHeader string) error {
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

	err = addHandlers(mux, db, basePath, lastSync)
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

func addHandlers(mux *http.ServeMux, sqlDB *sql.DB, basePath string, lastSync func() (time.Time, error)) error {
	// Download a PDF. The /invoice endpoint historically relies on hash files,
	// that's why a second endpoint /invoiceid was added to support invoice IDs.
	//
	//  GET /dl/invoice/660d79500178f21ab3ffc357/invoice.pdf
	//                  <----------------------> <--------->
	//                         <hash_file>        <filename>
	//
	//  GET /dl/contract/660d79500178f21ab3ffc357/contract.pdf
	//                   <----------------------> <---------->
	//                          <hash_file>        <filename>
	//
	//  GET /dl/invoiceid/660d79500178f21ab3ffc357/invoice.pdf
	//                    <----------------------> <---------->
	//                          <invoice_id>        <filename>
	mux.HandleFunc("/dl/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get filename and hash file.
		path, found := strings.CutPrefix(r.URL.Path, "/dl/")
		if !found {
			logutil.Errorf("was expecting a path like /dl/(invoice|contract)/<hash_file>/<filename> but got %q", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		parts := strings.SplitN(path, "/", 3)
		if len(parts) != 3 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		typ, hashFile, _ := parts[0], parts[1], parts[2]

		switch typ {
		case "invoice":
			expense, err := db.GetExpenseByHashFileDB(context.Background(), sqlDB, hashFile)
			if err != nil {
				logutil.Errorf("while getting expense by hash file: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.ServeFile(w, r, expense.FilePath)
		case "invoiceid":
			expense, err := db.GetExpenseByInvoiceID(context.Background(), sqlDB, hashFile)
			if err != nil {
				logutil.Errorf("while getting expense by invoice ID: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.ServeFile(w, r, expense.FilePath)
		case "contract":
			doc, err := db.GetSupplierContractByHashFileDB(context.Background(), sqlDB, hashFile)
			if err != nil {
				logutil.Errorf("while getting document by hash file: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.ServeFile(w, r, doc.FilePath)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))

	mux.HandleFunc("/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		missions, err := db.GetMissionsDB(context.Background(), sqlDB)
		if err != nil {
			logutil.Errorf("while listing interventions: %v", err)

			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{
				Error:   fmt.Sprintf("Error while listing interventions: %s", err),
				Version: version,
			})

			return
		}

		expenses, err := db.GetExpensesDB(context.Background(), sqlDB)
		if err != nil {
			logutil.Errorf("while listing expenses: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{
				Error:   fmt.Sprintf("Error while listing expenses: %s", err),
				Version: version,
			})
			return
		}

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

		sort.Slice(combined, func(i, j int) bool {
			di, dj := time.Time{}, time.Time{}
			if combined[i].Mission != nil {
				di = combined[i].Mission.StartedAt
			}
			if combined[i].Expense != nil {
				di = combined[i].Expense.Date
			}
			if combined[j].Mission != nil {
				dj = combined[j].Mission.StartedAt
			}
			if combined[j].Expense != nil {
				dj = combined[j].Expense.Date
			}
			return di.After(dj)
		})

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
			Items:      combined,
			Version:    version + " (" + date + ")"},
		)
		if err != nil {
			logutil.Errorf("executing template: %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	}))

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
