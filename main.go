package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/maelvls/foncia/logutil"
)

var (
	// EnableDebug enables debugFlag logs.
	debugFlag = flag.Bool("debug", false, "Enable debug logs, including equivalent curl commands.")

	serveBasePath = flag.String("basepath", "", "Base path to serve the API on. For example, if set to /api, the API will be served on /api/interventions. Useful for reverse proxies. Must start with a slash.")
	serveAddr     = flag.String("addr", "0.0.0.0:8080", "Address and port to serve the server on.")
	serveBaseURL  = flag.String("baseurl", "", "Domain on which the server is running. Used to generate URLs in Ntfy notifications. If empty, --addr is used.")
	dbOnly        = flag.Bool("db-only", false, "When set, no HTTP request is made, and everything is fetched from the DB.")
	dbPath        = flag.String("db", "foncia.sqlite", "Path to the sqlite3 database. You can use ':memory:' if you don't want to save the database.")
	ntfyTopic     = flag.String("ntfy-topic", "", "Topic to send notifications to using https://ntfy.sh/.")
	invoicesDir   = flag.String("invoices-dir", "invoices", "Directory to save invoices to. Will be created if it doesn't exist.")

	// In order to test the Ntfy integration, you can use --sync-period=10s and
	// manually remove the last item from the DB:
	//
	//  go run . rm-last-expense
	//  go run . rm-last-mission
	syncPeriod = flag.Duration("sync-period", 10*time.Minute, "Period at which to sync with the live API.")

	versionFlag = flag.Bool("version", false, "Print the version and exit.")
)

var (
	// version is the version of the binary. It is set at build time.
	version = "unknown"
	date    = "unknown"
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				version = setting.Value
			}
			if setting.Key == "vcs.time" {
				date = setting.Value
			}
		}
	}
}

func main() {
	flag.Parse()
	if *debugFlag {
		logutil.EnableDebug = true
		logutil.Debugf("debug output enabled")
	}

	switch flag.Arg(0) {
	case "version":
		fmt.Println(version)
	case "serve":
		logutil.Infof("version: %s (%s)", version, date)
		username, password := getCreds()

		path := *dbPath
		logutil.Debugf("using sqlite3 database file %q", path)

		err := createDB(context.Background(), path)
		if err != nil {
			logutil.Errorf("while creating schema: %v", err)
			os.Exit(1)
		}

		db, err := sql.Open("sqlite", path)
		if err != nil {
			logutil.Errorf("while opening database: %v", err)
			os.Exit(1)
		}

		client, err := authenticatedClient(&http.Client{}, username, password)
		if err != nil {
			logutil.Errorf("while authenticating client: %v", err)
			os.Exit(1)
		}

		m := sync.RWMutex{}
		lastSyncErr := error(nil)
		lastSync := time.Time{}

		writeLastSync := func(err error) {
			m.Lock()
			lastSyncErr = err
			lastSync = time.Now()
			m.Unlock()
		}
		readLastSync := func() (time.Time, error) {
			m.RLock()
			defer m.RUnlock()
			return lastSync, lastSyncErr
		}

		serveBaseURL := *serveBaseURL
		if strings.HasSuffix(serveBaseURL, "/") {
			logutil.Errorf("base URL must not end with a slash, or must be empty")
			os.Exit(1)
		}
		if serveBaseURL == "" {
			serveBaseURL = "http://" + *serveAddr
		}

		go func() {
			// When the database is empty, we do an initial fetch to populate
			// it; since it most likely means that these items aren't new, we
			// don't send Ntfy notifications.
			var skipNotif bool
			empty, err := isEmptyDB(context.Background(), db)
			if err != nil {
				logutil.Errorf("while checking if database is empty: %v", err)
				os.Exit(1)
			}
			if empty {
				skipNotif = true
			}

			for {
				logutil.Debugf("updating database by fetching from live")
				newMissions, newExpenses, err := authFetchSave(client, *invoicesDir, db)
				writeLastSync(err)
				if err != nil {
					logutil.Errorf("while fetching and updating database: %v", err)
				}

				if len(newMissions) > 0 || len(newExpenses) > 0 {
					logutil.Debugf("found %d new missions and %d new expenses", len(newMissions), len(newExpenses))
				} else {
					logutil.Debugf("no new mission and no new expense")
				}
				if skipNotif {
					skipNotif = false
					continue
				}
				for _, e := range newMissions {
					logutil.Infof("new mission: %s", e.Label)
					err := ntfy(*ntfyTopic, ntfyMsg{
						HeaderTags:     "tools",
						HeaderTitle:    "Nouvelle intervention",
						Body:           missionToNtfyBody(e),
						HeaderClick:    serveBaseURL + *serveBasePath + "/interventions#" + e.ID,
						HeaderPriority: "default",
					})
					if err != nil {
						logutil.Errorf("while sending notification: %v", err)
						writeLastSync(err)
					}
				}
				for _, e := range newExpenses {
					logutil.Infof("new expense: %s", e.Label)
					err := ntfy(*ntfyTopic, ntfyMsg{
						HeaderTags:     "money",
						HeaderTitle:    "Nouvelle facture",
						Body:           e.Label + " (" + e.Amount.String() + ")",
						HeaderClick:    serveBaseURL + *serveBasePath + "/interventions#" + e.InvoiceID,
						HeaderPriority: "default",
					})
					if err != nil {
						logutil.Errorf("while sending notification: %v", err)
						writeLastSync(err)
					}
				}

				time.Sleep(*syncPeriod)
			}
		}()

		ServeCmd(db, *serveAddr, *serveBasePath, username, password, readLastSync)
	case "list":
		username, password := getCreds()
		ListCmd(username, password)
	case "rm-last-expense":
		path := *dbPath
		logutil.Debugf("using sqlite3 database file %q", path)

		db, err := sql.Open("sqlite", path)
		if err != nil {
			logutil.Errorf("while opening database: %v", err)
			os.Exit(1)
		}
		err = rmLastExpenseDB(db)
		if err != nil {
			logutil.Errorf("while removing last expense: %v", err)
			os.Exit(1)
		}
	case "rm-last-mission":
		path := *dbPath
		logutil.Debugf("using sqlite3 database file %q", path)

		db, err := sql.Open("sqlite", path)
		if err != nil {
			logutil.Errorf("while opening database: %v", err)
			os.Exit(1)
		}
		err = rmLastMissionDB(db)
		if err != nil {
			logutil.Errorf("while removing last expense: %v", err)
			os.Exit(1)
		}
	case "token":
		username, password := getCreds()
		client := &http.Client{}
		enableDebugCurlLogs(client)
		token, err := getToken(client, username, password)
		if err != nil {
			logutil.Errorf("while authenticating: %v", err)
			os.Exit(1)
		}
		fmt.Println(token)
	case "":
		logutil.Errorf("no command given. Use one of: serve, list, token, version")
	default:
		logutil.Errorf("unknown command %q", flag.Arg(0))
		os.Exit(1)
	}
}

// Example:
//
//	POST https://ntfy.sh/my_topic
//	Content-Type: text/plain
//	Title: Unauthorized access detected
//	Priority: urgent
//	Tags: warning,skull
type ntfyMsg struct {
	HeaderTitle    string // Title of the notification.
	HeaderPriority string // Notif proprity: max/urgent, high, default, low, min.
	HeaderTags     string // Comma-separated emoji shortcodes: warning, skull, etc.
	HeaderClick    string // URL to open when clicking on the notification.
	Body           string // Content of the notification.
}

func missionToNtfyBody(m Mission) string {
	msg := m.Label
	if m.Description != "" {
		msg += ": " + m.Description
	}

	// Add the work orders.
	wos := make([]string, len(m.WorkOrders))
	for _, wo := range m.WorkOrders {
		wos = append(wos, fmt.Sprintf("%s %s", wo.Supplier.Activity, wo.Label))
	}
	if len(wos) > 0 {
		msg += " (" + strings.Join(wos, ", ") + ")"
	}

	return msg
}

// Returns the new entries found.
func authFetchSave(client *http.Client, invoicesDir string, db *sql.DB) ([]Mission, []Expense, error) {
	ctx := context.Background()

	newMissions, err := syncLiveMissionsWithDB(ctx, client, db)
	if err != nil {
		return nil, nil, fmt.Errorf("while saving to database: %v", err)
	}
	newExpenses, err := syncExpensesWithDB(ctx, client, db, invoicesDir)
	if err != nil {
		return nil, nil, fmt.Errorf("while saving to database: %v", err)
	}
	err = syncSuppliersWithDB(ctx, client, db, invoicesDir)
	if err != nil {
		return nil, nil, fmt.Errorf("while saving to database: %v", err)
	}

	return newMissions, newExpenses, nil
}

func getCreds() (string, secret) {
	username := os.Getenv("FONCIA_USERNAME")
	password := secret(os.Getenv("FONCIA_PASSWORD"))
	if username == "" || password == "" {
		logutil.Errorf("FONCIA_USERNAME and FONCIA_PASSWORD must be set.")
		os.Exit(1)
	}
	return username, password
}

type tmlpData struct {
	BasePath   string
	SyncStatus string
	NtfyTopic  string
	Items      []MissionOrExpense
	Version    string
}

var tmpl = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
<title>Interventions</title>
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
	<h1>Interventions et factures TERRA NOSTRA 2</h1>
	<p>Vous pouvez recevoir les notifications sur ordinateur sur <a href="https://ntfy.sh/{{.NtfyTopic}}">https://ntfy.sh/{{.NtfyTopic}}</a> ou en téléchargeant l'app Ntfy et en ajoutant le topic "{{.NtfyTopic}}". <small>Statut : {{.SyncStatus}}</small></p>
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
					<td><a href="{{$.BasePath}}/interventions#{{ .ID }}">{{.StartedAt.Format "02 Jan 2006"}}</a></td>
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
								{{if .Supplier.Document.HashFile}}{{with .Supplier.Document}}
									(<small><a href="{{$.BasePath}}/interventions/dl/contract/{{.HashFile}}/{{.Filename}}">{{.Filename}}</a></small>)
								{{end}}{{end}}
							{{end}}
						</small>
					</td>
				</tr>
				{{end}}
				{{with .Expense}}
				<tr id="{{.InvoiceID}}">
					<td><a href="{{$.BasePath}}/interventions#{{ .InvoiceID }}">{{.Date.Format "02 Jan 2006"}}</a></td>
					<td>Facture</td>
					<td>{{.Label}}</td>
					<td><small>
						{{.Amount}}
					</small></td>
					<td><small><a href="{{$.BasePath}}/interventions/dl/invoice/{{.HashFile}}/{{.Filename}}">{{.Filename}}</a></small></td>
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

// The basePath should always start with a slash and not end with a slash. If
// you want to given an empty base path, don't give "/". Instead, give "".
func ServeCmd(db *sql.DB, serveAddr, basePath, username string, password secret, lastSync func() (time.Time, error)) {
	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		logutil.Errorf("base path must start with a slash or be an empty string")
		os.Exit(1)
	}
	if strings.HasSuffix(basePath, "/") {
		logutil.Errorf("base path must not end with a slash; if you want to give the base path /, give an empty string instead")
		os.Exit(1)
	}

	defaultPath := basePath + "/interventions"

	client := &http.Client{}
	enableDebugCurlLogs(client)

	mux := http.NewServeMux()
	mux.HandleFunc("/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(302)
		w.Header().Set("Location", defaultPath)
		tmlpErr.Execute(w, map[string]interface{}{
			"Error":   fmt.Sprintf(`Please go to %s`, defaultPath),
			"Version": version,
		})
	}))

	// Download the invoice PDF. Example:
	//  GET /interventions/dl/invoice/660d79500178f21ab3ffc357/invoice.pdf
	//  GET /interventions/dl/contract/660d79500178f21ab3ffc357/contract.pdf
	//                                 <hash_file>              <filename>
	mux.HandleFunc("/interventions/dl/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get filename and hash file.
		path, found := strings.CutPrefix(r.URL.Path, "/interventions/dl/")
		if !found {
			logutil.Errorf("was expecting a path like /interventions/dl/(invoice|contract)/<hash_file>/<filename> but got %q", r.URL.Path)
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
			expense, err := getExpenseByHashFileDB(context.Background(), db, hashFile)
			if err != nil {
				logutil.Errorf("while getting expense by hash file: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.ServeFile(w, r, expense.FilePath)
		case "contract":
			doc, err := getDocumentByHashFile(context.Background(), db, hashFile)
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

	mux.HandleFunc("/interventions", logRequest(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		missions, err := getMissionsDB(context.Background(), db)
		if err != nil {
			logutil.Errorf("while listing interventions: %v", err)

			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{
				Error:   fmt.Sprintf("Error while listing interventions: %s", err),
				Version: version,
			})

			return
		}

		expenses, err := getExpensesDB(context.Background(), db)
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

	listner, err := net.Listen("tcp", serveAddr)
	if err != nil {
		logutil.Errorf("while listening: %v", err)
		os.Exit(1)
	}
	logutil.Infof("listening on %v", listner.Addr())
	logutil.Infof("url: http://%s%s", listner.Addr(), defaultPath)

	err = http.Serve(listner, mux)
	if err != nil {
		logutil.Errorf("while listening: %v", err)
		os.Exit(1)
	}
}

// This function comes from an MIT-licensed project from github.com/SgtCoDFish.
func ntfy(topic string, msg ntfyMsg) error {
	client := &http.Client{Timeout: 5 * time.Second}
	// Create request without doing it.

	req, err := http.NewRequest("POST", "https://ntfy.sh/"+topic, strings.NewReader(msg.Body))
	if err != nil {
		return fmt.Errorf("while creating request: %v", err)
	}

	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Title", msg.HeaderTitle)
	req.Header.Set("Priority", msg.HeaderPriority)
	req.Header.Set("Tags", msg.HeaderTags)
	req.Header.Set("Click", msg.HeaderClick)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("while sending request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1<<20) // Max. 1MiB.
		n, _ := resp.Body.Read(body)
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, body[:n])
	}

	return nil
}

// Returns the new items.
func syncLiveMissionsWithDB(ctx context.Context, client *http.Client, db *sql.DB) ([]Mission, error) {
	uuid, err := GetAccountUUID(client)
	if err != nil {
		return nil, fmt.Errorf("while getting account UUID: %v", err)
	}
	missions, err := getMissionsLive(client, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting interventions: %v", err)
	}

	missionsInDB, err := getMissionsDB(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("while getting existing missions: %v", err)
	}
	existsInDB := make(map[string]struct{})
	for _, item := range missionsInDB {
		existsInDB[item.ID] = struct{}{}
	}
	var newMissions []Mission
	for _, m := range missions {
		_, already := existsInDB[m.ID]
		if already {
			continue
		}
		newMissions = append(newMissions, m)
		logutil.Debugf("found new mission: %+v", m)
	}

	workOrders := make(map[string][]WorkOrder) // missionID -> work orders

	// Since HTTP request per new mission is made, and there may be 200-300
	// missions, let's do them in batches of 20 so that we can save to DB in
	// regularly so we don't lose all the work if the program crashes (takes a
	// lot of time partly because Synology's disk is slow, partly because there
	// are 200-300 HTTP calls to be made).
	batchSize := 20
	i := 0
	err = DoInBatches(batchSize, newMissions, func(batch []Mission) error {
		i++
		logutil.Debugf("batch %d", i)

		for _, mission := range batch {
			orders, err := getWorkOrdersLive(client, uuid, mission.ID)
			if err != nil {
				return fmt.Errorf("while getting work orders from API: %v", err)
			}
			workOrders[mission.ID] = orders
		}

		logutil.Debugf("saving work orders for %d missions to DB", len(batch))
		missionIDs := make([]string, len(batch))
		for _, m := range batch {
			missionIDs = append(missionIDs, m.ID)
		}

		err = saveWorkOrdersToDB(ctx, db, missionIDs, workOrders)
		if err != nil {
			return fmt.Errorf("while saving work orders: %v", err)
		}

		logutil.Debugf("saving %d missions to DB", batch)
		err = saveMissionsToDB(ctx, db, batch...)
		if err != nil {
			return fmt.Errorf("while saving missions: %v", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return newMissions, nil
}

// Returns new expenses.
func syncExpensesWithDB(ctx context.Context, client *http.Client, db *sql.DB, invoicesDir string) ([]Expense, error) {
	// Create dir if missing.
	err := os.MkdirAll(invoicesDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("while creating directory: %v", err)
	}

	uuid, err := GetAccountUUID(client)
	if err != nil {
		return nil, fmt.Errorf("while getting account UUID: %v", err)
	}
	var expensesLive []Expense
	expensesLive, err = getExpensesCurrentLive(client, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting expenses: %v", err)
	}
	periods, err := getAccountingPeriodsLive(client, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting accounting periods: %v", err)
	}
	for _, period := range periods {
		cur, err := getBuildingAccountingRGDDLive(client, uuid, period.ID)
		if err != nil {
			return nil, fmt.Errorf("while getting building accounting RGDD: %v", err)
		}
		expensesLive = append(expensesLive, cur...)
	}

	// Remove duplicates based on the label + date.
	seen := make(map[string]struct{})
	var expensesLiveUnique []Expense
	for _, e := range expensesLive {
		key := e.Label + e.Date.Format(time.RFC3339)
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		expensesLiveUnique = append(expensesLiveUnique, e)
	}
	expensesLive = expensesLiveUnique

	expensesInDB, err := getExpensesDB(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("while getting existing expenses: %v", err)
	}
	existsInDB := make(map[time.Time]Expense)
	invoiceIDToExpense := make(map[string]Expense)
	for _, item := range expensesInDB {
		existsInDB[item.Date] = item
		if item.InvoiceID != "" {
			invoiceIDToExpense[item.InvoiceID] = item
		}
	}

	var newExpenses []Expense
	// Save the invoice PDFs to disk.
	err = DoInBatches(20, expensesLive, func(expensesBatch []Expense) error {
		var expensesBatchUpdated []Expense
		for _, e := range expensesBatch {
			// I noticed that certain expenses have an invoiceID but no PDF
			// document attached, and that appears to be the case when the
			// hashFile is empty. So I skip downloading when there is no
			// invoiceID or when the hashFile is empty.
			if e.InvoiceID == "" || e.HashFile == "" {
				continue
			}

			// No need to download if it is already present on disk.
			expenseInDB, isInDB := invoiceIDToExpense[e.InvoiceID]
			if isInDB && fileExists(expenseInDB.FilePath) {
				continue
			}
			if !isInDB {
				logutil.Debugf("expense %s with invoice_id %q not found in DB", e.Date.Format(time.RFC3339), e.InvoiceID)
			}
			if isInDB && !fileExists(expenseInDB.FilePath) {
				logutil.Debugf("file %q not found, downloading invoice %q", expenseInDB.FilePath, e.InvoiceID)
			}

			invoiceURL, err := getInvoiceURL(client, e.InvoiceID)
			if err != nil {
				return fmt.Errorf("while getting invoice URL: %v", err)
			}
			if invoiceURL == "" {
				logutil.Infof("no invoice URL found for invoice ID %q, skipping download. Expense: %+v", e.InvoiceID, e)
				continue
			}
			e.FilePath, err = download(invoiceURL, invoicesDir)
			if err != nil {
				return fmt.Errorf("while downloading invoice: %v", err)
			}

			expensesBatchUpdated = append(expensesBatchUpdated, e)
		}

		var newExpensesInBatch, changedExpencesInBatch []Expense
		for _, expInBatch := range expensesBatchUpdated {
			expDB, found := existsInDB[expInBatch.Date]
			if !found {
				newExpensesInBatch = append(newExpensesInBatch, expInBatch)
				logutil.Debugf("found new expense %q: %s", expInBatch.Date, expInBatch.Label)
				continue
			}

			// Many expenses don't have an invoice PDF attached for a couple of
			// weeks. That's why we want to update the invoice_id if we found
			// that it changed. Note that some fields are unique to the database
			// Expense (Filename, FilePath), that's why we don't compare them.
			// The date and label are used as keys, so they are not compared.
			if expDB.InvoiceID != expInBatch.InvoiceID ||
				expDB.Amount != expInBatch.Amount ||
				expDB.HashFile != expInBatch.HashFile {
				changedExpencesInBatch = append(changedExpencesInBatch, expInBatch)
				logutil.Debugf("found changed expense %q: %s", expInBatch.Date, expInBatch.Label)
			}
		}

		newExpenses = append(newExpenses, newExpensesInBatch...)

		newOrChanged := append(newExpensesInBatch, changedExpencesInBatch...)
		err = upsertExpensesWithDB(ctx, db, newOrChanged...)
		if err != nil {
			return fmt.Errorf("while saving expenses: %v", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return newExpenses, nil
}

func syncSuppliersWithDB(ctx context.Context, client *http.Client, db *sql.DB, invoicesDir string) error {
	uuid, err := GetAccountUUID(client)
	if err != nil {
		return fmt.Errorf("while getting account UUID: %v", err)
	}

	contracts, err := getCouncilMissionSuppliersLive(client, uuid)
	if err != nil {
		return fmt.Errorf("while getting suppliers: %v", err)
	}

	var suppliers []Supplier
	var documents []Document

	for _, c := range contracts {
		suppliers = append(suppliers, c.Supplier)
		for _, d := range c.Documents {
			fileURL, err := getDocumentURL(client, d.HashFile)
			if err != nil {
				return fmt.Errorf("while getting document URL: %v", err)
			}

			d.SupplierID = c.Supplier.ID
			d.FilePath, err = download(fileURL, invoicesDir)
			if err != nil {
				return fmt.Errorf("while downloading document: %v", err)
			}
			d.Filename = filepath.Base(d.FilePath)

			documents = append(documents, d)
		}
	}

	err = upsertSuppliersToDB(ctx, db, suppliers)
	if err != nil {
		return fmt.Errorf("while saving suppliers: %v", err)
	}

	err = upsertDocumentsWithDB(ctx, db, documents)
	if err != nil {
		return fmt.Errorf("while saving documents: %v", err)
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func DoInBatches[T any](batchSize int, elmts []T, do func([]T) error) error {
	var batch []T

	for i, e := range elmts {
		batch = append(batch, e)

		isLastElmt := i == len(elmts)-1
		batchIsFull := len(batch) == batchSize

		if batchIsFull || isLastElmt {
			err := do(batch)
			if err != nil {
				return fmt.Errorf("while doing in batches: %v", err)
			}
			batch = nil
		}
	}

	return nil
}

func ListCmd(username string, password secret) {
	client, err := authenticatedClient(&http.Client{}, username, password)
	if err != nil {
		logutil.Errorf("while authenticating: %v", err)
		os.Exit(1)
	}

	accUUID, err := GetAccountUUID(client)
	if err != nil {
		logutil.Errorf("while getting account UUID: %v", err)
		os.Exit(1)
	}

	missions, err := getMissionsLive(client, accUUID)
	if err != nil {
		logutil.Errorf("getting interventions: %v", err)
		os.Exit(1)
	}

	// Print the items starting with the oldest one.
	for i := len(missions) - 1; i >= 0; i-- {
		fmt.Printf("%s %s %s %s %s\n",
			missions[i].StartedAt.Format("02 Jan 2006"),
			logutil.Bold(string(missions[i].Kind)),
			logutil.Yel(missions[i].Label),
			func() string {
				if missions[i].Status == "WORK_IN_PROGRESS" {
					return logutil.Red(missions[i].Status)
				} else {
					return logutil.Green(missions[i].Status)
				}
			}(),
			logutil.Gray(missions[i].Description),
		)
	}
}
