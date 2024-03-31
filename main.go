package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/maelvls/foncia/logutil"
	"github.com/sethgrid/gencurl"
	"github.com/shurcooL/graphql"
	"golang.org/x/oauth2"
)

var (
	// EnableDebug enables debugFlag logs.
	debugFlag = flag.Bool("debug", false, "Enable debug logs, including equivalent curl commands.")

	serveBasePath = flag.String("basepath", "", "Base path to serve the API on. For example, if set to /api, the API will be served on /api/interventions. Useful for reverse proxies. Must start with a slash.")
	serveAddr     = flag.String("addr", "0.0.0.0:8080", "Address and port to serve the server on.")
	dbOnly        = flag.Bool("db-only", false, "When set, no HTTP request is made, and everything is fetched from the DB.")
	dbPath        = flag.String("db", "foncia.sqlite", "Path to the sqlite3 database. You can use ':memory:' if you don't want to save the database.")
	ntfyTopic     = flag.String("ntfy-topic", "", "Topic to send notifications to using https://ntfy.sh/.")

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
		if *serveBasePath != "" && !strings.HasPrefix(*serveBasePath, "/") {
			logutil.Errorf("basepath must start with a slash")
			os.Exit(1)
		}
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

		go func() {
			items, err := authFetchSave(&http.Client{}, username, password, db)
			writeLastSync(err)
			if err != nil {
				logutil.Errorf("initial fetch: %v", err)
			}
			logutil.Debugf("initial fetch: %d new items", len(items))

			for {
				time.Sleep(10 * time.Minute)

				logutil.Debugf("updating database by fetching from live")
				newMissions, err := authFetchSave(&http.Client{}, username, password, db)
				writeLastSync(err)
				if err != nil {
					logutil.Errorf("while fetching and updating database: %v", err)
				}
				logutil.Debugf("found %d new items", len(newMissions))
				if len(newMissions) > 0 {
					for _, e := range newMissions {
						logutil.Infof("new: %s", e.Label)
						err := ntfy(*ntfyTopic, fmt.Sprintf("%s: %s", e.Label, e.Description))
						if err != nil {
							logutil.Errorf("while sending notification: %v", err)
							writeLastSync(err)
						}
					}
				}
			}
		}()

		ServeCmd(db, *serveAddr, *serveBasePath, username, password, readLastSync)
	case "list":
		username, password := getCreds()
		ListCmd(username, password)
	case "token":
		username, password := getCreds()
		client := &http.Client{}
		enableDebugCurlLogs(client)
		token, err := Token(client, username, password)
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

// Returns the new entries found.
func authFetchSave(c *http.Client, username string, password secret, db *sql.DB) ([]Mission, error) {
	cl, err := authenticatedClient(c, username, password)
	if err != nil {
		return nil, fmt.Errorf("while authenticating: %v", err)
	}
	newMissions, err := syncLiveMissionsWithDB(context.Background(), cl, db)
	if err != nil {
		return nil, fmt.Errorf("while saving to database: %v", err)
	}
	return newMissions, nil
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
	SyncStatus string
	Items      []Mission
	Version    string
}

var tmpl = template.Must(template.New("").Parse(`<!DOCTYPE html>
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
	<h1>Interventions</h1>
	<p>{{.SyncStatus}}</p>
	<table>
		<thead>
			<tr>
				<th>Started At</th>
				<th>Status</th>
				<th>Label</th>
				<th>Description</th>
				<th>Work Orders</th>
			</tr>
		</thead>
		<tbody>
			{{range .Items}}
			<tr>
				<td>{{.StartedAt.Format "02 Jan 2006"}}</td>
				<td>{{ .Kind }} {{ .Number }}</br><small>{{ .Status }}</small></td>
				<td>{{.Label}}</td>
				<td><small>{{.Description}}</small></td>
				<td>
					<small>
						{{range .WorkOrders}}
							{{.Number}}
							{{.Label}}
							{{.RepairDateStart.Format "02/01/2006"}}–{{.RepairDateEnd.Format "02/01/2006"}}
							{{.SupplierName}}
							{{.SupplierActivity}}</br>
						{{end}}
					</small>
				</td>
			</tr>
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

func createDB(ctx context.Context, path string) error {
	if path == "" {
		return fmt.Errorf("missing required value: path")
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("failed to open database at %q: %w", path, err)
	}

	defer db.Close()

	// number = Foncia's ID for the intervention.
	_, err = db.ExecContext(ctx, `
		create table IF NOT EXISTS missions (
			id TEXT UNIQUE,
			number TEXT,
			kind TEXT,
			label TEXT,
			status TEXT,
			started_at TEXT,             -- time.RFC3339
			description TEXT
		);`)
	if err != nil {
		return fmt.Errorf("failed to create table 'missions': %w", err)
	}
	_, err = db.ExecContext(ctx, `
		create table IF NOT EXISTS work_orders (
			id TEXT UNIQUE,
			mission_id TEXT NOT NULL,
			number TEXT,
			label TEXT,
			repair_date_start TEXT,      -- time.RFC3339
			repair_date_end TEXT,        -- time.RFC3339
			supplier_id TEXT,
			supplier_name TEXT,
			supplier_activity TEXT,
			FOREIGN KEY(mission_id) REFERENCES missions(id)
		);`)
	if err != nil {
		return fmt.Errorf("failed to create table 'work_orders': %w", err)
	}
	_, err = db.ExecContext(ctx, `create index IF NOT EXISTS idx_entries_started_at on missions (started_at);`)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}

	return nil
}

func ServeCmd(db *sql.DB, serveAddr, basePath, username string, password secret, lastSync func() (time.Time, error)) {
	defaultPath := basePath + "/interventions"

	client := &http.Client{}
	enableDebugCurlLogs(client)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(302)
		w.Header().Set("Location", defaultPath)
		tmlpErr.Execute(w, tmlpErrData{
			Error:   fmt.Sprintf(`Nothing here. Go to: %s`, defaultPath),
			Version: version,
		})
	})

	mux.HandleFunc("/interventions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		items, err := getMissionsDB(context.Background(), db)
		if err != nil {
			logutil.Errorf("while listing interventions: %v", err)

			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{
				Error:   fmt.Sprintf("Error while listing interventions: %s", err),
				Version: version,
			})

			return
		}

		w.Header().Set("Content-Type", "text/html")

		var statusMsg string
		when, err := lastSync()
		switch {
		case when.IsZero():
			statusMsg = "No sync has been done yet."
		case err != nil:
			statusMsg = fmt.Sprintf("Last sync failed %s ago: %v", time.Since(when).Truncate(time.Second), err)
		default:
			statusMsg = fmt.Sprintf("Last sync succeeded %s ago", time.Since(when).Truncate(time.Second))
		}

		err = tmpl.Execute(w, tmlpData{
			SyncStatus: statusMsg,
			Items:      items,
			Version:    version + " (" + date + ")"},
		)
		if err != nil {
			logutil.Errorf("executing template: %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	})

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
func ntfy(topic, message string) error {
	client := &http.Client{Timeout: 5 * time.Second}

	ntfyMessage := strings.NewReader(
		fmt.Sprintf("%s", message),
	)

	_, err := client.Post(fmt.Sprintf("https://ntfy.sh/%s", topic), "text/plain", ntfyMessage)
	return err
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
		logutil.Debugf("found new item %q", m.ID)
	}

	// Watch out, one HTTP request per new mission is made here. There may be
	// 200-300 missions, so this may take a while.
	//
	// Let's keep track of which mission IDs have been processed so that we can
	// save to DB in batches. That's because (1) disk is slow on Synology so we
	// need to batchSize, and (2) we don't want to lose all the work if the program
	// crashes.
	batchSize := 20
	var missionIDs []string
	var missionBatch []Mission
	workOrders := make(map[string][]WorkOrder) // missionID -> work orders

	for _, m := range newMissions {
		wo, err := getWorkOrdersLive(client, uuid, m.ID)
		if err != nil {
			return nil, fmt.Errorf("while getting work orders: %v", err)
		}
		workOrders[m.ID] = wo
		missionIDs = append(missionIDs, m.ID)
		missionBatch = append(missionBatch, m)

		if len(missionIDs) < batchSize {
			continue
		}

		logutil.Debugf("saving work orders for %d missions to DB", len(missionBatch))
		err = saveWorkOrdersToDB(ctx, db, missionIDs, workOrders)
		if err != nil {
			return nil, fmt.Errorf("while saving work orders: %v", err)
		}
		missionIDs = nil
		workOrders = make(map[string][]WorkOrder)

		logutil.Debugf("saving %d missions to DB", len(missionBatch))
		err = saveMissionsToDB(ctx, db, missionBatch...)
		if err != nil {
			return nil, fmt.Errorf("while saving missions: %v", err)
		}
		missionBatch = nil
	}

	return newMissions, nil
}

func saveWorkOrdersToDB(ctx context.Context, db *sql.DB, missionIDs []string, workOrdersMap map[string][]WorkOrder) error {
	if len(workOrdersMap) == 0 {
		return nil
	}

	req := "insert into work_orders (id, mission_id, number, label, repair_date_start, repair_date_end, supplier_id, supplier_name, supplier_activity) values "
	var values []interface{}
	for _, missionID := range missionIDs {
		workOrders, found := workOrdersMap[missionID]
		if !found {
			logutil.Debugf("no work orders for mission %q", missionID)
			continue
		}
		for _, w := range workOrders {
			req += "(?, ?, ?, ?, ?, ?, ?, ?, ?),"
			values = append(values, w.ID, missionID, w.Number, w.Label, w.RepairDateStart.Format(time.RFC3339), w.RepairDateEnd.Format(time.RFC3339), w.SupplierID, w.SupplierName, w.SupplierActivity)
		}
	}
	req = strings.TrimSuffix(req, ",")
	_, err := db.ExecContext(ctx, req, values...)
	if err != nil {
		return fmt.Errorf("while inserting work orders: %v", err)
	}

	return nil
}

func saveMissionsToDB(ctx context.Context, db *sql.DB, missions ...Mission) error {
	req := "insert into missions (id, number, kind, label, status, started_at, description) values "
	var values []interface{}
	for _, e := range missions {
		req += "(?, ?, ?, ?, ?, ?, ?),"
		values = append(values, e.ID, e.Number, e.Kind, e.Label, e.Status, e.StartedAt.Format(time.RFC3339), e.Description)
	}
	req = strings.TrimSuffix(req, ",")
	_, err := db.ExecContext(ctx, req, values...)
	if err != nil {
		return fmt.Errorf("while inserting values: %v", err)
	}

	return nil
}

func getMissionsDB(ctx context.Context, db *sql.DB) ([]Mission, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, number, kind, label, status, started_at, description FROM missions ORDER BY started_at DESC")
	if err != nil {
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	var missions []Mission
	for rows.Next() {
		var m Mission
		var startedAt string
		err = rows.Scan(&m.ID, &m.Number, &m.Kind, &m.Label, &m.Status, &startedAt, &m.Description)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
		}

		m.StartedAt, err = time.Parse(time.RFC3339, startedAt)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'started_at': %v", err)
		}
		missions = append(missions, m)
	}

	var missionIDs []string
	for i := range missions {
		missionIDs = append(missionIDs, missions[i].ID)
	}
	workOrderMap, err := getWorkOrdersDB(ctx, db, missionIDs...)
	if err != nil {
		return nil, fmt.Errorf("while getting work orders: %v", err)
	}

	for i := range missions {
		workOrders, found := workOrderMap[missions[i].ID]
		if !found {
			continue
		}
		missions[i].WorkOrders = workOrders
	}
	logutil.Debugf("found %d missions", len(missions))
	return missions, nil
}

func getWorkOrdersDB(ctx context.Context, db *sql.DB, missionIDs ...string) (map[string][]WorkOrder, error) {
	if len(missionIDs) == 0 {
		return nil, nil
	}

	req := "select id, mission_id, number, label, repair_date_start, repair_date_end, supplier_id, supplier_name, supplier_activity from work_orders where mission_id in ("
	var values []interface{}
	for _, id := range missionIDs {
		req += "?,"
		values = append(values, id)
	}
	req = strings.TrimSuffix(req, ",") + ");"
	logutil.Debugf("sql getWorkOrdersDB: %s", req)

	rows, err := db.QueryContext(ctx, req, values...)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	workOrderMap := make(map[string][]WorkOrder)
	for rows.Next() {
		var wo WorkOrder
		var repairDateStart, repairDateEnd string
		var missionID string
		err = rows.Scan(&wo.ID, &missionID, &wo.Number, &wo.Label, &repairDateStart, &repairDateEnd, &wo.SupplierID, &wo.SupplierName, &wo.SupplierActivity)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
		}

		wo.RepairDateStart, err = time.Parse(time.RFC3339, repairDateStart)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'repair_date_start': %v", err)
		}
		wo.RepairDateEnd, err = time.Parse(time.RFC3339, repairDateEnd)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'repair_date_end': %v", err)
		}

		workOrderMap[missionID] = append(workOrderMap[missionID], wo)
	}

	return workOrderMap, nil
}

func authenticatedClient(client *http.Client, username string, password secret) (*http.Client, error) {
	enableDebugCurlLogs(client)

	token, err := Token(client, username, password)
	if err != nil {
		logutil.Errorf("while authenticating: %v", err)
		os.Exit(1)
	}

	client = oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	))
	enableDebugCurlLogs(client)

	return client, nil
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

type Mission struct {
	ID          string      // "64850e8019d5d64c415d13dd"
	Number      string      // "7000YRK51"
	Label       string      // "ATELIER METALLERIE FERRONNERIE - VALIDATION DEVIS "
	Status      string      // "WORK_IN_PROGRESS"
	StartedAt   time.Time   // "2023-04-24T22:00:00.000Z" (time.RFC3339)
	Description string      // "BONJOUR,\n\nVEUILLEZ ENREGISTER LE C02\t\nMERCI CORDIALEMENT"
	Kind        MissionKind // "Incident" | "Repair"
	WorkOrders  []WorkOrder
}

type WorkOrder struct {
	ID               string    // "64850e80df57eb4ade3cf63c"
	Number           string    // "OSMIL802702875"
	Label            string    // "BOUVIER SECURITE INCENDIE - DEMANDE INTERVENTION P"
	RepairDateStart  time.Time // "2022-10-18T22:00:00.000Z"
	RepairDateEnd    time.Time // "2022-10-18T22:00:00.000Z"
	SupplierID       string    // "64850e809b58ffb817f73b20"
	SupplierName     string    // ""
	SupplierActivity string    // "MFEU"
}

type MissionKind string

var (
	Incident MissionKind = "Incident"
	Repair   MissionKind = "Repair"
)

type secret string

func (p secret) String() string {
	return "[redacted]"
}

func (p secret) Raw() string {
	return string(p)
}

// After getting the token, create a client with the following:
//
//	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
//	    &oauth2.Token{AccessToken: token},
//	))
//
// The given client isn't mutated.
func Token(client *http.Client, username string, password secret) (token string, _ error) {
	// Redirects don't make sense for HTML pages. For example, a 302 redirect
	// might actually indicate an error.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("error creating cookie jar: %w", err)
	}
	client.Jar = jar

	// A first request is needed to get the session cookie.
	req, err := http.NewRequest("GET", "https://myfoncia.fr/login", nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("while performing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// The second request is the actual authentication.
	form := url.Values{}
	form.Add("username", username)
	form.Add("_password", password.Raw())
	req, err = http.NewRequest("POST", "https://myfoncia.fr/login_check", strings.NewReader(form.Encode()))
	if err != nil {
		logutil.Errorf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("while performing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 302 {
		logutil.Debugf("authentication: got %d instead of a 302", resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		logutil.Debugf("HTML page was:\n%s", string(bodyBytes))
		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		logutil.Debugf("authentication: no Location header found")
		bodyBytes, _ := io.ReadAll(resp.Body)
		logutil.Debugf("HTML page was:\n%s", string(bodyBytes))
		return "", fmt.Errorf("error getting redirect location: %w", err)
	}
	// The Location header should be:
	// https://my-foncia.fonciamillenium.net?sso=<jwt>
	expected := "https://my-foncia.fonciamillenium.net?sso=<jwt>"
	ssoParam := loc.Query()["sso"]
	if len(ssoParam) != 1 {
		logutil.Debugf("authentication: no 'sso' query parameter found in the Location header. Was redirected to %s instead of expected %s", loc.String(), expected)
		bodyBytes, _ := io.ReadAll(resp.Body)
		logutil.Debugf("HTML page was:\n%s", string(bodyBytes))
		return "", fmt.Errorf("authentication did not go well. No 'sso' query param was found in the Location header. Location header was %s", loc.String())
	}
	jwt := ssoParam[0]
	logutil.Debugf("authentication: got jwt %q", jwt)
	return jwt, nil
}

// DO NOT USE. This function is kept for historical reasons.
func GetInterventionsOld(client *http.Client, coproID string) ([]Mission, error) {
	req, err := http.NewRequest("GET", "https://myfoncia.fr/espace-client/espace-de-gestion/conseil-syndical/interventions/"+coproID, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body: %w", err)
	}
	bodyStr := string(bodyBytes)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code %d with body:\n%s", resp.StatusCode, bodyStr)
	}

	// At this point, we have an HTML page that contains a long JavaScript line
	// that looks like this:
	//
	//  taffyData = [{'id': 'TaffyTableData', 'content': JSON_ARRAY}]
	//
	// The contents of JSON_ARRAY looks like this (I re-wrapped it, but in
	// reality it is on a single line):
	//
	//  [
	//     {
	//       "id": 545075,
	//       "nomFournisseur": "2apf",
	//       "activiteFournisseur": "20 MENUISERIE METAL.SERRURERIE",
	//       "telFournisseur": null,
	//       "date": "09.03.2023",
	//       "description": "BONJOUR,\n\nVEUILLEZ ENREGISTER LE C02\t\nMERCI CORDIALEMENT",
	//       "statut": "V",
	//       "libelleStatut": null,
	//       "document": null,
	//       "monthYear": "Mars 2023",
	//       "monthYearTs": 1677625200,
	//       "timestamp": 1678320000
	//     }
	//   ]

	// The first step is to extract the JSON array from the JavaScript line that
	// starts with "taffyData".
	lookup := "taffyData = [{'id': 'TaffyTableData', 'content':"
	start := strings.Index(bodyStr, lookup)
	if start == -1 {
		logutil.Debugf("HTML page:\n%s", bodyStr)
		return nil, fmt.Errorf("could not find '%s' in the HTML page", lookup)
	}
	end := strings.Index(bodyStr[start:], "\n")
	if end == -1 {
		logutil.Debugf("HTML page:\n%s", bodyStr)
		return nil, fmt.Errorf("the line starting with '%s' never ends", lookup)
	}
	line := bodyStr[start+len(lookup) : start+end]

	// Now, remove the JavaScript ending "}]".
	line = strings.TrimSuffix(strings.TrimSpace(line), "}]")

	// Finally, unmarshal the JSON array.
	var missions []Mission
	err = json.Unmarshal([]byte(line), &missions)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal JSON array: %v", err)
	}

	return missions, nil
}

// The accountUUID is the base 64 encoded ID of the account. For example:
//
//	"eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9"
//
// which decodes to:
//
//	{"accountId":"64850e80b3b2947c6cfbd608","customerId":"64850e8036ccdc2407baecd4","quality":"CO_OWNER","buildingId":"64850e80a4ccb95ce4b6b115","trusteeMember":true}
//
// I copy-pasted the graphql query from the "Dev tools" in Chrome, and asked
// ChatGPT to turn that query into Go.
func GetAccountUUID(client *http.Client) (string, error) {
	gqlclient := graphql.NewClient("https://myfoncia-gateway.prod.fonciamillenium.net/graphql", client)

	type Account struct {
		UUID string `graphql:"uuid"`
	}

	q := struct {
		Accounts []Account `graphql:"accounts"`
	}{}

	err := gqlclient.Query(context.Background(), &q, nil)
	if err != nil {
		return "", fmt.Errorf("error while querying: %w", err)
	}

	if len(q.Accounts) == 0 {
		return "", fmt.Errorf("no accounts found")
	}

	return q.Accounts[0].UUID, nil
}

// Repairs and Incidents. Use GetAccountUUID to get the accountUUID.
func getMissionsLive(client *http.Client, accountUUID string) ([]Mission, error) {
	var interventions []Mission

	type PageInfo struct {
		EndCursor   string `json:"endCursor"`
		HasNextPage bool   `json:"hasNextPage"`
	}

	type MissionIncidents struct {
		TotalCount int      `json:"totalCount"`
		PageInfo   PageInfo `json:"pageInfo"`
		Edges      []struct {
			Node struct {
				ID          string `json:"id"`
				Number      string `json:"number"`
				StartedAt   string `json:"startedAt"`
				Label       string `json:"label"`
				Status      string `json:"status"`
				Description string `json:"description"`
			} `json:"node"`
		} `json:"edges"`
	}

	type MissionRepairs struct {
		TotalCount int      `json:"totalCount"`
		PageInfo   PageInfo `json:"pageInfo"`
		Edges      []struct {
			Node struct {
				ID          string `json:"id"`
				Number      string `json:"number"`
				StartedAt   string `json:"startedAt"`
				Label       string `json:"label"`
				Status      string `json:"status"`
				Description string `json:"description"`
			} `json:"node"`
		} `json:"edges"`
	}

	const getIncidentsQuery = `
		query getCouncilMissionIncidents($accountUuid: EncodedID!, $first: Int, $after: Cursor, $sortBy: [SortByType!]) {
			coownerAccount(uuid: $accountUuid) {
				uuid
				trusteeCouncil {
					missionIncidents(first: $first, after: $after, sortBy: $sortBy) {
						totalCount
						pageInfo {
							startCursor
							endCursor
							hasPreviousPage
							hasNextPage
							pageNumber
							itemsPerPage
							totalDisplayPages
							totalPages
						}
						edges {
							node {
								id
								number
								startedAt
								label
								status
								description
							}
						}
					}
				}
			}
		}
	`

	perPage := 100 // I found that it is the maximum value that works.
	pagesLimit := 100000

	// The reason *string is needed is because I found that the empty string
	// doesn't work to get the first page. To get the first page, the field
	// `after` must be appearing as `null`.
	var cursor *string
	pageCount := 0
	for {
		var getIncidentsResp struct {
			Data struct {
				CoownerAccount struct {
					UUID           string `json:"uuid"`
					TrusteeCouncil struct {
						MissionIncidents MissionIncidents `json:"missionIncidents"`
					} `json:"trusteeCouncil"`
				}
			} `json:"data"`
		}
		err := DoGraphQL(client, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", getIncidentsQuery, map[string]interface{}{
			"accountUuid": accountUUID,
			"first":       perPage,
			"after":       cursor,
			"sortBy": map[string]interface{}{
				"key":       "createdAt",
				"direction": "DESC",
			},
		}, &getIncidentsResp)
		if err != nil {
			return nil, fmt.Errorf("error while querying getIncidentsResp: %w", err)
		}

		for _, edge := range getIncidentsResp.Data.CoownerAccount.TrusteeCouncil.MissionIncidents.Edges {
			var startedAt time.Time
			if edge.Node.StartedAt != "" {
				var err error
				startedAt, err = time.Parse(time.RFC3339, edge.Node.StartedAt)
				if err != nil {
					logutil.Debugf("error parsing time: %v", err)
					return nil, fmt.Errorf("error parsing time: %w", err)
				}
			}
			interventions = append(interventions, Mission{
				ID:          edge.Node.ID,
				Number:      edge.Node.Number,
				Label:       edge.Node.Label,
				Status:      edge.Node.Status,
				StartedAt:   startedAt,
				Description: edge.Node.Description,
				Kind:        Incident,
			})
		}

		if !getIncidentsResp.Data.CoownerAccount.TrusteeCouncil.MissionIncidents.PageInfo.HasNextPage {
			break
		}
		temp := getIncidentsResp.Data.CoownerAccount.TrusteeCouncil.MissionIncidents.PageInfo.EndCursor
		cursor = &temp

		pageCount++
		if pageCount == pagesLimit {
			break
		}
	}

	// Repairs.
	const getRepairsQuery = `
		query getCouncilMissionRepairs($accountUuid: EncodedID!, $first: Int, $after: Cursor, $sortBy: [SortByType!]) {
			coownerAccount(uuid: $accountUuid) {
				uuid
				trusteeCouncil {
					missionRepairs(first: $first, after: $after, sortBy: $sortBy) {
						totalCount
						pageInfo {
							startCursor
							endCursor
							hasPreviousPage
							hasNextPage
							pageNumber
							itemsPerPage
							totalDisplayPages
							totalPages
						}
						edges {
							node {
								id
								number
								startedAt
								label
								status
								description
							}
						}
					}
				}
			}
		}
	`

	cursor = nil
	pageCount = 0
	for {
		var getRepairsResp struct {
			Data struct {
				CoownerAccount struct {
					UUID           string `json:"uuid"`
					TrusteeCouncil struct {
						MissionRepairs MissionRepairs `json:"missionRepairs"`
					} `json:"trusteeCouncil"`
				}
			} `json:"data"`
		}
		err := DoGraphQL(client, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", getRepairsQuery, map[string]interface{}{
			"accountUuid": accountUUID,
			"first":       perPage,
			"after":       cursor,
			"sortBy": map[string]interface{}{
				"key":       "createdAt",
				"direction": "DESC",
			},
		}, &getRepairsResp)
		if err != nil {
			return nil, fmt.Errorf("error while querying getRepairsResp: %w", err)
		}

		for _, edge := range getRepairsResp.Data.CoownerAccount.TrusteeCouncil.MissionRepairs.Edges {
			var startedAt time.Time
			if edge.Node.StartedAt != "" {
				startedAt, err = time.Parse(time.RFC3339, edge.Node.StartedAt)
				if err != nil {
					return nil, fmt.Errorf("error parsing time: %w", err)
				}
			}
			interventions = append(interventions, Mission{
				ID:          edge.Node.ID,
				Number:      edge.Node.Number,
				Label:       edge.Node.Label,
				Status:      edge.Node.Status,
				StartedAt:   startedAt,
				Description: edge.Node.Description,
				Kind:        Repair,
			})
		}

		if !getRepairsResp.Data.CoownerAccount.TrusteeCouncil.MissionRepairs.PageInfo.HasNextPage {
			break
		}
		cursor = &getRepairsResp.Data.CoownerAccount.TrusteeCouncil.MissionRepairs.PageInfo.EndCursor

		pageCount++
		if pageCount == pagesLimit {
			break
		}
	}

	sort.Slice(interventions, func(i, j int) bool {
		return interventions[i].StartedAt.After(interventions[j].StartedAt)
	})
	return interventions, nil
}

func getWorkOrdersLive(client *http.Client, accountUUID, missionID string) ([]WorkOrder, error) {
	const getWorkOrders = `
		query getWorkOrders($accountUuid: EncodedID!, $missionId: ID!, $first: Int, $before: Cursor, $after: Cursor) {
			workOrders(accountUuid: $accountUuid, missionId: $missionId, first: $first, before: $before, after: $after) {
				edges {
					node {
						id
						number
						label
						repairDate {
							start
							end
						}
						supplier {
							id
							name
							firstName
							activity
						}
					}
				}
			}
		}
	`
	var getWorkOrdersResp struct {
		Data struct {
			WorkOrders struct {
				Edges []struct {
					Node struct {
						ID         string `json:"id"`
						Number     string `json:"number"`
						Label      string `json:"label"`
						RepairDate struct {
							Start string `json:"start"`
							End   string `json:"end"`
						} `json:"repairDate"`
						Supplier struct {
							ID        string `json:"id"`
							Name      string `json:"name"`
							FirstName string `json:"firstName"`
							Activity  string `json:"activity"`
						} `json:"supplier"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"workOrders"`
		} `json:"data"`
	}

	err := DoGraphQL(client, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", getWorkOrders, map[string]interface{}{
		"accountUuid": accountUUID,
		"missionId":   missionID,
	}, &getWorkOrdersResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getWorkOrdersResp for mission %s: %w", missionID, err)
	}

	var orders []WorkOrder
	for _, edge := range getWorkOrdersResp.Data.WorkOrders.Edges {
		var start, end time.Time
		if edge.Node.RepairDate.Start != "" {
			start, err = time.Parse(time.RFC3339, edge.Node.RepairDate.Start)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
		}
		if edge.Node.RepairDate.End != "" {
			end, err = time.Parse(time.RFC3339, edge.Node.RepairDate.End)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
		}

		orders = append(orders, WorkOrder{
			ID:               edge.Node.ID,
			Number:           edge.Node.Number,
			Label:            edge.Node.Label,
			RepairDateStart:  start,
			RepairDateEnd:    end,
			SupplierID:       edge.Node.Supplier.ID,
			SupplierName:     edge.Node.Supplier.Name,
			SupplierActivity: edge.Node.Supplier.Activity,
		})
	}

	return orders, nil
}

func enableDebugCurlLogs(client *http.Client) {
	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}
	client.Transport = transportCurlLogs{trWrapped: client.Transport}
}

// Only used when --debug is passed.
type transportCurlLogs struct {
	trWrapped http.RoundTripper
}

func (tr transportCurlLogs) RoundTrip(r *http.Request) (*http.Response, error) {
	logutil.Debugf("%s", gencurl.FromRequest(r))
	return tr.trWrapped.RoundTrip(r)
}

// At first, I coded this using ShurcooL/graphql. I stopped using it for three
// reasons: (1) I found it painful to have to guess the types of anything that
// is not a graphql.String, graphql.Int. (2) In the same vein, I wasted a few
// hours finding out that the cursor variable needs to be "null" to get the
// first page... I had to dig into shurcooL/graphql's `writeArgumentType` func
// to figure that I shouldn't use "type Cursor *graphql.String", but instead use
// "type Cursor graphql.String" and then use a pointer to a Cursor. (3) The last
// reason is that the GraphQL library I was using had mismatched types... A
// variable was expected to be "[SortByType!]" but the variable had to be a
// SortByType... and this was impossible to work around in ShurcooL/graphql.
//
// The reason (3) isn't related to ShurcooL/graphql, but (1) and (2) is... This
// library seems to be the mostly used one, which says a lot about GraphQL's
// maturity!
func DoGraphQL[T any](client *http.Client, url, query string, variables map[string]interface{}, resp T) error {
	req := struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
	}{
		Query:     query,
		Variables: variables,
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("error marshaling request body: %w", err)
	}
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("error while querying: %w", err)
	}
	defer httpResp.Body.Close()

	// It would be more efficient to parse the JSON blob straigt from the
	// io.Reader (would use less memory), but I don't care. If the body
	// can't be parsed as JSON, I want to see a dump of it. I should set a
	// limit to the size of the body though to prevent DoS attacks, but I
	// don't care about that right now.
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("status code %d, error while reading body: %w", httpResp.StatusCode, err)
	}

	if httpResp.StatusCode == 400 {
		var graphQLResp struct {
			Errors []struct {
				Message   string `json:"message"`
				Locations []struct {
					Line   int `json:"line"`
					Column int `json:"column"`
				} `json:"locations"`
			} `json:"errors"`
		}
		errUnmarsh := json.Unmarshal(body, &graphQLResp)
		if errUnmarsh != nil {
			// Fall back to showing the raw body.
			return fmt.Errorf("status code was 400, but body isn't a standard graphql JSON error, body: %v", string(body))
		}
		bytes, _ := json.MarshalIndent(graphQLResp, "", "  ")
		return fmt.Errorf("status code 400: %s", string(bytes))
	}
	if httpResp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code %d, body: %s", httpResp.StatusCode, string(body))
	}

	err = json.Unmarshal(body, &resp)
	if err != nil {
		return fmt.Errorf("status code was 200 but body could not be parsed as %T: %s\nbody: %s", resp, err, string(body))
	}

	return nil
}
