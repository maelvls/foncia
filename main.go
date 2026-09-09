package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

const (
	graphqlURL = "https://myfoncia-gateway.prod.fonciamillenium.net/graphql"
)

var (
	// EnableDebug enables debugFlag logs.
	debugFlag = flag.Bool("debug", false, "Enable debug logs, including equivalent curl commands.")

	serveBasePath  = flag.String("basepath", "", "Base path, useful for reverse proxies. Must start with a slash or be empty.")
	serveAddr      = flag.String("addr", "0.0.0.0:8080", "Address and port to serve the server on.")
	serveBaseURL   = flag.String("baseurl", "", "Domain on which the server is running. Used to generate URLs in Ntfy notifications. If empty, --addr is used.")
	dbPath         = flag.String("db", "foncia.sqlite", "Path to the sqlite3 database. You can use ':memory:' if you don't want to save the database.")
	allowedUsers   = flag.String("allowed-users", "", "Comma-separated list of email addresses allowed to use the web UI, matched against --auth-header. Empty (the default) means no check is done in this process and access control is left entirely to the reverse proxy.")
	authHeader     = flag.String("auth-header", "X-Forwarded-Email", "Header set by the authenticating reverse proxy, used by --allowed-users. The proxy must strip this header from incoming requests.")
	ntfyTopic      = flag.String("ntfy-topic", "", "Topic to send notifications to using https://ntfy.sh/.")
	invoicesDir    = flag.String("invoices-dir", "invoices", "Directory to save invoices to. Will be created if it doesn't exist.")
	htmlHeaderFile = flag.String("header-file", "", "File containing an HTML header to be added to the top of the page. Can contain Go template syntax. The template is executed with the following data: {BasePath, SyncStatus, NtfyTopic, Items, Version}.")

	// In order to test the Ntfy integration, you can use --sync-period=1m and
	// manually remove the last item from the DB:
	//
	//  go run . rm-last-expense
	//  go run . rm-last-mission
	syncPeriod = flag.Duration("sync-period", 10*time.Minute, "Period at which to sync with the live API.")
	readOnly   = flag.Bool("read-only", false, "Disable synchronization with the live API.")

	// The general assembly documents are always indexed so that they show up in
	// the UI, but they aren't downloaded by default: some of the convocations
	// weigh tens of megabytes, and there are more than a hundred of them. When
	// they aren't on disk, /dl/doc/<hash> redirects to the Foncia URL instead.
	downloadAGDocs = flag.Bool("download-ag-documents", false, "Download the general assembly documents (convocations, procès-verbaux, annexes) to --invoices-dir during the sync. They can weigh several hundred megabytes; when this is off, they are downloaded on the first click on their link instead.")

	jsonFlag   = flag.Bool("json", false, "For the 'comptes-travaux' command: print the result as JSON instead of a human-readable table.")
	totalsFlag = flag.Bool("totals", false, "For the 'comptes-travaux' command: also show the balance of each 'compte travaux'. Slower, since it does one extra API call per 'compte travaux'.")
)

var (
	// These don't need to be set manually at build time with -ldflags because
	// `go build` will set them for you thanks to the ReadBuildInfo() below, as
	// long as the build is made from a Git checkout.
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

var signalOnce sync.Once

// Catch ctrl+c and SIGTERM to exit cleanly. Only the first call to this func
// will be effective.
func signalOnExit(f func(os.Signal)) {
	signalOnce.Do(func() {
		installSignalHandler(f)
	})
}

func installSignalHandler(f func(os.Signal)) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sig
		logutil.Infof("received signal %q, closing cleanly... Press ctrl+c to force exit", s)
		f(s)
		<-sig
		logutil.Infof("received second signal %q, forcing exit", s)
		os.Exit(1)
	}()
}

func main() {
	flag.CommandLine.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n"+
			"  %s [flags] <command>\n"+
			"\n"+
			"Commands:\n"+
			"  serve, list, comptes-travaux, convocations, rm-last-expense, rm-last-mission, token, version\n"+
			"\n"+
			"Flags:\n", os.Args[0])
		flag.CommandLine.PrintDefaults()
	}

	flag.Parse()
	if *debugFlag {
		logutil.EnableDebug = true
		logutil.Debugf("debug output enabled")
	}

	// One context for the whole process, cancelled on SIGINT/SIGTERM, so that
	// an in-flight sync or HTTP request is interrupted instead of the process
	// being torn down mid-write.
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	signalOnExit(func(s os.Signal) {
		cancel(fmt.Errorf("received signal %q", s))
	})

	switch flag.Arg(0) {
	case "version":
		fmt.Println(version)
	case "serve":
		logutil.Infof("version: %s (%s)", version, date)

		sqlDB := openDB()
		defer sqlDB.Close()

		var err error
		token := os.Getenv("FONCIA_TOKEN")
		var client *http.Client
		if token != "" {
			logutil.Infof("using FONCIA_TOKEN instead of username and password")
			client = api.AuthenticatedClientToken(api.Token(token))
		} else {
			username, password := getCreds()
			client, err = api.AuthenticatedClient(&http.Client{}, graphqlURL, username, password)
			if err != nil {
				logutil.Errorf("while authenticating client: %v", err)
				os.Exit(1)
			}
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

		uuid, err := api.GetAccountUUID(ctx, client, graphqlURL)
		if err != nil {
			logutil.Errorf("while getting account UUID: %v", err)
			os.Exit(1)
		}

		if !*readOnly {
			go func() {
				// When the database is empty, we do an initial fetch to populate
				// it; since it most likely means that these items aren't new, we
				// don't send Ntfy notifications.
				skipNotif, err := db.IsEmptyDB(ctx, sqlDB)
				if err != nil {
					cancel(fmt.Errorf("while checking if database is empty: %w", err))
					return
				}

				for {
					logutil.Debugf("updating database by fetching from live")
					newMissions, newExpenses, err := authFetchSave(ctx, client, sqlDB, uuid, *invoicesDir)
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
						// Only stop skipping once a run has actually gone
						// through. Clearing the flag after a run that failed
						// halfway would make the next run announce the whole
						// backlog one item at a time.
						if err == nil {
							skipNotif = false
						}
						goto sleep
					}
					for _, e := range newMissions {
						logutil.Infof("new mission: %s", e.Label)
						err := ntfy(*ntfyTopic, ntfyMsg{
							HeaderTags:     "tools",
							HeaderTitle:    "Nouvelle intervention",
							Body:           missionToNtfyBody(e),
							HeaderClick:    serveBaseURL + *serveBasePath + "#" + e.ID,
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
							HeaderClick:    serveBaseURL + *serveBasePath + "#" + e.InvoiceID,
							HeaderPriority: "default",
						})
						if err != nil {
							logutil.Errorf("while sending notification: %v", err)
							writeLastSync(err)
						}
					}

				sleep:
					select {
					case <-ctx.Done():
						return
					case <-time.After(*syncPeriod):
					}
				}
			}()
		} else {
			logutil.Infof("running in read-only mode, skipping synchronization")
		}

		var htmlHeader string
		if *htmlHeaderFile != "" {
			htmlHeader, err = readHeaderFile(*htmlHeaderFile)
			if err != nil {
				logutil.Errorf("while reading HTML header file: %v", err)
				os.Exit(1)
			}
		}

		httpListen, err := net.Listen("tcp", *serveAddr)
		if err != nil {
			logutil.Errorf("while starting listener for the HTTP server: %v", err)
			return
		}

		wg := sync.WaitGroup{}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel(nil)
			err := ServeHTTP(ctx, sqlDB, httpListen, client, uuid, *serveBasePath, *invoicesDir, readLastSync, htmlHeader)
			if err != nil {
				cancel(err)
			}
		}()

		wg.Wait()
		if ctx.Err() != nil {
			logutil.Errorf("%v", context.Cause(ctx))
			os.Exit(1)
		}
	case "list":
		username, password := getCreds()
		ListCmd(ctx, username, password)
	case "comptes-travaux", "repair-budgets":
		// The --json and --totals flags are also declared globally so that they
		// show up in --help and can be given before the command name, as in
		// `foncia --totals comptes-travaux`.
		fs := flag.NewFlagSet(flag.Arg(0), flag.ExitOnError)
		asJSON := fs.Bool("json", *jsonFlag, "Print the result as JSON instead of a human-readable table.")
		withTotals := fs.Bool("totals", *totalsFlag, "Also show the balance of each 'compte travaux'. Slower, since it does one extra API call per 'compte travaux'.")
		args := parseInterspersed(fs, flag.Args()[1:])
		if len(args) > 1 {
			logutil.Errorf("expected at most one 'compte travaux' to look for, got %d: %s", len(args), strings.Join(args, ", "))
			os.Exit(1)
		}
		var search string
		if len(args) == 1 {
			search = args[0]
		}

		username, password := getCreds()
		ComptesTravauxCmd(ctx, username, password, search, *asJSON, *withTotals)
	case "convocations", "ag":
		fs := flag.NewFlagSet(flag.Arg(0), flag.ExitOnError)
		asJSON := fs.Bool("json", *jsonFlag, "Print the result as JSON instead of a human-readable table.")
		withAll := fs.Bool("all", false, "Also list the procès-verbaux and the annexes of the general assemblies, not just the convocations.")
		outDir := fs.String("download", "", "Download the PDFs to this directory instead of listing them. The directory is created if needed.")
		args := parseInterspersed(fs, flag.Args()[1:])
		if len(args) > 1 {
			logutil.Errorf("expected at most one file name to look for, got %d: %s", len(args), strings.Join(args, ", "))
			os.Exit(1)
		}
		var search string
		if len(args) == 1 {
			search = args[0]
		}

		username, password := getCreds()
		ConvocationsCmd(ctx, username, password, search, *outDir, *withAll, *asJSON)
	case "rm-last-expense":
		sqlDB := openDB()
		defer sqlDB.Close()

		err := db.RmLastExpenseDB(sqlDB)
		if err != nil {
			logutil.Errorf("while removing last expense: %v", err)
			os.Exit(1)
		}
	case "rm-last-mission":
		sqlDB := openDB()
		defer sqlDB.Close()

		err := db.RmLastMissionDB(sqlDB)
		if err != nil {
			logutil.Errorf("while removing last mission: %v", err)
			os.Exit(1)
		}
	case "token":
		username, password := getCreds()
		client := &http.Client{}
		api.EnableDebugCurlLogs(client)
		token, _, err := api.GetToken(ctx, client, graphqlURL, username, password)
		if err != nil {
			logutil.Errorf("while authenticating: %v", err)
			os.Exit(1)
		}
		fmt.Println(token.StringOnPurpose())
	case "":
		logutil.Errorf("no command given")
		flag.CommandLine.Usage()
		os.Exit(1)
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

func missionToNtfyBody(m db.MissionDB) string {
	msg := m.Label
	if m.Description != "" {
		msg += ": " + m.Description
	}

	// Add the work orders.
	wos := make([]string, 0, len(m.WorkOrders))
	for _, wo := range m.WorkOrders {
		wos = append(wos, fmt.Sprintf("%s %s", wo.Supplier.Activity, wo.Label))
	}
	if len(wos) > 0 {
		msg += " (" + strings.Join(wos, ", ") + ")"
	}

	return msg
}

// Returns the new entries found.
// authFetchSave runs the four syncs and returns the missions and expenses that
// were newly written.
//
// The four syncs are independent of each other, so one of them failing must not
// stop the others: a single document download answering 403 used to abort the
// whole run, and the rows the earlier steps had already written were then
// dropped from the result, which meant they were never notified about either.
// Every sync runs, and the errors are reported together.
func authFetchSave(ctx context.Context, client *http.Client, sqlDB *sql.DB, uuid, invoicesDir string) ([]db.MissionDB, []db.ExpenseDocumentDB, error) {
	var errs []error

	if err := syncAccountDocumentsWithDB(ctx, client, sqlDB, graphqlURL, uuid, invoicesDir, *downloadAGDocs); err != nil {
		errs = append(errs, fmt.Errorf("while syncing the account documents: %w", err))
	}

	newMissions, err := syncLiveMissionsWithDB(ctx, client, sqlDB, graphqlURL, uuid)
	if err != nil {
		errs = append(errs, fmt.Errorf("while syncing the missions: %w", err))
	}

	newExpenses, err := syncExpensesWithDB(ctx, client, sqlDB, graphqlURL, uuid, invoicesDir)
	if err != nil {
		errs = append(errs, fmt.Errorf("while syncing the expenses: %w", err))
	}

	if err := syncSuppliersWithDB(ctx, client, sqlDB, graphqlURL, uuid, invoicesDir); err != nil {
		errs = append(errs, fmt.Errorf("while syncing the suppliers: %w", err))
	}

	return newMissions, newExpenses, errors.Join(errs...)
}

// The flag package stops parsing as soon as it hits a non-flag argument, which
// means `comptes-travaux ascenseur --totals` would leave --totals unparsed.
// This helper keeps parsing after each positional argument so that flags can
// appear anywhere. It returns the positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			// Unreachable with flag.ExitOnError, but let's not rely on it.
			logutil.Errorf("while parsing flags: %v", err)
			os.Exit(1)
		}
		if fs.NArg() == 0 {
			return positional
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func getCreds() (string, api.Password) {
	username := os.Getenv("FONCIA_USERNAME")
	password := api.Password(os.Getenv("FONCIA_PASSWORD"))
	if username == "" || password == "" {
		logutil.Errorf("FONCIA_USERNAME and FONCIA_PASSWORD must be set.")
		os.Exit(1)
	}
	return username, password
}

func readHeaderFile(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("while opening HTML header file: %v", err)
	}

	bytes, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("while reading HTML header file: %v", err)
	}
	err = f.Close()
	if err != nil {
		return "", fmt.Errorf("while closing HTML header file: %v", err)
	}

	return string(bytes), nil
}

// This function comes from an MIT-licensed project from github.com/SgtCoDFish.
func ntfy(topic string, msg ntfyMsg) error {
	// Without a topic, the URL would be https://ntfy.sh/ and every send would
	// fail. Notifications are optional, so skip them silently instead.
	if topic == "" {
		logutil.Debugf("no --ntfy-topic configured, skipping notification %q", msg.HeaderTitle)
		return nil
	}

	client := &http.Client{Timeout: 5 * time.Second}

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

// openDB opens the SQLite database given with --db and applies the schema. The
// three commands that need a database used to each repeat this block.
func openDB() *sql.DB {
	path := *dbPath
	if path == "" {
		logutil.Errorf("missing required value: --db")
		os.Exit(1)
	}
	logutil.Debugf("using sqlite3 database file %q", path)

	sqlDB, err := db.Open(path)
	if err != nil {
		logutil.Errorf("%v", err)
		os.Exit(1)
	}
	return sqlDB
}
