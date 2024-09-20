package main

import (
	"context"
	"database/sql"
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
	"github.com/maelvls/foncia/logutil"
	"github.com/maelvls/foncia/undent"
)

var (
	// EnableDebug enables debugFlag logs.
	debugFlag = flag.Bool("debug", false, "Enable debug logs, including equivalent curl commands.")

	serveBasePath  = flag.String("basepath", "", "Base path, useful for reverse proxies. Must start with a slash or be empty.")
	serveAddr      = flag.String("addr", "0.0.0.0:8080", "Address and port to serve the server on.")
	serveBaseURL   = flag.String("baseurl", "", "Domain on which the server is running. Used to generate URLs in Ntfy notifications. If empty, --addr is used.")
	dbOnly         = flag.Bool("db-only", false, "When set, no HTTP request is made, and everything is fetched from the DB.")
	dbPath         = flag.String("db", "foncia.sqlite", "Path to the sqlite3 database. You can use ':memory:' if you don't want to save the database.")
	ntfyTopic      = flag.String("ntfy-topic", "", "Topic to send notifications to using https://ntfy.sh/.")
	invoicesDir    = flag.String("invoices-dir", "invoices", "Directory to save invoices to. Will be created if it doesn't exist.")
	htmlHeaderFile = flag.String("header-file", "", "File containing an HTML header to be added to the top of the page. Can contain Go template syntax. The template is executed with the following data: {BasePath, SyncStatus, NtfyTopic, Items, Version}.")

	smtpAddr = flag.String("smtp-addr", "0.0.0.0:25", "SMTP server address. The SMTP server is used to forward 'mission' emails from Foncia")

	// In order to test the Ntfy integration, you can use --sync-period=1m and
	// manually remove the last item from the DB:
	//
	//  go run . rm-last-expense
	//  go run . rm-last-mission
	syncPeriod = flag.Duration("sync-period", 10*time.Minute, "Period at which to sync with the live API.")

	versionFlag = flag.Bool("version", false, "Print the version and exit.")
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

var signalOnce = make(chan struct{})

// Catch ctrl+c and SIGTERM to exit cleanly. Only the first call to this func
// will be effective.
func signalOnExit(f func(os.Signal)) {
	close(signalOnce) // Prevents us from using this func again.

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
			"  serve, serve-smtp, list, rm-last-expense, rm-last-mission, token\n"+
			"\n"+
			"Flags:\n", os.Args[0])
		flag.CommandLine.PrintDefaults()
	}

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

		// The `--db` is the path to the SQLite database. Example:
		// "/var/lib/foncia.db".
		path := *dbPath
		logutil.Debugf("using sqlite3 database file %q", path)
		if path == "" {
			logutil.Errorf("missing required value: path")
			os.Exit(1)
		}

		db, err := sql.Open("sqlite", path)
		if err != nil {
			logutil.Errorf("failed to open database at %q: %w", path, err)
			os.Exit(1)
		}
		defer db.Close()

		err = initSchemaDB(context.Background(), db)
		if err != nil {
			logutil.Errorf("while creating schema: %v", err)
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

				time.Sleep(*syncPeriod)
			}
		}()

		htmlHeader, err := readHeaderFile(*htmlHeaderFile)
		if err != nil {
			logutil.Errorf("while reading HTML header file: %v", err)
			os.Exit(1)
		}

		httpListen, err := net.Listen("tcp", *serveAddr)
		if err != nil {
			logutil.Errorf("while starting listener for the SMTP server: %v", err)
			return
		}
		smtpListen, err := net.Listen("tcp", *smtpAddr)
		if err != nil {
			logutil.Errorf("while starting listener for the HTTP server: %v", err)
			return
		}

		wg := sync.WaitGroup{}
		ctx := context.Background()
		ctx, cancel := context.WithCancelCause(ctx)
		defer cancel(fmt.Errorf("main: cancelled for no reason"))
		signalOnExit(func(s os.Signal) {
			cancel(fmt.Errorf("main: cancelled by signal %s", s))
		})

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ServeSMTP(ctx, db, smtpListen)
			if err != nil {
				cancel(err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ServeHTTP(ctx, db, httpListen, *serveBasePath, username, password, readLastSync, htmlHeader)
			if err != nil {
				cancel(err)
			}
		}()

		wg.Wait()
		if ctx.Err() != nil {
			logutil.Errorf("main: %v", context.Cause(ctx))
			os.Exit(1)
		}
	case "serve-smtp":
		// The `--db` is the path to the SQLite database. Example:
		// "/var/lib/foncia.db".
		path := *dbPath
		logutil.Debugf("using sqlite3 database file %q", path)
		if path == "" {
			logutil.Errorf("missing required value: path")
			os.Exit(1)
		}

		db, err := sql.Open("sqlite", path)
		if err != nil {
			logutil.Errorf("failed to open database at %q: %w", path, err)
			os.Exit(1)
		}
		defer db.Close()

		err = initSchemaDB(context.Background(), db)
		if err != nil {
			logutil.Errorf("while creating schema: %v", err)
			os.Exit(1)
		}

		smtpListen, err := net.Listen("unix", "/tmp/smtp.sock")
		if err != nil {
			logutil.Errorf("while starting listener for the HTTP server: %v", err)
			return
		}

		logutil.Infof(undent.Undent(`
			To test the SMTP server, run:

			socat - UNIX-CONNECT:/tmp/smtp.sock <<EOF
			EHLO localhost
			AUTH PLAIN
			AHVzZXJuYW1lAHBhc3N3b3Jk
			MAIL FROM:<noreplay@foncia.fr>
			RCPT TO:<foo@gmail.com>
			DATA
			$(cat email.mbox)
			.
			EOF


		`))

		wg := sync.WaitGroup{}
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(fmt.Errorf("main: cancelled for no reason"))
		signalOnExit(func(s os.Signal) {
			cancel(fmt.Errorf("main: cancelled by signal %s", s))
		})

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ServeSMTP(ctx, db, smtpListen)
			if err != nil {
				cancel(err)
			}
		}()

		wg.Wait()
		if ctx.Err() != nil {
			logutil.Errorf("main: %v", ctx.Err())
			os.Exit(1)
		}
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
		fmt.Println(token.StringOnPurpose())
	case "":
		logutil.Errorf("no command given. Use one of: serve, list, rm-last-expense, rm-last-mission, token")
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
