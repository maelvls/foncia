package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime/debug"
	"strings"

	"github.com/sethgrid/gencurl"

	"github.com/maelvls/foncia/logutil"
)

var (
	// EnableDebug enables debugFlag logs.
	debugFlag = flag.Bool("debug", false, "Enable debug logs, including equivalent curl commands.")

	serveBasePath = flag.String("basepath", "", "Base path to serve the API on. For example, if set to /api, the API will be served on /api/interventions. Useful for reverse proxies. Must start with a slash.")
	serveAddr     = flag.String("addr", "0.0.0.0:8080", "Address and port to serve the server on.")

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
	}
	username := os.Getenv("FONCIA_USERNAME")
	password := os.Getenv("FONCIA_PASSWORD")
	coproID := os.Getenv("FONCIA_COPRO_ID")
	if username == "" || password == "" {
		logutil.Errorf("FONCIA_USERNAME and FONCIA_PASSWORD must be set.")
		os.Exit(1)
	}
	if coproID == "" {
		logutil.Errorf("FONCIA_COPRO_ID must be set.")
		os.Exit(1)
	}

	switch flag.Arg(0) {
	case "version":
		fmt.Println(version)
	case "serve":
		if *serveBasePath != "" && !strings.HasPrefix(*serveBasePath, "/") {
			logutil.Errorf("basepath must start with a slash")
			os.Exit(1)
		}
		ServeCmd(*serveAddr, *serveBasePath, username, password, coproID)
	case "list":
		ListCmd(username, password, coproID)
	default:
		logutil.Errorf("unknown command %q", flag.Arg(0))
		os.Exit(1)
	}
}

type tmlpData struct {
	Items   []Intervention
	Version string
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
	<table>
		<thead>
			<tr>
				<th>Nom Fournisseur</th>
				<th>Date</th>
				<th>Statut</th>
				<th>Description</th>
			</tr>
		</thead>
		<tbody>
			{{range .Items}}
			<tr>
				<td>
					{{ .NomFournisseur }}
					<small>({{ .ActiviteFournisseur }})</small>
				</td>
				<td>{{.Date}}</td>
				<td>{{.Statut}}</td>
				<td>{{.Description}}</td>
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

func ServeCmd(serveAddr, basePath, username, password, coproID string) {
	client := &http.Client{}
	enableDebugCurlLogs(client)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(302)
		tmlpErr.Execute(w, tmlpErrData{
			Error:   fmt.Sprintf(`The actual page is <a href="%s/interventions">here</a>.`, basePath),
			Version: version,
		})
	})

	http.HandleFunc("/interventions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err := Authenticate(client, username, password)
		if err != nil {
			logutil.Errorf("while authenticating: %v", err)

			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{
				Error:   fmt.Sprintf("Error while authenticating: %s", err),
				Version: version,
			})

			return
		}

		items, err := GetInterventions(client, coproID)
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

		err = tmpl.Execute(w, tmlpData{
			Items:   items,
			Version: version + " (" + date + ")"},
		)
		if err != nil {
			logutil.Errorf("executing template: %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	})

	logutil.Infof("Listening on %s", serveAddr)
	err := http.ListenAndServe(serveAddr, nil)
	if err != nil {
		logutil.Errorf("while listening: %v", err)
		os.Exit(1)
	}
}

func ListCmd(username, password, coproID string) {
	client := &http.Client{}
	enableDebugCurlLogs(client)

	err := Authenticate(client, username, password)
	if err != nil {
		logutil.Errorf("while authenticating: %v", err)
		os.Exit(1)
	}

	items, err := GetInterventions(client, coproID)
	if err != nil {
		logutil.Errorf("getting interventions: %v", err)
		os.Exit(1)
	}

	// Print the items starting with the oldest one.
	for i := len(items) - 1; i > 0; i-- {
		fmt.Printf("%s %s %s %s %s\n",
			items[i].Date,
			items[i].ActiviteFournisseur,
			logutil.Yel(items[i].NomFournisseur),
			func() string {
				if items[i].Statut == "V" {
					return logutil.Green("Terminé")
				}
				return logutil.Red("En cours")
			}(),
			logutil.Gray(items[i].Description),
		)
	}
}

type Intervention struct {
	ID                  int         `json:"id"`
	NomFournisseur      string      `json:"nomFournisseur"`
	ActiviteFournisseur string      `json:"activiteFournisseur"`
	TelFournisseur      interface{} `json:"telFournisseur"`
	Date                string      `json:"date"`
	Description         string      `json:"description"`
	Statut              string      `json:"statut"`
	LibelleStatut       interface{} `json:"libelleStatut"`
	Document            interface{} `json:"document"`
	MonthYear           string      `json:"monthYear"`
	MonthYearTs         int         `json:"monthYearTs"`
	Timestamp           int         `json:"timestamp"`
}

func Authenticate(client *http.Client, username, password string) error {
	// Redirects don't make sense for HTML pages. For example, a 302 redirect
	// might actually indicate an error.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("error creating cookie jar: %w", err)
	}
	client.Jar = jar

	// A first request is needed to get the session cookie.
	req, err := http.NewRequest("GET", "https://myfoncia.fr/login", nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// The second request is the actual authentication.
	form := url.Values{}
	form.Add("username", username)
	form.Add("_password", password)
	req, err = http.NewRequest("POST", "https://myfoncia.fr/login_check", strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Printf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 302 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		return fmt.Errorf("error getting redirect location: %w", err)
	}
	if loc.Path != "/espace-client/espace-de-gestion/mon-bien" {
		return fmt.Errorf("authentication did not go well (redirected to %s)", loc.String())
	}

	setCookies := resp.Header.Values("Set-Cookie")
	if setCookies == nil {
		return fmt.Errorf("no Set-Cookie found in the response, the authentication failed")
	}

	// The endpoint returns three cookies. The first eZSESSID doesn't work, so
	// it needs to be skipped. The second eZSESSID is the one that works. Sample
	// of the cookies returned:
	//
	//  Set-Cookie: eZSESSID=mjcimnin45v5u33061a1mstlr4; path=/; secure; HttpOnly
	//  Set-Cookie: is_logged_in=true; expires=Sat, 11-Mar-2023 18:20:16 GMT; Max-Age=1800; path=/
	//  Set-Cookie: eZSESSID=bdrjj36o2okutmmro6vlmkrqo5; path=/; secure; HttpOnly

	// var eZSESSID *http.Cookie
	// for _, cookie := range resp.Cookies() {
	// 	if cookie.Name == "eZSESSID" {
	// 		eZSESSID = cookie
	// 	}
	// }
	// req.AddCookie(eZSESSID)

	logutil.Debugf("Successfully authenticated as %s", username)
	return nil
}

func GetInterventions(client *http.Client, coproID string) ([]Intervention, error) {
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
	var items []Intervention
	err = json.Unmarshal([]byte(line), &items)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal JSON array: %v", err)
	}

	return items, nil
}

func enableDebugCurlLogs(client *http.Client) {
	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}
	client.Transport = transportCurlLogs{trWrapped: client.Transport}
}

type transportCurlLogs struct {
	trWrapped http.RoundTripper
	token     string
}

func (tr transportCurlLogs) RoundTrip(r *http.Request) (*http.Response, error) {
	logutil.Debugf("%s", gencurl.FromRequest(r))
	return tr.trWrapped.RoundTrip(r)
}
