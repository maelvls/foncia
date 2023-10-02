package main

import (
	"context"
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
	"time"

	"github.com/dreamscached/minequery/v2"
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
		username, password, coproID := getCreds()
		ServeCmd(*serveAddr, *serveBasePath, username, password, coproID)
	case "list":
		username, password, _ := getCreds()
		ListCmd(username, password)
	case "token":
		username, password, _ := getCreds()
		client := &http.Client{}
		enableDebugCurlLogs(client)
		token, err := Token(client, username, password)
		if err != nil {
			logutil.Errorf("while authenticating: %v", err)
			os.Exit(1)
		}
		fmt.Println(token)
	case "list-mc":
		res, err := minequery.Ping17("lisa.valais.dev", 25565)
		if err != nil {
			panic(err)
		}
		fmt.Println(res)
	default:
		logutil.Errorf("unknown command %q", flag.Arg(0))
		os.Exit(1)
	}
}

func getCreds() (string, secret, string) {
	username := os.Getenv("FONCIA_USERNAME")
	password := secret(os.Getenv("FONCIA_PASSWORD"))
	coproID := os.Getenv("FONCIA_COPRO_ID")
	if username == "" || password == "" {
		logutil.Errorf("FONCIA_USERNAME and FONCIA_PASSWORD must be set.")
		os.Exit(1)
	}
	if coproID == "" {
		logutil.Errorf("FONCIA_COPRO_ID must be set.")
		os.Exit(1)
	}
	return username, password, coproID
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
				<th>Number</th>
				<th>Label</th>
				<th>Status</th>
				<th>StartedAt</th>
			</tr>
		</thead>
		<tbody>
			{{range .Items}}
			<tr>
				<td>{{ .Number }}</td>
				<td>{{.Label}}</td>
				<td>{{.Status}}</td>
				<td>{{.StartedAt}}</td>
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

func ServeCmd(serveAddr, basePath, username string, password secret, coproID string) {
	client := &http.Client{}
	enableDebugCurlLogs(client)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(302)
		w.Header().Set("Location", basePath+"/interventions")
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

		token, err := Token(client, username, password)
		client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		))
		enableDebugCurlLogs(client)

		if err != nil {
			logutil.Errorf("while authenticating: %v", err)

			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{
				Error:   fmt.Sprintf("Error while authenticating: %s", err),
				Version: version,
			})

			return
		}

		items, err := GetInterventions(client)
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

	http.HandleFunc("/minecraft", ServeMinecraft)

	logutil.Infof("Listening on %s", serveAddr)
	err := http.ListenAndServe(serveAddr, nil)
	if err != nil {
		logutil.Errorf("while listening: %v", err)
		os.Exit(1)
	}
}

func ListCmd(username string, password secret) {
	client := &http.Client{}
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

	items, err := GetInterventions(client)
	if err != nil {
		logutil.Errorf("getting interventions: %v", err)
		os.Exit(1)
	}

	// Print the items starting with the oldest one.
	for i := len(items) - 1; i > 0; i-- {
		fmt.Printf("%s %s %s\n",
			items[i].StartedAt,
			logutil.Yel(items[i].Label),
			func() string {
				if items[i].Status == "WORK_IN_PROGRESS" {
					return logutil.Red(items[i].Status)
				} else {
					return logutil.Green(items[i].Status)
				}
			}(),
		)
	}
}

// Example:
//
// {
//   "data": {
//     "coownerAccount": {
//       "uuid": "eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9",
//       "trusteeCouncil": {
//         "missionIncidents": {
//           "totalCount": null,
//           "pageInfo": {
//             "startCursor": "eyJwYWdlTnVtYmVyIjoxLCJpdGVtc1BlclBhZ2UiOjEwfQ",
//             "endCursor": "eyJwYWdlTnVtYmVyIjoyLCJpdGVtc1BlclBhZ2UiOjEwfQ",
//             "hasPreviousPage": false,
//             "hasNextPage": true,
//             "pageNumber": 1,
//             "itemsPerPage": 10,
//             "totalDisplayPages": 6,
//             "totalPages": null
//           },
//           "edges": [
//             {
//               "node": {
//                 "id": "64850e8019d5d64c415d13dd",
//                 "number": "7000YRK51",
//                 "startedAt": "2023-04-24T22:00:00.000Z",
//                 "label": "ATELIER METALLERIE FERRONNERIE - VALIDATION DEVIS ",
//                 "status": "WORK_IN_PROGRESS",
//                 "__typename": "MissionIncident"
//               },
//               "__typename": "MissionIncidentNode"
//             }
//           ]
//         },
//         "__typename": "TrusteeCouncil"
//       },
//       "__typename": "CoownerAccount"
//     },
//     "__typename": "Query"
//   }
// }

type Intervention struct {
	ID        string    // "64850e8019d5d64c415d13dd"
	Number    string    // "7000YRK51"
	Label     string    // "ATELIER METALLERIE FERRONNERIE - VALIDATION DEVIS "
	Status    string    // "WORK_IN_PROGRESS"
	StartedAt time.Time // "2023-04-24T22:00:00.000Z"
}

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
	return jwt, nil
}

func GetInterventionsOld(client *http.Client, coproID string) ([]Intervention, error) {
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

func GetInterventions(client *http.Client) ([]Intervention, error) {
	gqlclient := graphql.NewClient("https://myfoncia-gateway.prod.fonciamillenium.net/graphql", client)

	type PageOptions struct {
		// Define the fields of PageOptions here if necessary.
	}

	type PageInfo struct {
		StartCursor       graphql.String
		EndCursor         graphql.String
		HasPreviousPage   graphql.Boolean
		HasNextPage       graphql.Boolean
		PageNumber        graphql.Int
		ItemsPerPage      graphql.Int
		TotalDisplayPages graphql.Int
		TotalPages        graphql.Int
	}

	type MissionIncident struct {
		ID        graphql.String
		Number    graphql.String
		StartedAt graphql.String
		Label     graphql.String
		Status    graphql.String
		Typename  graphql.String `graphql:"__typename"`
	}

	type MissionIncidents struct {
		TotalCount graphql.Int
		PageInfo   PageInfo
		Edges      []struct {
			Node     MissionIncident
			Typename graphql.String `graphql:"__typename"`
		}
	}
	type TrusteeCouncil struct {
		MissionIncidents MissionIncidents
		Typename         graphql.String `graphql:"__typename"`
	}

	type CoownerAccount struct {
		UUID           graphql.String
		TrusteeCouncil TrusteeCouncil
		Typename       graphql.String `graphql:"__typename"`
	}

	type GetCouncilMissionIncidentsQuery struct {
		CoownerAccount CoownerAccount `graphql:"coownerAccount(uuid: $accountUuid)"`
		Typename       graphql.String `graphql:"__typename"`
	}

	// type AccountUUID struct {
	// 	AccountID     string `json:"accountId"`
	// 	CustomerID    string `json:"customerId"`
	// 	Quality       string `json:"quality"`
	// 	BuildingID    string `json:"buildingId"`
	// 	TrusteeMember bool   `json:"trusteeMember"`
	// }

	type EncodedID string

	accountUuid := "eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9"
	// Set the variables you want to use in the query.
	variables := map[string]interface{}{
		"accountUuid": (EncodedID)(accountUuid),
	}

	q := GetCouncilMissionIncidentsQuery{}
	err := gqlclient.Query(context.Background(), &q, variables)
	if err != nil {
		logutil.Debugf("while querying: %v", err)
		return nil, fmt.Errorf("error while querying: %w", err)
	}

	var interventions []Intervention
	for _, edge := range q.CoownerAccount.TrusteeCouncil.MissionIncidents.Edges {
		var startedAt time.Time
		if edge.Node.StartedAt != "" {
			startedAt, err = time.Parse(time.RFC3339, string(edge.Node.StartedAt))
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
		}
		interventions = append(interventions, Intervention{
			ID:        string(edge.Node.ID),
			Number:    string(edge.Node.Number),
			Label:     string(edge.Node.Label),
			Status:    string(edge.Node.Status),
			StartedAt: startedAt,
		})
	}

	return interventions, nil
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
