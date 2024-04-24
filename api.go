package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/maelvls/foncia/logutil"
	"github.com/sethgrid/gencurl"
	"github.com/shurcooL/graphql"
	"golang.org/x/oauth2"
)

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

type MissionOrExpense struct {
	Mission *Mission
	Expense *Expense
}

type WorkOrder struct {
	ID              string    // "64850e80df57eb4ade3cf63c"
	Number          string    // "OSMIL802702875"
	Label           string    // "BOUVIER SECURITE INCENDIE - DEMANDE INTERVENTION P"
	RepairDateStart time.Time // "2022-10-18T22:00:00.000Z"
	RepairDateEnd   time.Time // "2022-10-18T22:00:00.000Z"
	Supplier        Supplier
}

type MissionKind string

var (
	Incident MissionKind = "Incident"
	Repair   MissionKind = "Repair"
)

// The `authClient` given as input is only used to authenticate and is not used
// after that. A fresh client is returned.
func authenticatedClient(authClient *http.Client, username string, password secret) (*http.Client, error) {
	enableDebugCurlLogs(authClient)

	token, err := getToken(authClient, username, password)
	if err != nil {
		logutil.Errorf("while authenticating: %v", err)
		os.Exit(1)
	}

	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: string(token)},
	))
	enableDebugCurlLogs(client)

	return client, nil
}

// After getting the token, create a client with the following:
//
//	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
//	    &oauth2.getToken{AccessToken: token},
//	))
//
// The given client isn't mutated.
func getToken(client *http.Client, username string, password secret) (Token, error) {
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
	token := Token(ssoParam[0])

	// We parse the JWT to know when the token expires. We can't verify the JWT
	// because we don't have the public key (and we don't need to verify it),
	// but I trust that the `exp` claim is correct since I trust the server.
	expiry, err := parseJWTExp(string(token))
	if err != nil {
		return "", fmt.Errorf("while parsing JWT: %w", err)
	}
	logutil.Debugf("authentication: token expires in %s (%s)", expiry.Sub(time.Now()).Round(time.Second), expiry)
	return Token(token), nil
}

// Returns the expiry date of the given JWT. WARNING: This func doesn't verify
// the JWT's signature! You must trust the source of the JWT.
func parseJWTExp(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("JWT has %d parts instead of 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("while decoding JWT payload: %w", err)
	}
	var payloadMap map[string]interface{}
	err = json.Unmarshal(payload, &payloadMap)
	if err != nil {
		return time.Time{}, fmt.Errorf("while unmarshaling JWT payload: %w", err)
	}
	exp, found := payloadMap["exp"]
	if !found {
		return time.Time{}, fmt.Errorf("JWT payload does not contain 'exp'")
	}
	expInt, ok := exp.(float64)
	if !ok {
		return time.Time{}, fmt.Errorf("JWT payload 'exp' is not a number")
	}
	expTime := time.Unix(int64(expInt), 0)
	return expTime, nil
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
			// We don't sort by "createdAt" because some entries have the same
			// timestamp, leading to unpredictable ordering, which, combined
			// with pagination, leads to duplicate or missing entries.
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
			// We don't sort by "createdAt" because some entries have the same
			// timestamp, leading to unpredictable ordering, which, combined
			// with pagination, leads to duplicate or missing entries.
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
			ID:              edge.Node.ID,
			Number:          edge.Node.Number,
			Label:           edge.Node.Label,
			RepairDateStart: start,
			RepairDateEnd:   end,
			Supplier: Supplier{
				ID:        edge.Node.Supplier.ID,
				Name:      edge.Node.Supplier.Name,
				FirstName: edge.Node.Supplier.FirstName,
				Activity:  edge.Node.Supplier.Activity,
			},
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
	// Minify the query.
	query = strings.ReplaceAll(query, "\n", " ")
	query = strings.ReplaceAll(query, "\t", " ")
	query = regexp.MustCompile(`\s+`).ReplaceAllString(query, " ")

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

type Supplier struct {
	ID       string
	Name     string // Examples: "2NRT-POMPES ENVIRONNEMENT"
	Activity string // Examples: "PLOM", "ADBE", "ISOL"

	// DB-only fields.
	Document Document

	// Live-only fields.
	FirstName string // Almost always "null".
}

type Document struct {
	ID       string
	HashFile string // Example: "64850e805e5793033297f476"

	// DB-only fields.
	SupplierID string
	FilePath   string // Example: "invoices/2023-03-09_2apf.pdf"
	Filename   string // Example: "2023-03-09_2apf.pdf"

	// Live-only fields.
	OriginalFilename string // Example: "2023-03-09_2apf.pdf"
	MimeType         string // Example: "application/pdf"
	Category         string // Example: "contract"
	CreatedAt        time.Time
}

type Contract struct {
	Supplier  Supplier
	Documents []Document

	// Live-only fields.
	ID          string
	Label       string
	Description string
	Number      string
	EndingDate  string
}

func getCouncilMissionSuppliersLive(client *http.Client, accountUUID string) ([]Contract, error) {
	const getSuppliersQuery = `
		query getCouncilMissionSuppliers(
		  $accountUuid: EncodedID!
		  $first: Int
		  $after: Cursor
		  $description: String
		  $supplierFullname: String
		  $endingDateFrom: String
		  $endingDateTo: String
		) {
		  coownerAccount(uuid: $accountUuid) {
		    uuid
		    trusteeCouncil {
		      supplierContracts(
		        first: $first
		        after: $after
		        description: $description
		        supplierFullname: $supplierFullname
		        endingDateFrom: $endingDateFrom
		        endingDateTo: $endingDateTo
		      ) {
		        pageInfo {
		            endCursor
		            hasNextPage
		        }
		        edges {
		          node {
		            id
		            label
		            description
		            number
		            endingDate
		            supplier {
		                id
		                name
		                firstName
		                activity
		            }
		            documents {
		                id
		                hashFile
		                mimeType
		                originalFilename
		                category
		                createdAt
		            }
		          }
		        }
		      }
		    }
		  }
		}`
	var getCouncilMissionSuppliers struct {
		Data struct {
			CoownerAccount struct {
				UUID           string `json:"uuid"`
				TrusteeCouncil struct {
					SupplierContracts struct {
						PageInfo struct {
							EndCursor   string `json:"endCursor"`
							HasNextPage bool   `json:"hasNextPage"`
						} `json:"pageInfo"`
						Edges []struct {
							Node struct {
								ID          string `json:"id"`
								Label       string `json:"label"`
								Description string `json:"description"`
								Number      string `json:"number"`
								EndingDate  string `json:"endingDate"`
								Supplier    struct {
									ID        string `json:"id"`
									Name      string `json:"name"`
									FirstName string `json:"firstName"`
									Activity  string `json:"activity"`
								} `json:"supplier"`
								Documents []struct {
									ID               string `json:"id"`
									HashFile         string `json:"hashFile"`
									MimeType         string `json:"mimeType"`
									OriginalFilename string `json:"originalFilename"`
									Category         string `json:"category"`
									CreatedAt        string `json:"createdAt"`
								} `json:"documents"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"supplierContracts"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		} `json:"data"`
	}

	err := DoGraphQL(client, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", getSuppliersQuery, map[string]interface{}{
		"accountUuid":      accountUUID,
		"description":      "",
		"supplierFullname": "",
	}, &getCouncilMissionSuppliers)
	if err != nil {
		return nil, fmt.Errorf("error while querying getCouncilMissionSuppliers: %w", err)
	}

	var contracts []Contract
	for _, edge := range getCouncilMissionSuppliers.Data.CoownerAccount.TrusteeCouncil.SupplierContracts.Edges {
		contracts = append(contracts, Contract{
			ID:          edge.Node.ID,
			Label:       edge.Node.Label,
			Description: edge.Node.Description,
			Number:      edge.Node.Number,
			EndingDate:  edge.Node.EndingDate,
			Supplier: Supplier{
				ID:   edge.Node.Supplier.ID,
				Name: edge.Node.Supplier.Name,

				FirstName: edge.Node.Supplier.FirstName,
				Activity:  edge.Node.Supplier.Activity,
			},
			Documents: func() []Document {
				var docs []Document
				for _, doc := range edge.Node.Documents {
					createdAt, err := time.Parse(time.RFC3339, doc.CreatedAt)
					if err != nil {
						logutil.Debugf("error parsing time: %v", err)
						return nil
					}
					docs = append(docs, Document{
						ID:               doc.ID,
						HashFile:         doc.HashFile,
						MimeType:         doc.MimeType,
						OriginalFilename: doc.OriginalFilename,
						Category:         doc.Category,
						CreatedAt:        createdAt,
					})
				}
				return docs
			}(),
		})
	}
	return contracts, nil
}

type Amount int

func (a Amount) String() string {
	// 1234567890 -> 1234567,90 €
	return fmt.Sprintf("%d,%02d €", a/100, a%100)
}

// I use the label + date as a key in the DB. This is because the date isn't
// unique. During an update, we may end up duplicating the same expense, but
// I'll solve that later if that ever happens.
type Expense struct {
	InvoiceID string    // May be empty! Cannot be used as a key.
	HashFile  string    // May be empty! Cannot be used as a key.
	Label     string    // Example: "MADAME-OU CHANNA ENTRETIEN PARTIES COMMUNES 03/2024". May not be unique.
	Date      time.Time // May not be unique.
	Amount    Amount    // Example: 1234567890, which means "1234567,90 €". Negative = credit, positive = debit.

	// DB-only fields.
	FilePath string // Example: "file/path/to/invoice.pdf". Empty when querying live.
	Filename string // Example: "invoice.pdf". Empty when querying live.
}

func getInvoiceURL(client *http.Client, invoiceID string) (string, error) {
	const getInvoiceURLQuery = `query getInvoiceURL($invoiceId: String!) {invoiceURL(invoiceId: $invoiceId)}`
	var getInvoiceURLResp struct {
		Data struct {
			InvoiceURL string `json:"invoiceURL"`
		} `json:"data"`
	}

	err := DoGraphQL(client, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", getInvoiceURLQuery, map[string]interface{}{
		"invoiceId": invoiceID,
	}, &getInvoiceURLResp)
	if err != nil {
		return "", fmt.Errorf("error while querying getInvoiceURLResp: %w", err)
	}

	return getInvoiceURLResp.Data.InvoiceURL, nil
}

func getDocumentURL(client *http.Client, hash string) (string, error) {
	const getDocumentURLQuery = `query getDocumentURL($hash: String!) {documentURL(hash: $hash)}`
	var getDocumentURLResp struct {
		Data struct {
			DocumentURL string `json:"documentURL"`
		} `json:"data"`
	}

	err := DoGraphQL(client, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", getDocumentURLQuery, map[string]interface{}{
		"hash": hash,
	}, &getDocumentURLResp)
	if err != nil {
		return "", fmt.Errorf("error while querying getDocumentURL: %w", err)
	}

	return getDocumentURLResp.Data.DocumentURL, nil
}

func getExpensesCurrentLive(client *http.Client, accountUUID string) ([]Expense, error) {
	const getBuildingAccountingCurrentQuery = `
		query getBuildingAccountingCurrent($uuid: EncodedID!) {
		  coownerAccount(uuid: $uuid) {
		    uuid
		    trusteeCouncil {
		      bankBalance {value currency}
		      accountingCurrent {
		        id
		        openingDate
		        closingDate
		        previousTotal {value currency}
		        votedTotal {value currency}
		        total {value currency}
		        nextVotedTotal {value currency}
		        allocations {
				  id
				  name
				  code
				  previousTotal {value currency}
				  votedTotal {value currency}
				  total {value currency}
				  nextVotedTotal {value currency}
				  expenseTypes {
					id
					allocationId
					name
					code
					previousTotal {value currency}
					votedTotal {value currency}
					total {value currency}
					nextVotedTotal {value currency}
					expenses {
					  invoiceId
					  piece {
						hashFile
					  }
					  label
					  date
					  amount {
						... on Debit {
						  value
						  currency
						  __typename
						}
						... on Credit {
						  value
						  currency
						  __typename
						}
					  }
					  isFromPreviousPeriod
					}
				  }
		        }
		      }
		    }
		  }
		}`
	var getBuildingAccountingCurrentResp struct {
		Data struct {
			CoownerAccount struct {
				TrusteeCouncil struct {
					BankBalance struct {
						Value    int    `json:"value"`
						Currency string `json:"currency"`
					} `json:"bankBalance"`
					AccountingCurrent struct {
						ID            string `json:"id"`
						OpeningDate   string `json:"openingDate"`
						ClosingDate   string `json:"closingDate"`
						PreviousTotal struct {
							Value    int    `json:"value"`
							Currency string `json:"currency"`
						} `json:"previousTotal"`
						VotedTotal struct {
							Value    int    `json:"value"`
							Currency string `json:"currency"`
						} `json:"votedTotal"`
						Total struct {
							Value    int    `json:"value"`
							Currency string `json:"currency"`
						} `json:"total"`
						NextVotedTotal struct {
							Value    int    `json:"value"`
							Currency string `json:"currency"`
						} `json:"nextVotedTotal"`
						Allocations []struct {
							ID            string `json:"id"`
							Name          string `json:"name"`
							Code          string `json:"code"`
							PreviousTotal struct {
								Value    int    `json:"value"`
								Currency string `json:"currency"`
							} `json:"previousTotal"`
							VotedTotal struct {
								Value    int    `json:"value"`
								Currency string `json:"currency"`
							} `json:"votedTotal"`
							Total struct {
								Value    int    `json:"value"`
								Currency string `json:"currency"`
							} `json:"total"`
							NextVotedTotal struct {
								Value    int    `json:"value"`
								Currency string `json:"currency"`
							} `json:"nextVotedTotal"`
							ExpenseTypes []struct {
								ID            string `json:"id"`
								AllocationID  string `json:"allocationId"`
								Name          string `json:"name"`
								Code          string `json:"code"`
								PreviousTotal struct {
									Value    int    `json:"value"`
									Currency string `json:"currency"`
								} `json:"previousTotal"`
								VotedTotal struct {
									Value    int    `json:"value"`
									Currency string `json:"currency"`
								} `json:"votedTotal"`
								Total struct {
									Value    int    `json:"value"`
									Currency string `json:"currency"`
								} `json:"total"`
								NextVotedTotal struct {
									Value    int    `json:"value"`
									Currency string `json:"currency"`
								} `json:"nextVotedTotal"`
								Expenses []struct {
									InvoiceID string `json:"invoiceId"`
									Piece     struct {
										HashFile string `json:"hashFile"`
									} `json:"piece"`
									Label string `json:"label"`
									Date  string `json:"date"`
									// This is a union type, "Debit" or "Credit".
									Amount struct {
										Value    int    `json:"value"`
										Currency string `json:"currency"`
										Typename string `json:"__typename"`
									} `json:"amount"`
									IsFromPreviousPeriod bool `json:"isFromPreviousPeriod"`
								} `json:"expenses"`
							} `json:"expenseTypes"`
						} `json:"allocations"`
					} `json:"accountingCurrent"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		} `json:"data"`
	}

	err := DoGraphQL(client, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", getBuildingAccountingCurrentQuery, map[string]interface{}{
		"uuid": accountUUID,
	}, &getBuildingAccountingCurrentResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getBuildingAccountingCurrentResp: %w", err)
	}

	var expenses []Expense
	for _, allocation := range getBuildingAccountingCurrentResp.Data.CoownerAccount.TrusteeCouncil.AccountingCurrent.Allocations {
		for _, expenseType := range allocation.ExpenseTypes {
			for _, expense := range expenseType.Expenses {
				var amount int
				switch expense.Amount.Typename {
				case "Credit":
					amount = -expense.Amount.Value
				case "Debit":
					amount = expense.Amount.Value
				default:
					return nil, fmt.Errorf("unexpected typename %q for expense %+v", expense.Amount.Typename, expense)
				}
				var date time.Time
				if expense.Date != "" {
					var err error
					date, err = time.Parse(time.RFC3339, expense.Date)
					if err != nil {
						return nil, fmt.Errorf("error parsing time: %w", err)
					}
				}
				expenses = append(expenses, Expense{
					InvoiceID: expense.InvoiceID,
					HashFile:  expense.Piece.HashFile,
					Label:     expense.Label,
					Date:      date,
					Amount:    Amount(amount),
				})
			}
		}
	}

	return expenses, nil
}

type AccountingPeriod struct {
	ID          string
	Name        string
	OpeningDate time.Time
	ClosingDate time.Time
	Status      string
}

//		query getAccountingPeriods($accountUuid: EncodedID!, $sortBy: [SortByType!], $status: [AccountingPeriodStatusEnum!], $closingDateTo: String, $first: Int, $before: Cursor, $after: Cursor) {
//		  coownerAccount(uuid: $accountUuid) {
//		    uuid
//		    trusteeCouncil {
//		      accountingPeriods(
//		        first: $first
//		        before: $before
//		        after: $after
//		        sortBy: $sortBy
//		        status: $status
//		        closingDateTo: $closingDateTo
//		      ) {
//		        totalCount
//		        pageInfo {
//		          startCursor
//		          endCursor
//		          hasPreviousPage
//		          hasNextPage
//		        }
//		        edges {
//		          node {
//		            id
//	             name
//	             openingDate
//	             closingDate
//	             status
//		          }
//		        }
//		      }
//		    }
//		  }
//		}
func getAccountingPeriodsLive(client *http.Client, accountUUID string) ([]AccountingPeriod, error) {
	const getAccountingPeriodsQuery = `
		query getAccountingPeriods($accountUuid: EncodedID!, $sortBy: [SortByType!], $status: [AccountingPeriodStatusEnum!], $closingDateTo: String, $first: Int, $before: Cursor, $after: Cursor) {
		  coownerAccount(uuid: $accountUuid) {
		    uuid
		    trusteeCouncil {
		      accountingPeriods(
		        first: $first
		        before: $before
		        after: $after
		        sortBy: $sortBy
		        status: $status
		        closingDateTo: $closingDateTo
		      ) {
		        totalCount
		        pageInfo {
		          startCursor
		          endCursor
		          hasPreviousPage
		          hasNextPage
		        }
		        edges {
		          node {
		            id
		            name
		            openingDate
		            closingDate
		            status
		          }
		        }
		      }
		    }
		  }
		}`
	var getAccountingPeriodsResp struct {
		Data struct {
			CoownerAccount struct {
				TrusteeCouncil struct {
					AccountingPeriods struct {
						TotalCount int `json:"totalCount"`
						PageInfo   struct {
							StartCursor     string `json:"startCursor"`
							EndCursor       string `json:"endCursor"`
							HasPreviousPage bool   `json:"hasPreviousPage"`
							HasNextPage     bool   `json:"hasNextPage"`
						} `json:"pageInfo"`
						Edges []struct {
							Node struct {
								ID          string `json:"id"`
								Name        string `json:"name"`
								OpeningDate string `json:"openingDate"`
								ClosingDate string `json:"closingDate"`
								Status      string `json:"status"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"accountingPeriods"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		} `json:"data"`
	}

	err := DoGraphQL(client, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", getAccountingPeriodsQuery, map[string]interface{}{
		"accountUuid": accountUUID,
	}, &getAccountingPeriodsResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getAccountingPeriodsResp: %w", err)
	}

	var periods []AccountingPeriod
	for _, edge := range getAccountingPeriodsResp.Data.CoownerAccount.TrusteeCouncil.AccountingPeriods.Edges {
		var openingDate, closingDate time.Time
		if edge.Node.OpeningDate != "" {
			var err error
			openingDate, err = time.Parse(time.RFC3339, edge.Node.OpeningDate)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
		}
		if edge.Node.ClosingDate != "" {
			var err error
			closingDate, err = time.Parse(time.RFC3339, edge.Node.ClosingDate)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
		}
		periods = append(periods, AccountingPeriod{
			ID:          edge.Node.ID,
			Name:        edge.Node.Name,
			OpeningDate: openingDate,
			ClosingDate: closingDate,
			Status:      edge.Node.Status,
		})
	}
	return periods, nil
}

// query getBuildingAccountingRGDD($uuid: EncodedID!, $accountingPeriodId: String) {\n  coownerAccount(uuid: $uuid) {\n    uuid\n    trusteeCouncil {\n      pastAccountingRGDD(accountingPeriodId: $accountingPeriodId) {\n        totalToAllocate {\n          ...amount\n          __typename\n        }\n        totalVat {\n          ...amount\n          __typename\n        }\n        totalRecoverable {\n          ...amount\n          __typename\n        }\n        allocations {\n          ...allocation\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment amount on Amount {\n  value\n  currency\n  __typename\n}\n\nfragment allocation on Allocation {\n  id\n  name\n  code\n  toAllocate {\n    ...amount\n    __typename\n  }\n  vat {\n    ...amount\n    __typename\n  }\n  recoverable {\n    ...amount\n    __typename\n  }\n  expenseTypes {\n    ...expenseType\n    __typename\n  }\n  __typename\n}\n\nfragment expenseType on ExpenseType {\n  id\n  allocationId\n  name\n  code\n  toAllocate {\n    ...amount\n    __typename\n  }\n  vat {\n    ...amount\n    __typename\n  }\n  recoverable {\n    ...amount\n    __typename\n  }\n  expenses {\n    ...expense\n    __typename\n  }\n  __typename\n}\n\nfragment expense on Expense {\n  id\n  label\n  date\n  invoiceId\n  piece {\n    hashFile\n    category\n    id\n    __typename\n  }\n  toAllocate {\n    ...amount\n    __typename\n  }\n  vat {\n    ...amount\n    __typename\n  }\n  recoverable {\n    ...amount\n    __typename\n  }\n  __typename\n}
func getBuildingAccountingRGDDLive(client *http.Client, accountUUID, accountingPeriodID string) ([]Expense, error) {
	const getBuildingAccountingRGDDQuery = `
		query getBuildingAccountingRGDD($uuid: EncodedID!, $accountingPeriodId: String) {
		  coownerAccount(uuid: $uuid) {
		    uuid
		    trusteeCouncil {
		      pastAccountingRGDD(accountingPeriodId: $accountingPeriodId) {
		        totalToAllocate {
		          value
		          currency
		        }
		        totalVat {
		          value
		          currency
		        }
		        totalRecoverable {
		          value
		          currency
		        }
		        allocations {
		          id
		          name
		          code
		          toAllocate {
		            value
		            currency
		          }
		          vat {
		            value
		            currency
		          }
		          recoverable {
		            value
		            currency
		          }
		          expenseTypes {
		            id
		            allocationId
		            name
		            code
		            toAllocate {
		              value
		              currency
		            }
		            vat {
		              value
		              currency
		            }
		            recoverable {
		              value
		              currency
		            }
		            expenses {
		              id
		              label
		              date
		              invoiceId
		              piece {
		                hashFile
		                category
		                id
		              }
		              toAllocate {
		                value
		                currency
		              }
		              vat {
		                value
		                currency
		              }
		              recoverable {
		                value
		                currency
		              }
		            }
		          }
		        }
		      }
		    }
		  }
		}`
	var getBuildingAccountingRGDDResp struct {
		Data struct {
			CoownerAccount struct {
				TrusteeCouncil struct {
					PastAccountingRGDD struct {
						TotalToAllocate struct {
							Value    int    `json:"value"`
							Currency string `json:"currency"`
						} `json:"totalToAllocate"`
						TotalVat struct {
							Value    int    `json:"value"`
							Currency string `json:"currency"`
						} `json:"totalVat"`
						TotalRecoverable struct {
							Value    int    `json:"value"`
							Currency string `json:"currency"`
						} `json:"totalRecoverable"`
						Allocations []struct {
							ID         string `json:"id"`
							Name       string `json:"name"`
							Code       string
							ToAllocate struct {
								Value    int    `json:"value"`
								Currency string `json:"currency"`
							} `json:"toAllocate"`
							Vat struct {
								Value    int    `json:"value"`
								Currency string `json:"currency"`
							} `json:"vat"`
							Recoverable struct {
								Value    int    `json:"value"`
								Currency string `json:"currency"`
							} `json:"recoverable"`
							ExpenseTypes []struct {
								ID           string `json:"id"`
								AllocationID string `json:"allocationId"`
								Name         string `json:"name"`
								Code         string
								ToAllocate   struct {
									Value    int    `json:"value"`
									Currency string `json:"currency"`
								} `json:"toAllocate"`
								Vat struct {
									Value    int    `json:"value"`
									Currency string `json:"currency"`
								} `json:"vat"`
								Recoverable struct {
									Value    int    `json:"value"`
									Currency string `json:"currency"`
								} `json:"recoverable"`
								Expenses []struct {
									ID        string `json:"id"`
									Label     string `json:"label"`
									Date      string `json:"date"`
									InvoiceID string `json:"invoiceId"`
									Piece     struct {
										HashFile string `json:"hashFile"`
										Category string `json:"category"`
										ID       string `json:"id"`
									} `json:"piece"`
									ToAllocate struct {
										Value    int    `json:"value"`
										Currency string `json:"currency"`
									} `json:"toAllocate"`
									Vat struct {
										Value    int    `json:"value"`
										Currency string `json:"currency"`
									} `json:"vat"`
									Recoverable struct {
										Value    int    `json:"value"`
										Currency string `json:"currency"`
									} `json:"recoverable"`
								} `json:"expenses"`
							} `json:"expenseTypes"`
						} `json:"allocations"`
					} `json:"pastAccountingRGDD"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		} `json:"data"`
	}

	err := DoGraphQL(client, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", getBuildingAccountingRGDDQuery, map[string]interface{}{
		"uuid":               accountUUID,
		"accountingPeriodId": accountingPeriodID,
	}, &getBuildingAccountingRGDDResp)

	if err != nil {
		return nil, fmt.Errorf("error while querying getBuildingAccountingRGDDResp: %w", err)
	}

	var expenses []Expense
	for _, allocation := range getBuildingAccountingRGDDResp.Data.CoownerAccount.TrusteeCouncil.PastAccountingRGDD.Allocations {
		for _, expenseType := range allocation.ExpenseTypes {
			for _, expense := range expenseType.Expenses {
				var date time.Time
				if expense.Date != "" {
					var err error
					date, err = time.Parse(time.RFC3339, expense.Date)
					if err != nil {
						return nil, fmt.Errorf("error parsing time: %w", err)
					}
				}
				expenses = append(expenses, Expense{
					InvoiceID: expense.InvoiceID,
					HashFile:  expense.Piece.HashFile,
					Label:     expense.Label,
					Date:      date,
					Amount:    Amount(expense.ToAllocate.Value),
				})
			}
		}
	}
	return expenses, nil
}

// Returns the path to the downloaded file relative to the current folder.
// Example, if `invoicesDir` is "invoices":
//
//	path:     "invoices/2024-04-05_2APF.pdf"
func download(fileURL string, invoicesDir string) (path string, _ error) {
	// No need to use the authenticated client here since the URL is
	// authenticated using one of the query parameters.
	resp, err := http.Get(fileURL)
	if err != nil {
		return "", fmt.Errorf("while downloading invoice: %v", err)
	}
	defer resp.Body.Close()
	// Example:
	//  x-amz-id-2: LYkuTg0aWoXYJfRSsy2CF+BBAFZJB7Fmt6pLoGb34Yta62/CDmp63ank88BDQQ2itWWHAWwGRAA=
	//  x-amz-request-id: 1YW04QB3HZTWXHSN
	//  Date: Fri, 05 Apr 2024 18:31:17 GMT
	//  x-amz-replication-status: COMPLETED
	//  Last-Modified: Tue, 02 Apr 2024 06:42:18 GMT
	//  ETag: "3ce4db0dc63cd2ef935f316181b0fed5"
	//  x-amz-server-side-encryption: AES256
	//  x-amz-version-id: k628Oenqp4qoDYl3cNHu59gBK2PIBqpK
	//  Content-Disposition: filename="ALPES%20CONTROLES%20-%20OSMIL802674431%20-%202024-02-16%20-%202431007J.pdf"
	//  Accept-Ranges: bytes
	//  Content-Type: application/pdf
	//  Server: AmazonS3
	//  Content-Length: 370642

	// Grab the HTTP headers that contain the file type, size, and name.
	// This is useful for debugging.
	disposition := resp.Header.Get("Content-Disposition")
	if !strings.HasPrefix(disposition, "attachment;") {
		disposition = "attachment;" + disposition
	}

	// Parse the filename from the Content-Disposition header.
	// Example:
	//     filename="example.pdf"
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return "", fmt.Errorf("while parsing Content-Disposition: %v", err)
	}
	filename := params["filename"]
	if filename == "" {
		return "", fmt.Errorf("no filename in Content-Disposition header")
	}

	// URL decode the filename.
	filename, err = url.QueryUnescape(filename)
	if err != nil {
		return "", fmt.Errorf("while URL-decoding filename: %v", err)
	}

	// Replace all characters that are not allowed in a filename with an
	// underscore.
	// [^\d\.\-_~,;:\[\]\(\]]
	filename = strings.Map(func(r rune) rune {
		switch {
		case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9',
			r == '.', r == '-', r == '_', r == '~', r == ',', r == ';', r == ':',
			r == '[', r == ']', r == '(', r == ')' || r == ' ':
			return r
		default:
			return '_'
		}
	}, filename)

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", fmt.Errorf("while reading file: %v", err)
	}

	path = invoicesDir + "/" + filename
	err = os.WriteFile(path, buf.Bytes(), 0644)
	if err != nil {
		return "", fmt.Errorf("while saving file to disk: %v", err)
	}

	return path, nil
}

type secret string

func (p secret) String() string {
	return "redacted"
}

func (p secret) Raw() string {
	return string(p)
}

type Token string

func (t Token) String() string {
	return "redacted"
}
