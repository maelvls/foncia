package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudmailin/cloudmailin-go"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
	"github.com/sethgrid/gencurl"
	"github.com/shurcooL/graphql"
	"golang.org/x/oauth2"
)

type MissionAPI struct {
	ID          string         // "64850e8019d5d64c415d13dd"
	Number      string         // "7000YRK51"
	Label       string         // "ATELIER METALLERIE FERRONNERIE - VALIDATION DEVIS "
	Status      string         // "WORK_IN_PROGRESS"
	StartedAt   time.Time      // "2023-04-24T22:00:00.000Z" (time.RFC3339)
	Description string         // "BONJOUR,\n\nVEUILLEZ ENREGISTER LE C02\t\nMERCI CORDIALEMENT"
	Kind        MissionKindAPI // "Incident" | "Repair"
	WorkOrders  []WorkOrderAPI
}

type WorkOrderAPI struct {
	ID              string    // "64850e80df57eb4ade3cf63c"
	Number          string    // "OSMIL802702875"
	Label           string    // "BOUVIER SECURITE INCENDIE - DEMANDE INTERVENTION P"
	RepairDateStart time.Time // "2022-10-18T22:00:00.000Z"
	RepairDateEnd   time.Time // "2022-10-18T22:00:00.000Z"
	Supplier        SupplierAPI
}

type MissionKindAPI string

var (
	Incident MissionKindAPI = "Incident"
	Repair   MissionKindAPI = "Repair"
)

// The `authClient` given as input is only used to authenticate and is not used
// after that. A fresh client is returned.
func AuthenticatedClient(authClient *http.Client, graphqlURL, username string, password Password) (*http.Client, error) {
	EnableDebugCurlLogs(authClient)

	token, err := GetToken(authClient, graphqlURL, username, password)
	if err != nil {
		logutil.Errorf("while authenticating: %v", err)
		os.Exit(1)
	}

	return AuthenticatedClientToken(token), nil
}

func AuthenticatedClientToken(token Token) *http.Client {
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: string(token)},
	))
	EnableDebugCurlLogs(client)
	return client
}

// Detect when 429 too many requests is returned by the server.
func IsTooManyRequests(body []byte) bool {
	var resp struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	err := json.Unmarshal(body, &resp)
	if err != nil {
		return false
	}
	for _, err := range resp.Errors {
		if err.Message == "429: Too Many Requests" {
			return true
		}
	}
	return false
}

// After getting the token, create a client with the following:
//
//	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
//	    &oauth2.getToken{AccessToken: token},
//	))
//
// The given client isn't mutated.
//
//	curl 'https://myfoncia-gateway.prod.fonciamillenium.net/graphql' \
//	  -H 'accept: */*' \
//	  -H 'accept-language: en-US,en;q=0.9,fr;q=0.8,fr-FR;q=0.7' \
//	  -H 'authorization;' \
//	  -H 'content-type: application/json' \
//	  -H 'origin: https://my-foncia.fonciamillenium.net' \
//	  -H 'priority: u=1, i' \
//	  -H 'referer: https://my-foncia.fonciamillenium.net/' \
//	  -H 'sec-ch-ua: "Not A(Brand";v="8", "Chromium";v="132", "Microsoft Edge";v="132"' \
//	  -H 'sec-ch-ua-mobile: ?0' \
//	  -H 'sec-ch-ua-platform: "macOS"' \
//	  -H 'sec-fetch-dest: empty' \
//	  -H 'sec-fetch-mode: cors' \
//	  -H 'sec-fetch-site: same-site' \
//	  -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0' \
//	  --data-raw $'{"query":"mutation login($request: LoginRequest\u0021) {\\n  login(request: $request) {\\n    token\\n    __typename\\n  }\\n}","variables":{"request":{"username":"","password":"","appId":"myfoncia"}},"operationName":"login"}'
func GetToken(client *http.Client, graphqlURL, username string, password Password) (Token, error) {
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

	query := `mutation login($request: LoginRequest!) {
		login(request: $request) {
			token
			__typename
		}
	}`

	type LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
		AppID    string `json:"appId"`
	}
	var loginResp struct {
		Data struct {
			Login struct {
				Token string `json:"token"`
			} `json:"login"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	err = DoGraphQL(client, graphqlURL, query, map[string]any{
		"request": LoginRequest{
			Username: username,
			Password: password.Raw(),
			AppID:    "myfoncia",
		},
	}, &loginResp)
	if err != nil {
		return "", fmt.Errorf("error while querying loginResp: %w", err)
	}

	if len(loginResp.Errors) > 0 {
		return "", fmt.Errorf("error while logging in: %s", loginResp.Errors[0].Message)
	}

	// We parse the JWT to know when the token expires. We can't verify the JWT
	// because we don't have the public key (and we don't need to verify it),
	// but I trust that the `exp` claim is correct since I trust the server.
	expiry, err := parseJWTExp(string(loginResp.Data.Login.Token))
	if err != nil {
		return "", fmt.Errorf("while parsing JWT: %w", err)
	}

	logutil.Debugf("authentication: token expires in %s (%s)", expiry.Sub(time.Now()).Round(time.Second), expiry)
	return Token(loginResp.Data.Login.Token), nil
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
	var payloadMap map[string]any
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
// `fromCursor` allows you to skip missions that you already have.
func GetMissionsAPI(client *http.Client, graphqlURL, accountUUID string, fromCursor string) (_ []MissionAPI, lastCursor string, _ error) {
	var interventions []MissionAPI

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
	if fromCursor != "" {
		cursor = &fromCursor
	}
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
		err := DoGraphQL(client, graphqlURL, getIncidentsQuery, map[string]any{
			"accountUuid": accountUUID,
			"first":       perPage,
			"after":       cursor,
			// We don't sort by "createdAt" because some entries have the same
			// timestamp, leading to unpredictable ordering, which, combined
			// with pagination, leads to duplicate or missing entries.
		}, &getIncidentsResp)
		if err != nil {
			return nil, "", fmt.Errorf("error while querying getIncidentsResp: %w", err)
		}

		for _, edge := range getIncidentsResp.Data.CoownerAccount.TrusteeCouncil.MissionIncidents.Edges {
			var startedAt time.Time
			if edge.Node.StartedAt != "" {
				var err error
				startedAt, err = time.Parse(time.RFC3339Nano, edge.Node.StartedAt)
				if err != nil {
					logutil.Debugf("error parsing time: %v", err)
					return nil, "", fmt.Errorf("error parsing time: %w", err)
				}
			}
			interventions = append(interventions, MissionAPI{
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
		err := DoGraphQL(client, graphqlURL, getRepairsQuery, map[string]any{
			"accountUuid": accountUUID,
			"first":       perPage,
			"after":       cursor,
			// We don't sort by "createdAt" because some entries have the same
			// timestamp, leading to unpredictable ordering, which, combined
			// with pagination, leads to duplicate or missing entries.
		}, &getRepairsResp)
		if err != nil {
			return nil, "", fmt.Errorf("error while querying getRepairsResp: %w", err)
		}

		for _, edge := range getRepairsResp.Data.CoownerAccount.TrusteeCouncil.MissionRepairs.Edges {
			var startedAt time.Time
			if edge.Node.StartedAt != "" {
				startedAt, err = time.Parse(time.RFC3339Nano, edge.Node.StartedAt)
				if err != nil {
					return nil, "", fmt.Errorf("error parsing time: %w", err)
				}
			}
			interventions = append(interventions, MissionAPI{
				ID:          edge.Node.ID,
				Number:      edge.Node.Number,
				Label:       edge.Node.Label,
				Status:      edge.Node.Status,
				StartedAt:   startedAt,
				Description: edge.Node.Description,
				Kind:        Repair,
			})
		}

		cursor = &getRepairsResp.Data.CoownerAccount.TrusteeCouncil.MissionRepairs.PageInfo.EndCursor
		if !getRepairsResp.Data.CoownerAccount.TrusteeCouncil.MissionRepairs.PageInfo.HasNextPage {
			break
		}

		pageCount++
		if pageCount == pagesLimit {
			break
		}
	}

	sort.Slice(interventions, func(i, j int) bool {
		return interventions[i].StartedAt.After(interventions[j].StartedAt)
	})
	// The `cursor` pointer must be not nil if we are getting here. If it is
	// nil, it means that an error occurred above, which should have returned.
	return interventions, *cursor, nil
}

func GetWorkOrdersAPI(client *http.Client, graphqlURL, accountUUID, missionID string) (_ []WorkOrderAPI, _ error) {
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

	err := DoGraphQL(client, graphqlURL, getWorkOrders, map[string]any{
		"accountUuid": accountUUID,
		"missionId":   missionID,
		"first":       100,
	}, &getWorkOrdersResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getWorkOrdersResp for mission %s: %w", missionID, err)
	}

	var orders []WorkOrderAPI
	for _, edge := range getWorkOrdersResp.Data.WorkOrders.Edges {
		var start, end time.Time
		if edge.Node.RepairDate.Start != "" {
			start, err = time.Parse(time.RFC3339Nano, edge.Node.RepairDate.Start)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
		}
		if edge.Node.RepairDate.End != "" {
			end, err = time.Parse(time.RFC3339Nano, edge.Node.RepairDate.End)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
		}

		orders = append(orders, WorkOrderAPI{
			ID:              edge.Node.ID,
			Number:          edge.Node.Number,
			Label:           edge.Node.Label,
			RepairDateStart: start,
			RepairDateEnd:   end,
			Supplier: SupplierAPI{
				ID:        edge.Node.Supplier.ID,
				Name:      edge.Node.Supplier.Name,
				FirstName: edge.Node.Supplier.FirstName,
				Activity:  edge.Node.Supplier.Activity,
			},
		})
	}

	return orders, nil
}

func EnableDebugCurlLogs(client *http.Client) {
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
func DoGraphQL[T any](client *http.Client, url, query string, variables map[string]any, resp T) error {
	// Minify the query.
	query = strings.ReplaceAll(query, "\n", " ")
	query = strings.ReplaceAll(query, "\t", " ")
	query = regexp.MustCompile(`\s+`).ReplaceAllString(query, " ")

	req := struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}{
		Query:     query,
		Variables: variables,
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("error marshaling request body: %w", err)
	}
	httpResp, err := Do(client, http.MethodPost, url, reqBody)
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

type SupplierAPI struct {
	ID        string
	Name      string // Examples: "2NRT-POMPES ENVIRONNEMENT"
	Activity  string // Examples: "PLOM", "ADBE", "ISOL"
	FirstName string // Almost always "null".
}

type SupplierContractAPI struct {
	ID          string
	Label       string
	Description string
	Number      string
	EndingDate  time.Time
	Supplier    SupplierAPI
	Documents   []DocumentAPI
}

type DocumentAPI struct {
	ID               string
	HashFile         db.HashFile // Only set when a document is attached. Example: "64850e805e5793033297f476"
	OriginalFilename string      // Example: "2023-03-09_2apf.pdf"
	MimeType         string      // Example: "application/pdf"
	Category         string      // Example: "contract", "reportVisit", "councilReportVisit"
	CreatedAt        time.Time   // Example: "2023-03-09T22:00:00.000Z"
}

func GetCouncilMissionSuppliersAPI(client *http.Client, graphqlURL, accountUUID string) ([]SupplierContractAPI, error) {
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

	err := DoGraphQL(client, graphqlURL, getSuppliersQuery, map[string]any{
		"accountUuid":      accountUUID,
		"description":      "",
		"supplierFullname": "",
		"first":            100,
	}, &getCouncilMissionSuppliers)
	if err != nil {
		return nil, fmt.Errorf("error while querying getCouncilMissionSuppliers: %w", err)
	}

	var contracts []SupplierContractAPI
	for _, edge := range getCouncilMissionSuppliers.Data.CoownerAccount.TrusteeCouncil.SupplierContracts.Edges {
		var endingDate time.Time
		if edge.Node.EndingDate != "" {
			endingDate, err = time.Parse(time.RFC3339Nano, edge.Node.EndingDate)
			if err != nil {
				logutil.Errorf("error parsing time: %v", err)
				continue
			}
		}

		var docs []DocumentAPI
		for _, doc := range edge.Node.Documents {
			createdAt, err := time.Parse(time.RFC3339Nano, doc.CreatedAt)
			if err != nil {
				logutil.Errorf("error parsing time: %v", err)
				continue
			}
			docs = append(docs, DocumentAPI{
				ID:               doc.ID,
				HashFile:         db.HashFile(doc.HashFile),
				OriginalFilename: doc.OriginalFilename,
				MimeType:         doc.MimeType,
				Category:         doc.Category,
				CreatedAt:        createdAt,
			})
		}

		contracts = append(contracts, SupplierContractAPI{
			ID:          edge.Node.ID,
			Label:       edge.Node.Label,
			Description: edge.Node.Description,
			Number:      edge.Node.Number,
			EndingDate:  endingDate,
			Supplier: SupplierAPI{
				ID:        edge.Node.Supplier.ID,
				Name:      edge.Node.Supplier.Name,
				FirstName: edge.Node.Supplier.FirstName,
				Activity:  edge.Node.Supplier.Activity,
			},
			Documents: docs,
		})
	}
	return contracts, nil
}

type ExpenseDocumentAPI struct {
	// Only set when a document is attached. E.g., "64850e805e5793033297f476".
	// We use that as an ID for the expense document since we don't have any
	// other way. Note that the API sometimes returns expense documents that
	// don't have an invoice ID. If you are using this as an ID, you should skip
	// those.
	InvoiceID string
	Label     string      // Example: "MADAME-OU CHANNA ENTRETIEN PARTIES COMMUNES 03/2024". May not be unique.
	Amount    db.Amount   // Example: 1234567890, which means "1234567,90 €". Negative = credit, positive = debit.
	Date      time.Time   // May not be unique. Example: "2024-03-01T00:00:00.000Z". Use time.RFC3339Nano to marshall.
	HashFile  db.HashFile // Only set when a document is attached. Example: "66fbf2a9294cd8ed17d7ce9a"

	AccountingAllocation  string // Example: "CHARGES GENERALES"
	AccountingExpenseType string // Example: "CONTRAT D'ENTRETIEN"
}

var ErrEmptyURL = fmt.Errorf("empty URL")

// Important: don't call getInvoiceURL if invoiceID exists but the hashFile is
// empty. If that's the case, the invoice PDF doesn't exist, and getInvoiceURL
// will return an empty URL. To know if the URL returned was empty:
//
//	errors.Is(err, api.ErrEmptyURL)
func GetInvoiceURL(client *http.Client, graphqlURL, invoiceID string) (filename, fileURL string, _ error) {
	const getInvoiceURLQuery = `query getInvoiceURL($invoiceId: String!) {invoiceURL(invoiceId: $invoiceId)}`
	var getInvoiceURLResp struct {
		Data struct {
			InvoiceURL string `json:"invoiceURL"`
		} `json:"data"`
	}

	err := DoGraphQL(client, graphqlURL, getInvoiceURLQuery, map[string]any{
		"invoiceId": invoiceID,
	}, &getInvoiceURLResp)
	if err != nil {
		return "", "", fmt.Errorf("while querying getInvoiceURLResp: %w", err)
	}

	if getInvoiceURLResp.Data.InvoiceURL == "" {
		return "", "", fmt.Errorf("getInvoiceURL: %w", ErrEmptyURL)
	}

	filename, err = getFilenameFromURL(getInvoiceURLResp.Data.InvoiceURL)
	if err != nil {
		return "", "", fmt.Errorf("while getting filename from %s: %w", getInvoiceURLResp.Data.InvoiceURL, err)
	}

	return filename, getInvoiceURLResp.Data.InvoiceURL, nil
}

// To know if the URL returned was empty:
//
//	errors.Is(err, api.ErrEmptyURL)
func GetDocumentURL(client *http.Client, graphqlURL string, hash db.HashFile) (filename, fileURL string, _ error) {
	const getDocumentURLQuery = `query getDocumentURL($hash: String!) {documentURL(hash: $hash)}`
	var getDocumentURLResp struct {
		Data struct {
			DocumentURL string `json:"documentURL"`
		} `json:"data"`
	}

	err := DoGraphQL(client, graphqlURL, getDocumentURLQuery, map[string]any{
		"hash": hash,
	}, &getDocumentURLResp)
	if err != nil {
		return "", "", fmt.Errorf("error while querying getDocumentURL: %w", err)
	}

	if getDocumentURLResp.Data.DocumentURL == "" {
		return "", "", fmt.Errorf("getDocumentURL: %w", ErrEmptyURL)
	}

	filename, err = getFilenameFromURL(getDocumentURLResp.Data.DocumentURL)
	if err != nil {
		return "", "", fmt.Errorf("error getting filename from URL: %w", err)
	}
	return filename, getDocumentURLResp.Data.DocumentURL, nil
}

// The URLs are short-lived and look like this:
// https://fon-mil-prod-plato-prv.s3.eu-west-3.amazonaws.com/e/6/6/6/2/674836bfb753160398ee6662?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAXMTESETVHY3LHMDR%2F20250129%2Feu-west-3%2Fs3%2Faws4_request&X-Amz-Date=20250129T171628Z&X-Amz-Expires=900&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIf%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMyJHMEUCIQDj8iWPBGZspCL2CUSMniDTOhPCKTr8o17mjxtWdO00UwIgL4D1u5DtZfYCKCEpUX78c0b4SDYeR2VddKGkGdcNdpIqgAQIkP%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARACGgw1MDgwOTA3ODcwNTAiDN51Bas9kmYPyShHAyrUA7wx2z79PWterZcfjBNa1kQmpd1SESDoHBUV05Bv%2FW2HIiGMDBVv1l1B4Xa4hH3ixDokqYjttUqbOde3oJLgKzhdSRx8AKWtNLxGFGRKg49bEi6TC2SjuOFCd51ZGOcLxRY1EnyP9jr9CaDsDk%2FJDurkEdInf8ASH56pXwpaz4BhCSn7PKexefL7YNfNmYFl0u9LAXR24%2FOCngnLP%2Fug0klrN3qttY50MxiLvKN1nnjwpBIr%2FMeGexwf0btY4LWgh6ipWURmdsCHyMQtfkn%2B7sAhQ3ujUXmcrRrTcffaqDckJEkfC2Od7y4CnTNWrHdgWrkR2ksD8pfjIrL4Iv2Ct8IhKaGmlG0sbiP5YprFHmLA1nkr87buei8EOkTfSiuZu%2FKGaWcYHOzdGQitRBeT4MZkNd4uOL%2F6V62ncHHP8MoD%2BXIBcQkL7W1cUkMXrkyHT6VaDGiEXLJ1J7Y194wE0uJq6XTfGtJc2SEzMDm4wN2TvSBUAjBo1RAmEDzMSV6evXNCv2oATxufxKDQ0HLJ0Dq6IWsm0pbMwc2n1pjdx9aHFpFd9U%2BJHwjruKQfpTbY2LYxc2LhkhHlW0xH2UzXWxO94eU%2BVIZLFiy2yuEUBVggIgTVCDDXhum8BjqlAdxyOC29dGCIo%2F3dk1vvqbzAppsm4mKv0TjM45BOiReDsu%2FPpEpLd1klWv7iWuW%2BG8uqQr0Gilfbt6y%2F6I5eOzYlm%2BfmYWCOPxVFAaR1iosjwpmpOKmDxow6O4CvntbXC1TgE8gUb3WLI45xq1A2kYMD9PjgoiZj01hia1qwh47bptY8%2BOnkCfF1UByAm2nis9fd5P75QLRVj%2B8DLqKbahlQ0O7jsA%3D%3D&X-Amz-Signature=7c1094dee2ee4812de265c48533846f9a353a4be234180ed47b0d772c91dcbd6&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22IZQUIERDO%2520-%2520OSMIL806596688%2520-%25202024-11-28%2520-%252025-074.pdf%22&x-id=GetObject
//
// The file path is deduced from from one of the URL's query parameters:
//
//	response-content-disposition=filename%3D%22IZQUIERDO%2520-%2520OSMIL806596688%2520-%25202024-11-28%2520-%252025-074.pdf%22
func getFilenameFromURL(fileURL string) (string, error) {
	u, err := url.Parse(fileURL)
	if err != nil {
		return "", fmt.Errorf("error parsing URL: %w", err)
	}
	q := u.Query()
	disposition := q.Get("response-content-disposition")
	if disposition == "" {
		return "", fmt.Errorf("could not find response-content-disposition in URL: %s", fileURL)
	}

	// Ensure that the Content-Disposition header starts with "attachment;".
	// Otherwise, can't use mime.ParseMediaType.
	if !strings.HasPrefix(disposition, "attachment;") {
		disposition = "attachment;" + disposition
	}

	// Parse the filename from the Content-Disposition header.
	// Example:
	//     filename="example.pdf"
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return "", fmt.Errorf("while parsing response-content-disposition: %v", err)
	}
	filename := params["filename"]
	if filename == "" {
		return "", fmt.Errorf("no filename in response-content-disposition query parameter: %s", fileURL)
	}

	filename, err = url.QueryUnescape(filename)
	if err != nil {
		return "", fmt.Errorf("error url-decoding response-content-disposition filename field: %w", err)
	}

	// Replace all characters that are not allowed in a filename with an
	// underscore. [^\d\.\-_~,;:\[\]\(\]]
	filename = strings.Map(func(r rune) rune {
		switch {
		case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9',
			r == '.', r == '-', r == '_', r == '~', r == ',', r == ';', r == ':',
			r == '[', r == ']', r == '(', r == ')' || r == ' ':
			return r
		default:
			return '-'
		}
	}, filename)

	return filename, nil
}

// This query is light and doesn't need to be paginated.
func GetBuildingAccountingCurrent(client *http.Client, graphqlURL, accountUUID string) ([]ExpenseDocumentAPI, error) {
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
						id
						hashFile
						category
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
									// For some reason, expenses don't have an
									// ID. The invoice ID is sometimes empty...
									// but we use that since we have no other
									// way.
									InvoiceID string `json:"invoiceId"`
									Piece     struct {
										ID       string `json:"id"`
										HashFile string `json:"hashFile"`
										Category string `json:"category"`
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

	err := DoGraphQL(client, graphqlURL, getBuildingAccountingCurrentQuery, map[string]any{
		"uuid": accountUUID,
	}, &getBuildingAccountingCurrentResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getBuildingAccountingCurrentResp: %w", err)
	}

	var expenses []ExpenseDocumentAPI
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
					return nil, fmt.Errorf("was expecting typename 'Credit' or 'Debit', but got %q for expense %+v", expense.Amount.Typename, expense)
				}
				var date time.Time
				if expense.Date != "" {
					var err error
					date, err = time.Parse(time.RFC3339Nano, expense.Date)
					if err != nil {
						return nil, fmt.Errorf("error parsing time: %w", err)
					}
				}
				expenses = append(expenses, ExpenseDocumentAPI{
					HashFile:              db.HashFile(expense.Piece.HashFile),
					InvoiceID:             expense.InvoiceID,
					Label:                 expense.Label,
					Date:                  date,
					Amount:                db.Amount(amount),
					AccountingAllocation:  allocation.Name,
					AccountingExpenseType: expenseType.Name,
				})
			}
		}
	}

	return expenses, nil
}

type AccountingPeriodAPI struct {
	ID          string
	Name        string
	OpeningDate time.Time
	ClosingDate time.Time
	Status      string
}

// This query is light and doesn't need to be paginated. No need to remember the
// last cursor.
func GetAccountingPeriods(client *http.Client, graphqlURL, accountUUID string) ([]AccountingPeriodAPI, error) {
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

	err := DoGraphQL(client, graphqlURL, getAccountingPeriodsQuery, map[string]any{
		"accountUuid": accountUUID,
	}, &getAccountingPeriodsResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getAccountingPeriodsResp: %w", err)
	}

	var periods []AccountingPeriodAPI
	for _, edge := range getAccountingPeriodsResp.Data.CoownerAccount.TrusteeCouncil.AccountingPeriods.Edges {
		var openingDate, closingDate time.Time
		if edge.Node.OpeningDate != "" {
			var err error
			openingDate, err = time.Parse(time.RFC3339Nano, edge.Node.OpeningDate)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
		}
		if edge.Node.ClosingDate != "" {
			var err error
			closingDate, err = time.Parse(time.RFC3339Nano, edge.Node.ClosingDate)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
		}
		periods = append(periods, AccountingPeriodAPI{
			ID:          edge.Node.ID,
			Name:        edge.Node.Name,
			OpeningDate: openingDate,
			ClosingDate: closingDate,
			Status:      edge.Node.Status,
		})
	}
	return periods, nil
}

// This query is light and doesn't need to be paginated. No need to remember the
// last cursor.
func GetBuildingAccountingRGDD(client *http.Client, graphqlURL, accountUUID, accountingPeriodID string) ([]ExpenseDocumentAPI, error) {
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
					  invoiceId
		              label
		              date
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

	err := DoGraphQL(client, graphqlURL, getBuildingAccountingRGDDQuery, map[string]any{
		"uuid":               accountUUID,
		"accountingPeriodId": accountingPeriodID,
	}, &getBuildingAccountingRGDDResp)

	if err != nil {
		return nil, fmt.Errorf("error while querying getBuildingAccountingRGDDResp: %w", err)
	}

	var expenses []ExpenseDocumentAPI
	for _, allocation := range getBuildingAccountingRGDDResp.Data.CoownerAccount.TrusteeCouncil.PastAccountingRGDD.Allocations {
		for _, expenseType := range allocation.ExpenseTypes {
			for _, expense := range expenseType.Expenses {
				var date time.Time
				if expense.Date != "" {
					var err error
					date, err = time.Parse(time.RFC3339Nano, expense.Date)
					if err != nil {
						return nil, fmt.Errorf("error parsing time: %w", err)
					}
				}
				expenses = append(expenses, ExpenseDocumentAPI{
					InvoiceID:             expense.InvoiceID, // May be empty.
					HashFile:              db.HashFile(expense.Piece.HashFile),
					Label:                 expense.Label,
					Date:                  date,
					Amount:                db.Amount(expense.ToAllocate.Value),
					AccountingAllocation:  allocation.Name,
					AccountingExpenseType: expenseType.Name,
				})
			}
		}
	}
	return expenses, nil
}

func Download(client *http.Client, fileURL string, filePath string) error {
	// No need to use the authenticated client here since the URL is
	// authenticated using one of the query parameters.
	resp, err := Do(client, http.MethodGet, fileURL, nil)
	if err != nil {
		return fmt.Errorf("while downloading invoice: %v", err)
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

	var buf bytes.Buffer

	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return fmt.Errorf("while reading file: %v", err)
	}

	err = os.WriteFile(filePath, buf.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("while saving file to disk: %v", err)
	}

	return nil
}

type Password string

func (p Password) String() string {
	return "redacted"
}

func (p Password) Raw() string {
	return string(p)
}

type Token string

func (t Token) String() string {
	return "redacted"
}

func (t Token) StringOnPurpose() string {
	return string(t)
}

func SaveEmailToDB(ctx context.Context, db *sql.DB, message *cloudmailin.IncomingMail) error {
	// Save the message to the database.
	_, err := db.ExecContext(ctx, `
		INSERT INTO emails (from, to, subject, body, received_at)
		VALUES ($1, $2, $3, $4, $5)
	`, message.Headers.From, message.Headers.To, message.Headers.Subject, message.Plain, message.Headers.Find("Date"))
	if err != nil {
		return fmt.Errorf("error while saving email to DB: %w", err)
	}

	return nil
}

type AccountDocumentAPI struct {
	ID               string
	HashFile         db.HashFile
	MimeType         string
	OriginalFilename string
	Category         db.DocumentCategory // Example: "reportVisit"
	CreatedAt        time.Time
}

func GetAccountDocuments(client *http.Client, graphqlURL, accountUUID string, category db.DocumentCategory) ([]AccountDocumentAPI, error) {
	const getAccountDocumentsQuery = `
		query getAccountDocuments($accountUuid: EncodedID!, $first: Int, $after: Cursor, $customerPortalCategory: CustomerPortalFileCategoryEnum!, $originalFilename: String, $subCategories: [String!], $fromDate: String, $toDate: String, $missionGeneralAssemblyIds: [String!]) {
		  account(uuid: $accountUuid) {
		    uuid
		    documents(
		      customerPortalCategory: $customerPortalCategory
		      first: $first
		      after: $after
		      originalFilename: $originalFilename
		      subCategories: $subCategories
		      fromDate: $fromDate
		      toDate: $toDate
		      missionGeneralAssemblyIds: $missionGeneralAssemblyIds
		    ) {
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
		          hashFile
		          mimeType
		          originalFilename
		          category
		          createdAt
		        }
		      }
		    }
		  }
		}`
	var getAccountDocumentsResp struct {
		Data struct {
			Account struct {
				Documents struct {
					TotalCount int `json:"totalCount"`
					PageInfo   struct {
						StartCursor       string `json:"startCursor"`
						EndCursor         string `json:"endCursor"`
						HasPreviousPage   bool   `json:"hasPreviousPage"`
						HasNextPage       bool   `json:"hasNextPage"`
						PageNumber        int    `json:"pageNumber"`
						ItemsPerPage      int    `json:"itemsPerPage"`
						TotalDisplayPages int    `json:"totalDisplayPages"`
						TotalPages        int    `json:"totalPages"`
					} `json:"pageInfo"`
					Edges []struct {
						Node struct {
							ID               string `json:"id"`
							HashFile         string `json:"hashFile"`
							MimeType         string `json:"mimeType"`
							OriginalFilename string `json:"originalFilename"`
							Category         string `json:"category"`
							CreatedAt        string `json:"createdAt"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"documents"`
			} `json:"account"`
		} `json:"data"`
	}

	var cursor *string
	err := DoGraphQL(client, graphqlURL, getAccountDocumentsQuery, map[string]any{
		"accountUuid":            accountUUID,
		"originalFilename":       "",
		"subCategories":          []string{},
		"customerPortalCategory": category,
		"after":                  cursor,
	}, &getAccountDocumentsResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getAccountDocumentsResp: %w", err)
	}

	var docs []AccountDocumentAPI
	for _, edge := range getAccountDocumentsResp.Data.Account.Documents.Edges {
		createdAt, err := time.Parse(time.RFC3339Nano, edge.Node.CreatedAt)
		if err != nil {
			logutil.Debugf("error parsing time: %v", err)
			return nil, err
		}

		docs = append(docs, AccountDocumentAPI{
			ID:               edge.Node.ID,
			HashFile:         db.HashFile(edge.Node.HashFile),
			MimeType:         edge.Node.MimeType,
			OriginalFilename: edge.Node.OriginalFilename,
			Category:         db.DocumentCategory(edge.Node.Category),
			CreatedAt:        createdAt,
		})
	}
	return docs, nil
}

// Annual General Meeting (AGM) of Co-Owners ("Assemblée Générale"). The `after`
// parameter is the cursor to use to get the next page of results. Leave it
// empty to get the first page.
func GetCouncilProjectDocumentsAPI(client *http.Client, graphqlURL, accountUUID, after string) ([]AccountDocumentAPI, error) {
	const getCouncilProjectDocumentsQuery = `
    query getCouncilProjectDocuments($accountUuid: EncodedID!, $sortBy: [SortByType!], $first: Int, $after: Cursor, $skipNotPaginatedData: Boolean! = false) {
        coownerAccount(uuid: $accountUuid) {
            uuid
            pastGeneralAssembly @skip(if: $skipNotPaginatedData) {
                id
                label
                officialMeeting {
                    date
                }
                meetingPlace {
                    address1
                    address2
                    city
                    zipCode
                    countryCode
                }
                lastValidPostalVoteReceptionDate
                hasAccessToPostalVote
                hasPreVoting
                status
            }
            nextGeneralAssembly @skip(if: $skipNotPaginatedData) {
                id
                label
                officialMeeting {
                    date
                }
                meetingPlace {
                    address1
                    address2
                    city
                    zipCode
                    countryCode
                }
                lastValidPostalVoteReceptionDate
                hasAccessToPostalVote
                hasPreVoting
                status
            }
            trusteeCouncil {
                projectDocuments(first: $first, after: $after, sortBy: $sortBy) {
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
`
	var getCouncilProjectDocumentsResp struct {
		Data struct {
			CoownerAccount struct {
				TrusteeCouncil struct {
					ProjectDocuments struct {
						TotalCount int `json:"totalCount"`
						PageInfo   struct {
							StartCursor     string `json:"startCursor"`
							EndCursor       string `json:"endCursor"`
							HasPreviousPage bool   `json:"hasPreviousPage"`
							HasNextPage     bool   `json:"hasNextPage"`
						} `json:"pageInfo"`
						Edges []struct {
							Node struct {
								ID               string `json:"id"`
								HashFile         string `json:"hashFile"`
								MimeType         string `json:"mimeType"`
								OriginalFilename string `json:"originalFilename"`
								Category         string `json:"category"`
								CreatedAt        string `json:"createdAt"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"projectDocuments"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		} `json:"data"`
	}

	var cursor *string
	if after != "" {
		cursor = &after
	}
	err := DoGraphQL(client, graphqlURL, getCouncilProjectDocumentsQuery, map[string]any{
		"accountUuid":          accountUUID,
		"first":                100, // I found that it is the maximum accepted value.
		"after":                cursor,
		"skipNotPaginatedData": false,
	}, &getCouncilProjectDocumentsResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getCouncilProjectDocumentsResp: %w", err)
	}

	var docs []AccountDocumentAPI
	for _, edge := range getCouncilProjectDocumentsResp.Data.CoownerAccount.TrusteeCouncil.ProjectDocuments.Edges {
		createdAt, err := time.Parse(time.RFC3339Nano, edge.Node.CreatedAt)
		if err != nil {
			logutil.Debugf("error parsing time: %v", err)
			return nil, err
		}

		docs = append(docs, AccountDocumentAPI{
			ID:               edge.Node.ID,
			HashFile:         db.HashFile(edge.Node.HashFile),
			MimeType:         edge.Node.MimeType,
			OriginalFilename: edge.Node.OriginalFilename,
			Category:         db.DocumentCategory(edge.Node.Category),
			CreatedAt:        createdAt,
		})
	}

	return docs, nil
}

// RepairBudgetAPI is one "compte travaux". In the Foncia GraphQL API, they are
// called "repair budgets". Each of them tracks the expenses of a single works
// project voted at a general assembly, e.g. "REFECTION ASCENSEURS".
type RepairBudgetAPI struct {
	ID              string    // Example: "6939a432a558318b60013568".
	Label           string    // Example: "GSM BAT C".
	ValidatedAmount db.Amount // Amount voted at the general assembly. Example: 100371, i.e. "1003,71 €".
}

// RepairBudgetDetailsAPI is the breakdown of a single "compte travaux". The
// expenses are grouped by accounting allocation ("clé de répartition"), and
// then by expense type.
type RepairBudgetDetailsAPI struct {
	BudgetID string

	// TotalToAllocate is the balance of the "compte travaux": the sum of the
	// expenses charged to it (positive) and of the funds mobilized to pay for
	// them (negative). A negative total means the works have been over-funded.
	TotalToAllocate  db.Amount
	TotalVat         db.Amount
	TotalRecoverable db.Amount

	Allocations []RepairAllocationAPI
}

type RepairAllocationAPI struct {
	ID           string
	Name         string // Example: "CHARGES ASCENSEUR C".
	Code         string // Example: "600".
	ToAllocate   db.Amount
	Vat          db.Amount
	Recoverable  db.Amount
	ExpenseTypes []RepairExpenseTypeAPI
}

type RepairExpenseTypeAPI struct {
	ID          string
	Name        string // Example: "HCC HONORAIRES TRAVAUX".
	Code        string // Example: "1703".
	ToAllocate  db.Amount
	Vat         db.Amount
	Recoverable db.Amount
	Expenses    []RepairExpenseAPI
}

type RepairExpenseAPI struct {
	ID          string
	InvoiceID   string      // Empty when no invoice PDF is attached.
	HashFile    db.HashFile // Empty when no invoice PDF is attached.
	Label       string
	Date        time.Time
	ToAllocate  db.Amount
	Vat         db.Amount
	Recoverable db.Amount
}

// GetRepairBudgets returns the "comptes travaux" of the building. Use
// GetRepairBudgetDetails or GetRepairBudgetDetailsFull to get the expenses
// charged to one of them.
func GetRepairBudgets(client *http.Client, graphqlURL, accountUUID string) ([]RepairBudgetAPI, error) {
	const getRepairBudgetsQuery = `
        query getRepairBudgets($accountUuid: EncodedID!) {
          repairBudgets(accountUuid: $accountUuid) {
            id
            label
            validatedAmount {
              value
              currency
            }
          }
        }`
	var listRepairIDsResp struct {
		Data struct {
			RepairBudgets []struct {
				ID              string `json:"id"`
				Label           string `json:"label"`
				ValidatedAmount struct {
					Value    int    `json:"value"`
					Currency string `json:"currency"`
				} `json:"validatedAmount"`
			} `json:"repairBudgets"`
		} `json:"data"`
	}

	err := DoGraphQL(client, graphqlURL, getRepairBudgetsQuery, map[string]any{
		"accountUuid": accountUUID,
	}, &listRepairIDsResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying listRepairIDsResp: %w", err)
	}

	var budgets []RepairBudgetAPI
	for _, repair := range listRepairIDsResp.Data.RepairBudgets {
		budgets = append(budgets, RepairBudgetAPI{
			ID:              repair.ID,
			Label:           repair.Label,
			ValidatedAmount: db.Amount(repair.ValidatedAmount.Value),
		})
	}
	return budgets, nil
}

// GetRepairBudgetDetails returns the expenses charged to a single "compte
// travaux", flattened. Use GetRepairBudgetDetailsFull if you also need the
// allocation and expense-type totals.
func GetRepairBudgetDetails(client *http.Client, graphqlURL, accountUUID, budgetID string) ([]ExpenseDocumentAPI, error) {
	details, err := GetRepairBudgetDetailsFull(client, graphqlURL, accountUUID, budgetID)
	if err != nil {
		return nil, err
	}

	var expenses []ExpenseDocumentAPI
	for _, allocation := range details.Allocations {
		for _, expenseType := range allocation.ExpenseTypes {
			for _, expense := range expenseType.Expenses {
				expenses = append(expenses, ExpenseDocumentAPI{
					InvoiceID:             expense.InvoiceID, // May be empty.
					HashFile:              expense.HashFile,
					Label:                 expense.Label,
					Date:                  expense.Date,
					Amount:                expense.ToAllocate,
					AccountingAllocation:  allocation.Name,
					AccountingExpenseType: expenseType.Name,
				})
			}
		}
	}

	return expenses, nil
}

// GetRepairBudgetDetailsFull returns the full breakdown of a single "compte
// travaux": totals, allocations, expense types, and expenses.
func GetRepairBudgetDetailsFull(client *http.Client, graphqlURL, accountUUID, budgetID string) (RepairBudgetDetailsAPI, error) {
	if accountUUID == "" {
		return RepairBudgetDetailsAPI{}, errors.New("accountUUID is empty")
	}
	if budgetID == "" {
		return RepairBudgetDetailsAPI{}, errors.New("budgetID is empty")
	}
	const getRepairBudgetDetailsQuery = `
		query getRepairBudgetDetails($accountUuid: EncodedID!, $budgetId: ID!) {
		  coownerAccount(uuid: $accountUuid) {
		    uuid
		    trusteeCouncil {
		      repairBudgets(accountUuid: $accountUuid, budgetId: $budgetId) {
		        budgetId
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
	type amount struct {
		Value    int    `json:"value"`
		Currency string `json:"currency"`
	}
	var getRepairBudgetDetailsResp struct {
		Data struct {
			CoownerAccount struct {
				TrusteeCouncil struct {
					RepairBudgets struct {
						BudgetID         string `json:"budgetId"`
						TotalToAllocate  amount `json:"totalToAllocate"`
						TotalVat         amount `json:"totalVat"`
						TotalRecoverable amount `json:"totalRecoverable"`
						Allocations      []struct {
							ID           string `json:"id"`
							Name         string `json:"name"`
							Code         string `json:"code"`
							ToAllocate   amount `json:"toAllocate"`
							Vat          amount `json:"vat"`
							Recoverable  amount `json:"recoverable"`
							ExpenseTypes []struct {
								ID           string `json:"id"`
								AllocationID string `json:"allocationId"`
								Name         string `json:"name"`
								Code         string `json:"code"`
								ToAllocate   amount `json:"toAllocate"`
								Vat          amount `json:"vat"`
								Recoverable  amount `json:"recoverable"`
								Expenses     []struct {
									ID        string `json:"id"`
									InvoiceID string `json:"invoiceId"`
									Label     string `json:"label"`
									Date      string `json:"date"`
									Piece     struct {
										HashFile string `json:"hashFile"`
										Category string `json:"category"`
										ID       string `json:"id"`
									} `json:"piece"`
									ToAllocate  amount `json:"toAllocate"`
									Vat         amount `json:"vat"`
									Recoverable amount `json:"recoverable"`
								} `json:"expenses"`
							} `json:"expenseTypes"`
						} `json:"allocations"`
					} `json:"repairBudgets"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		} `json:"data"`
	}

	err := DoGraphQL(client, graphqlURL, getRepairBudgetDetailsQuery, map[string]any{
		"accountUuid": accountUUID,
		"budgetId":    budgetID,
	}, &getRepairBudgetDetailsResp)
	if err != nil {
		return RepairBudgetDetailsAPI{}, fmt.Errorf("error while querying getRepairBudgetDetailsResp: %w", err)
	}

	raw := getRepairBudgetDetailsResp.Data.CoownerAccount.TrusteeCouncil.RepairBudgets
	details := RepairBudgetDetailsAPI{
		BudgetID:         raw.BudgetID,
		TotalToAllocate:  db.Amount(raw.TotalToAllocate.Value),
		TotalVat:         db.Amount(raw.TotalVat.Value),
		TotalRecoverable: db.Amount(raw.TotalRecoverable.Value),
	}
	for _, allocation := range raw.Allocations {
		a := RepairAllocationAPI{
			ID:          allocation.ID,
			Name:        allocation.Name,
			Code:        allocation.Code,
			ToAllocate:  db.Amount(allocation.ToAllocate.Value),
			Vat:         db.Amount(allocation.Vat.Value),
			Recoverable: db.Amount(allocation.Recoverable.Value),
		}
		for _, expenseType := range allocation.ExpenseTypes {
			t := RepairExpenseTypeAPI{
				ID:          expenseType.ID,
				Name:        expenseType.Name,
				Code:        expenseType.Code,
				ToAllocate:  db.Amount(expenseType.ToAllocate.Value),
				Vat:         db.Amount(expenseType.Vat.Value),
				Recoverable: db.Amount(expenseType.Recoverable.Value),
			}
			for _, expense := range expenseType.Expenses {
				var date time.Time
				if expense.Date != "" {
					var err error
					date, err = time.Parse(time.RFC3339Nano, expense.Date)
					if err != nil {
						return RepairBudgetDetailsAPI{}, fmt.Errorf("error parsing time: %w", err)
					}
				}
				t.Expenses = append(t.Expenses, RepairExpenseAPI{
					ID:          expense.ID,
					InvoiceID:   expense.InvoiceID, // May be empty.
					HashFile:    db.HashFile(expense.Piece.HashFile),
					Label:       expense.Label,
					Date:        date,
					ToAllocate:  db.Amount(expense.ToAllocate.Value),
					Vat:         db.Amount(expense.Vat.Value),
					Recoverable: db.Amount(expense.Recoverable.Value),
				})
			}
			a.ExpenseTypes = append(a.ExpenseTypes, t)
		}
		details.Allocations = append(details.Allocations, a)
	}

	return details, nil
}

// I found that after many calls, the server starts returning:
//
//	HTTP/2.0 403
//	date: Wed, 29 Jan 2025 20:27:28 GMT
//	content-type: application/json
//	content-length: 23
//	x-amzn-requestid: d612d465-164e-4821-968c-d43a2bc1066f
//	x-amzn-errortype: ForbiddenException
//	x-amz-apigw-id: FKtPnFBhCGYEU3w=
//
//	{"message":"Forbidden"}
//
// Also, in some instances, it returns an error with `peer closed connection`.
//
// I suspect that the server is rate-limiting me. This func is meant to wrap
// client.Do calls and retry them if they fail with a 403.
func Do(client *http.Client, method string, url string, body []byte) (*http.Response, error) {
	b := bytes.NewReader(body)
	for i := 0; i < 10; i++ {
		_, err := b.Seek(0, 0)
		if err != nil {
			return nil, fmt.Errorf("while seeking body: %w", err)
		}
		req, err := http.NewRequest(method, url, b)
		if err != nil {
			return nil, fmt.Errorf("while creating request: %w", err)
		}

		resp, err := client.Do(req)
		switch {
		case errors.Is(err, syscall.ECONNRESET):
			logutil.Infof("received connection reset, suspecting rate-limiting, retrying...")
			resp.Body.Close()
			time.Sleep(30 * time.Second)
			continue
		case err != nil:
			return nil, fmt.Errorf("while doing request: %w", err)
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusBadGateway:
			logutil.Infof("received %d, suspecting rate-limiting, retrying...", resp.StatusCode)
			resp.Body.Close()
			time.Sleep(30 * time.Second)
			continue
		}

		return resp, nil
	}
	return nil, fmt.Errorf("retried multiple times, giving up")
}

type Coowner struct {
	Civility    string
	FirstName   string
	LastName    string
	DisplayName string
	Address1    string
	Address2    string
	City        string
	ZipCode     string
	Units       []int // Lots.
}

func GetCouncilCoowners(client *http.Client, accountUuid string) ([]Coowner, error) {
	getCouncilCoownersQuery := `
      query getCouncilCoowners(
        $accountUuid: EncodedID!,
        $first: Int,
        $after: Cursor,
        $customerName: String!,
        $fullAddress: String!,
        $sortBy: [SortByType!],
        $units: [String!],
        $holderProperties: [String!]
      ) {
        coownerAccount(uuid: $accountUuid) {
          uuid
          trusteeCouncil {
            coowners(
              first: $first
              after: $after
              customerName: $customerName
              fullAddress: $fullAddress
              sortBy: $sortBy
              units: $units
              holderProperties: $holderProperties
            ) {
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
                  units {
                    id
                    number
                    coOwnershipByLawsId
                  }
                  mainHolder {
                    propertyType
                    customer {
                      id
                      civility
                      firstName
                      lastName
                      displayName
                      address {
                        address1
                        city
                        zipCode
                      }
                    }
                  }
                  balance {
                    value
                    currency
                  }
                }
              }
            }
          }
        }
      }
	`
	var cursor *string
	variables := map[string]any{
		"accountUuid":      accountUuid,
		"first":            100,
		"after":            cursor,
		"customerName":     "",
		"fullAddress":      "",
		"sortBy":           map[string]string{"key": "customerName", "direction": "ASC"},
		"units":            []string(nil),
		"holderProperties": []string(nil),
	}
	body, err := json.Marshal(map[string]any{
		"query":     getCouncilCoownersQuery,
		"variables": variables,
	})
	if err != nil {
		return nil, fmt.Errorf("while marshalling request body: %w", err)
	}
	resp, err := Do(client, http.MethodPost, "https://myfoncia-gateway.prod.fonciamillenium.net/graphql", body)
	if err != nil {
		return nil, fmt.Errorf("while doing request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, respBody)
	}

	var getCouncilCoownersResp struct {
		Data struct {
			CoownerAccount struct {
				TrusteeCouncil struct {
					Coowners struct {
						TotalCount int `json:"totalCount"`
						PageInfo   struct {
							StartCursor       string `json:"startCursor"`
							EndCursor         string `json:"endCursor"`
							HasPreviousPage   bool   `json:"hasPreviousPage"`
							HasNextPage       bool   `json:"hasNextPage"`
							PageNumber        int    `json:"pageNumber"`
							ItemsPerPage      int    `json:"itemsPerPage"`
							TotalDisplayPages int    `json:"totalDisplayPages"`
							TotalPages        int    `json:"totalPages"`
						} `json:"pageInfo"`
						Edges []struct {
							Node struct {
								ID    string `json:"id"`
								Units []struct {
									ID                  string `json:"id"`
									Number              string `json:"number"`
									CoOwnershipByLawsID string `json:"coOwnershipByLawsId"`
								} `json:"units"`
								MainHolder struct {
									PropertyType string `json:"propertyType"`
									Customer     struct {
										ID          string `json:"id"`
										Civility    string `json:"civility"`
										FirstName   string `json:"firstName"`
										LastName    string `json:"lastName"`
										DisplayName string `json:"displayName"`
										Address     struct {
											Address1 string `json:"address1"`
											Address2 string `json:"address2"`
											City     string `json:"city"`
											ZipCode  string `json:"zipCode"`
										} `json:"address"`
									} `json:"customer"`
								} `json:"mainHolder"`
							} `json:"node"`
						}
					}
				}
			}
		}
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("while reading response body: %w", err)
	}
	defer resp.Body.Close()

	if err := json.Unmarshal(bytes, &getCouncilCoownersResp); err != nil {
		return nil, fmt.Errorf("while unmarshalling response body: %w", err)
	}

	var coowners []Coowner
	for _, edge := range getCouncilCoownersResp.Data.CoownerAccount.TrusteeCouncil.Coowners.Edges {
		var units []int
		for _, unit := range edge.Node.Units {
			// Parse front string.
			unitNumber, err := strconv.Atoi(unit.CoOwnershipByLawsID)
			if err != nil {
				return nil, fmt.Errorf("error parsing unit number %s: %w", unit.CoOwnershipByLawsID, err)
			}
			units = append(units, unitNumber)
		}

		coowners = append(coowners, Coowner{
			Civility:    edge.Node.MainHolder.Customer.Civility,
			FirstName:   edge.Node.MainHolder.Customer.FirstName,
			LastName:    edge.Node.MainHolder.Customer.LastName,
			DisplayName: edge.Node.MainHolder.Customer.DisplayName,
			Address1:    edge.Node.MainHolder.Customer.Address.Address1,
			Address2:    edge.Node.MainHolder.Customer.Address.Address2,
			City:        edge.Node.MainHolder.Customer.Address.City,
			ZipCode:     edge.Node.MainHolder.Customer.Address.ZipCode,
			Units:       units,
		})
	}

	return coowners, nil
}
