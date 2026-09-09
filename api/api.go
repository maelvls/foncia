package api

import (
	"bytes"
	"context"
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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
	"github.com/sethgrid/gencurl"
)

// DefaultTimeout is the timeout given to the HTTP clients created by this
// package. Without it, a request that the Foncia gateway never answers hangs
// forever, and since these calls are also made from HTTP handlers, that means a
// stuck web server.
const DefaultTimeout = 60 * time.Second

// GraphQLURL is the production Foncia GraphQL gateway. It is only a default:
// every func in this package takes the URL so that the tests can point it at an
// httptest server.
const GraphQLURL = "https://myfoncia-gateway.prod.fonciamillenium.net/graphql"

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

// Time is a time.Time that knows how to decode the dates the Foncia API
// returns: RFC 3339, except that a missing date is an empty string rather than
// `null`. An empty string (and `null`) decode to the zero time; anything else
// that isn't a date is an error rather than a silently dropped record.
type Time struct {
	time.Time
}

func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("expected a date as a JSON string, got %s", string(b))
	}
	if s == "" {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fmt.Errorf("error parsing time: %w", err)
	}
	t.Time = parsed
	return nil
}

func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte(`""`), nil
	}
	return json.Marshal(t.Format(time.RFC3339Nano))
}

// amount is the `Money` type of the Foncia API. The value is in cents, e.g.
// 1234567890 means "1234567,90 €".
type amount struct {
	Value    int    `json:"value"`
	Currency string `json:"currency"`
}

// pageInfo is the Relay-style pagination info returned by every paginated
// field of the Foncia API.
type pageInfo struct {
	StartCursor     string `json:"startCursor"`
	EndCursor       string `json:"endCursor"`
	HasPreviousPage bool   `json:"hasPreviousPage"`
	HasNextPage     bool   `json:"hasNextPage"`
}

// documentNode is the shape of a document as returned by the API.
type documentNode struct {
	ID               string `json:"id"`
	HashFile         string `json:"hashFile"`
	MimeType         string `json:"mimeType"`
	OriginalFilename string `json:"originalFilename"`
	Category         string `json:"category"`
	CreatedAt        Time   `json:"createdAt"`
}

type supplierNode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	FirstName string `json:"firstName"`
	Activity  string `json:"activity"`
}

func (s supplierNode) toAPI() SupplierAPI {
	return SupplierAPI{ID: s.ID, Name: s.Name, FirstName: s.FirstName, Activity: s.Activity}
}

// AuthenticatedClient returns a client that logs in again when the token
// expires. The tokens handed out by Foncia are valid for 30 days, which is
// plenty for the one-shot commands, but the `serve` command stays up for
// months. It used to keep using the very first token forever, which meant that
// after 30 days every call to the API failed; the sync stopped, and the
// "Télécharger depuis Foncia" links started answering "not found".
//
// The `authClient` given as input is only used to log in, and is not mutated: a
// copy of it is used.
func AuthenticatedClient(authClient *http.Client, graphqlURL, username string, password Password) (*http.Client, error) {
	// A copy: we don't want to mutate the caller's client.
	loginClient := *authClient
	if loginClient.Timeout == 0 {
		loginClient.Timeout = DefaultTimeout
	}
	loginClient.Transport = withDebugCurlLogs(loginClient.Transport)

	src := &loginTokenSource{
		authClient: &loginClient,
		graphqlURL: graphqlURL,
		username:   username,
		password:   password,
	}

	tr := &tokenTransport{
		base:  withDebugCurlLogs(nil),
		login: src.Token,
	}

	// Let's log in once right away so that wrong credentials are reported when
	// the command starts rather than on the first call to the API.
	if _, err := tr.token(context.Background(), false); err != nil {
		return nil, fmt.Errorf("while authenticating: %w", err)
	}

	return &http.Client{Transport: tr, Timeout: DefaultTimeout}, nil
}

// AuthenticatedClientToken is used when the token is given directly with
// FONCIA_TOKEN. Contrary to AuthenticatedClient, this client has no way to log
// in again, so it stops working when the token expires.
func AuthenticatedClientToken(token Token) *http.Client {
	return &http.Client{
		Transport: &tokenTransport{base: withDebugCurlLogs(nil), tok: token},
		Timeout:   DefaultTimeout,
	}
}

// expiryDelta is the margin taken on the expiry date: a token that is about to
// expire is replaced right away rather than half-way through a request.
const expiryDelta = 30 * time.Second

// tokenTransport attaches the `Authorization: Bearer` header, and logs in again
// when the token it holds has expired or when the server tells us it doesn't
// like it (401). This replaces golang.org/x/oauth2, which pulled in appengine
// and the deprecated github.com/golang/protobuf, and which couldn't re-login on
// a 401.
type tokenTransport struct {
	base http.RoundTripper

	// login is nil when the token was given by the user (FONCIA_TOKEN): there
	// is then no way to get a fresh one.
	login func(ctx context.Context) (Token, time.Time, error)

	mu     sync.Mutex
	tok    Token
	expiry time.Time // Zero means "we don't know", i.e. never re-login.
}

// token returns the token to use, logging in if the current one is missing,
// expired, or if `force` is set. The mutex is deliberately held during the
// login call so that concurrent requests don't all log in at once.
func (t *tokenTransport) token(ctx context.Context, force bool) (Token, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stillGood := t.tok != "" && (t.expiry.IsZero() || time.Now().Before(t.expiry.Add(-expiryDelta)))
	if !force && stillGood {
		return t.tok, nil
	}
	if t.login == nil {
		// Static token: nothing better to offer.
		return t.tok, nil
	}
	tok, expiry, err := t.login(ctx)
	if err != nil {
		return "", err
	}
	t.tok, t.expiry = tok, expiry
	return tok, nil
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.token(req.Context(), false)
	if err != nil {
		return nil, fmt.Errorf("while getting a token: %w", err)
	}

	// A RoundTripper must not modify the request it is given.
	authReq := req.Clone(req.Context())
	authReq.Header.Set("Authorization", "Bearer "+string(tok))

	resp, err := t.base.RoundTrip(authReq)
	if err != nil {
		return nil, err
	}

	// The token was rejected: log in again and replay the request once. Only
	// possible if we know how to log in and if the body can be re-read.
	replayable := t.login != nil && (req.Body == nil || req.GetBody != nil)
	if resp.StatusCode != http.StatusUnauthorized || !replayable {
		return resp, nil
	}
	logutil.Debugf("authentication: got a 401, logging in again and retrying")
	resp.Body.Close()

	tok, err = t.token(req.Context(), true)
	if err != nil {
		return nil, fmt.Errorf("while logging in again after a 401: %w", err)
	}
	retryReq := req.Clone(req.Context())
	retryReq.Header.Set("Authorization", "Bearer "+string(tok))
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("while rewinding the body to retry after a 401: %w", err)
		}
		retryReq.Body = body
	}
	return t.base.RoundTrip(retryReq)
}

// loginTokenSource logs in with the username and password every time a fresh
// token is needed.
type loginTokenSource struct {
	authClient *http.Client
	graphqlURL string
	username   string
	password   Password
}

// Token logs in and returns the new token along with its expiry date.
func (s *loginTokenSource) Token(ctx context.Context) (Token, time.Time, error) {
	return GetToken(ctx, s.authClient, s.graphqlURL, s.username, s.password)
}

// GetToken logs in and returns the token together with the expiry date read
// from the token's `exp` claim.
//
// The given client isn't mutated: GetToken needs a client that doesn't follow
// redirects (a 302 on a login is an error, not a redirect) and that keeps
// cookies, so it works on a copy.
//
//	curl 'https://myfoncia-gateway.prod.fonciamillenium.net/graphql' \
//	  -H 'content-type: application/json' \
//	  --data-raw $'{"query":"mutation login($request: LoginRequest!) {\\n  login(request: $request) {\\n    token\\n  }\\n}","variables":{"request":{"username":"","password":"","appId":"myfoncia"}},"operationName":"login"}'
func GetToken(ctx context.Context, client *http.Client, graphqlURL, username string, password Password) (Token, time.Time, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("error creating cookie jar: %w", err)
	}

	loginClient := *client
	loginClient.Jar = jar
	// Redirects don't make sense for HTML pages. For example, a 302 redirect
	// might actually indicate an error.
	loginClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	const query = `mutation login($request: LoginRequest!) {
		login(request: $request) {
			token
		}
	}`

	type LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
		AppID    string `json:"appId"`
	}
	var loginResp struct {
		Login struct {
			Token string `json:"token"`
		} `json:"login"`
	}

	err = DoGraphQL(ctx, &loginClient, graphqlURL, query, map[string]any{
		"request": LoginRequest{
			Username: username,
			Password: password.Raw(),
			AppID:    "myfoncia",
		},
	}, &loginResp)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("error while logging in: %w", err)
	}
	if loginResp.Login.Token == "" {
		return "", time.Time{}, fmt.Errorf("the login mutation returned an empty token")
	}

	// We parse the JWT to know when the token expires. We can't verify the JWT
	// because we don't have the public key (and we don't need to verify it),
	// but I trust that the `exp` claim is correct since I trust the server.
	expiry, err := parseJWTExp(loginResp.Login.Token)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("while parsing the JWT that was just issued: %w", err)
	}

	logutil.Debugf("authentication: token expires in %s (%s)", time.Until(expiry).Round(time.Second), expiry)
	return Token(loginResp.Login.Token), expiry, nil
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
	return time.Unix(int64(expInt), 0), nil
}

// The accountUUID is the base 64 encoded ID of the account. For example:
//
//	"eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9"
//
// which decodes to:
//
//	{"accountId":"64850e80b3b2947c6cfbd608","customerId":"64850e8036ccdc2407baecd4","quality":"CO_OWNER","buildingId":"64850e80a4ccb95ce4b6b115","trusteeMember":true}
func GetAccountUUID(ctx context.Context, client *http.Client, graphqlURL string) (string, error) {
	const getAccountsQuery = `query getAccounts {accounts {uuid}}`
	var getAccountsResp struct {
		Accounts []struct {
			UUID string `json:"uuid"`
		} `json:"accounts"`
	}

	err := DoGraphQL(ctx, client, graphqlURL, getAccountsQuery, nil, &getAccountsResp)
	if err != nil {
		return "", fmt.Errorf("error while querying getAccountsResp: %w", err)
	}
	if len(getAccountsResp.Accounts) == 0 {
		return "", fmt.Errorf("no accounts found")
	}
	return getAccountsResp.Accounts[0].UUID, nil
}

// pagesLimit is a safety net: the loop stops after that many pages even if the
// server keeps claiming there is a next page.
const pagesLimit = 10000

// paginate calls `fetch` page after page, following the end cursor, until the
// server says there is no next page. It returns the cursor of the last page so
// that the next sync can resume from there; when nothing was fetched, the
// `fromCursor` given as input is returned unchanged.
func paginate(ctx context.Context, fromCursor string, fetch func(ctx context.Context, after *string) (pageInfo, error)) (lastCursor string, _ error) {
	// The reason *string is needed is because I found that the empty string
	// doesn't work to get the first page. To get the first page, the field
	// `after` must be appearing as `null`.
	var cursor *string
	if fromCursor != "" {
		cursor = &fromCursor
	}
	lastCursor = fromCursor

	for page := 0; page < pagesLimit; page++ {
		info, err := fetch(ctx, cursor)
		if err != nil {
			return lastCursor, err
		}
		if info.EndCursor != "" {
			lastCursor = info.EndCursor
		}
		// Guard against a server that keeps saying "there is a next page" while
		// handing us the same cursor over and over.
		if !info.HasNextPage || info.EndCursor == "" || (cursor != nil && info.EndCursor == *cursor) {
			return lastCursor, nil
		}
		endCursor := info.EndCursor
		cursor = &endCursor
	}
	return lastCursor, nil
}

// perPage is the maximum page size the Foncia API accepts.
const perPage = 100

// MissionsCursor remembers where the previous call to GetMissionsAPI stopped.
// Incidents and repairs are two distinct paginated lists on the Foncia side, so
// they each need their own cursor; feeding one's cursor to the other query
// silently skips or duplicates missions.
type MissionsCursor struct {
	IncidentsCursor string
	RepairsCursor   string
}

// missionNode is what both `missionIncidents` and `missionRepairs` return.
type missionNode struct {
	ID          string `json:"id"`
	Number      string `json:"number"`
	StartedAt   Time   `json:"startedAt"`
	Label       string `json:"label"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

type missionConnection struct {
	TotalCount int      `json:"totalCount"`
	PageInfo   pageInfo `json:"pageInfo"`
	Edges      []struct {
		Node missionNode `json:"node"`
	} `json:"edges"`
}

const missionsPageInfoFields = `
	pageInfo {
		startCursor
		endCursor
		hasPreviousPage
		hasNextPage
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
	}`

const getIncidentsQuery = `
	query getCouncilMissionIncidents($accountUuid: EncodedID!, $first: Int, $after: Cursor, $sortBy: [SortByType!]) {
		coownerAccount(uuid: $accountUuid) {
			uuid
			trusteeCouncil {
				missionIncidents(first: $first, after: $after, sortBy: $sortBy) {
					totalCount` + missionsPageInfoFields + `
				}
			}
		}
	}`

const getRepairsQuery = `
	query getCouncilMissionRepairs($accountUuid: EncodedID!, $first: Int, $after: Cursor, $sortBy: [SortByType!]) {
		coownerAccount(uuid: $accountUuid) {
			uuid
			trusteeCouncil {
				missionRepairs(first: $first, after: $after, sortBy: $sortBy) {
					totalCount` + missionsPageInfoFields + `
				}
			}
		}
	}`

// GetMissionsAPI returns the repairs and incidents. Use GetAccountUUID to get
// the accountUUID. `from` lets you skip the missions you already have; the
// returned cursor pair is meant to be persisted and handed back on the next
// call.
func GetMissionsAPI(ctx context.Context, client *http.Client, graphqlURL, accountUUID string, from MissionsCursor) (_ []MissionAPI, _ MissionsCursor, _ error) {
	var missions []MissionAPI
	last := from

	// Incidents.
	var err error
	last.IncidentsCursor, err = paginate(ctx, from.IncidentsCursor, func(ctx context.Context, after *string) (pageInfo, error) {
		var resp struct {
			CoownerAccount struct {
				UUID           string `json:"uuid"`
				TrusteeCouncil struct {
					MissionIncidents missionConnection `json:"missionIncidents"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		}
		err := DoGraphQL(ctx, client, graphqlURL, getIncidentsQuery, map[string]any{
			"accountUuid": accountUUID,
			"first":       perPage,
			"after":       after,
			// We don't sort by "createdAt" because some entries have the same
			// timestamp, leading to unpredictable ordering, which, combined
			// with pagination, leads to duplicate or missing entries.
		}, &resp)
		if err != nil {
			return pageInfo{}, fmt.Errorf("error while querying getIncidentsResp: %w", err)
		}
		conn := resp.CoownerAccount.TrusteeCouncil.MissionIncidents
		missions = append(missions, missionsFromEdges(conn, Incident)...)
		return conn.PageInfo, nil
	})
	if err != nil {
		return nil, from, err
	}

	// Repairs.
	last.RepairsCursor, err = paginate(ctx, from.RepairsCursor, func(ctx context.Context, after *string) (pageInfo, error) {
		var resp struct {
			CoownerAccount struct {
				UUID           string `json:"uuid"`
				TrusteeCouncil struct {
					MissionRepairs missionConnection `json:"missionRepairs"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		}
		err := DoGraphQL(ctx, client, graphqlURL, getRepairsQuery, map[string]any{
			"accountUuid": accountUUID,
			"first":       perPage,
			"after":       after,
		}, &resp)
		if err != nil {
			return pageInfo{}, fmt.Errorf("error while querying getRepairsResp: %w", err)
		}
		conn := resp.CoownerAccount.TrusteeCouncil.MissionRepairs
		missions = append(missions, missionsFromEdges(conn, Repair)...)
		return conn.PageInfo, nil
	})
	if err != nil {
		return nil, from, err
	}

	sort.Slice(missions, func(i, j int) bool {
		return missions[i].StartedAt.After(missions[j].StartedAt)
	})
	return missions, last, nil
}

func missionsFromEdges(conn missionConnection, kind MissionKindAPI) []MissionAPI {
	var missions []MissionAPI
	for _, edge := range conn.Edges {
		missions = append(missions, MissionAPI{
			ID:          edge.Node.ID,
			Number:      edge.Node.Number,
			Label:       edge.Node.Label,
			Status:      edge.Node.Status,
			StartedAt:   edge.Node.StartedAt.Time,
			Description: edge.Node.Description,
			Kind:        kind,
		})
	}
	return missions
}

func GetWorkOrdersAPI(ctx context.Context, client *http.Client, graphqlURL, accountUUID, missionID string) (_ []WorkOrderAPI, _ error) {
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
		WorkOrders struct {
			Edges []struct {
				Node struct {
					ID         string `json:"id"`
					Number     string `json:"number"`
					Label      string `json:"label"`
					RepairDate struct {
						Start Time `json:"start"`
						End   Time `json:"end"`
					} `json:"repairDate"`
					Supplier supplierNode `json:"supplier"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"workOrders"`
	}

	err := DoGraphQL(ctx, client, graphqlURL, getWorkOrders, map[string]any{
		"accountUuid": accountUUID,
		"missionId":   missionID,
		"first":       perPage,
	}, &getWorkOrdersResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getWorkOrdersResp for mission %s: %w", missionID, err)
	}

	var orders []WorkOrderAPI
	for _, edge := range getWorkOrdersResp.WorkOrders.Edges {
		orders = append(orders, WorkOrderAPI{
			ID:              edge.Node.ID,
			Number:          edge.Node.Number,
			Label:           edge.Node.Label,
			RepairDateStart: edge.Node.RepairDate.Start.Time,
			RepairDateEnd:   edge.Node.RepairDate.End.Time,
			Supplier:        edge.Node.Supplier.toAPI(),
		})
	}

	return orders, nil
}

// EnableDebugCurlLogs makes the client log every request as a curl command when
// --debug is on. The wrapping is free when --debug is off: the request is only
// cloned (which means re-reading the body) when the log is actually emitted.
func EnableDebugCurlLogs(client *http.Client) {
	client.Transport = withDebugCurlLogs(client.Transport)
}

func withDebugCurlLogs(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	if _, alreadyWrapped := rt.(transportCurlLogs); alreadyWrapped {
		return rt
	}
	return transportCurlLogs{trWrapped: rt}
}

// Only does something when --debug is passed.
type transportCurlLogs struct {
	trWrapped http.RoundTripper
}

func (tr transportCurlLogs) RoundTrip(r *http.Request) (*http.Response, error) {
	if !logutil.EnableDebug {
		return tr.trWrapped.RoundTrip(r)
	}

	// Clone request to redact sensitive headers from debug logs.
	r2 := r.Clone(r.Context())
	if r.GetBody != nil {
		body, err := r.GetBody()
		if err != nil {
			return nil, fmt.Errorf("while cloning request body for debug log: %w", err)
		}
		r2.Body = body
	} else {
		r2.Body = nil
	}
	if r2.Header != nil {
		r2.Header = r2.Header.Clone()
		r2.Header.Del("Authorization")
		r2.Header.Del("authorization")
		r2.Header.Del("Cookie")
		r2.Header.Del("cookie")
	}
	logutil.Debugf("%s", gencurl.FromRequest(r2))
	return tr.trWrapped.RoundTrip(r)
}

// GraphQLError is one entry of the `errors` array of a GraphQL response.
type GraphQLError struct {
	Message   string `json:"message"`
	Locations []struct {
		Line   int `json:"line"`
		Column int `json:"column"`
	} `json:"locations"`
	Path       []any          `json:"path"`
	Extensions map[string]any `json:"extensions"`
}

// GraphQLErrors is returned by DoGraphQL when the server answered with a
// non-empty `errors` array. Note that GraphQL reports errors with a 200 status
// code, so this can (and usually does) happen on a 200.
type GraphQLErrors struct {
	StatusCode int
	Errors     []GraphQLError
}

func (e *GraphQLErrors) Error() string {
	msgs := make([]string, 0, len(e.Errors))
	for _, err := range e.Errors {
		msgs = append(msgs, err.Message)
	}
	return fmt.Sprintf("graphql error (status %d): %s", e.StatusCode, strings.Join(msgs, "; "))
}

// maxBodySize is a crude protection against a server that would answer with a
// body large enough to make us run out of memory.
const maxBodySize = 64 << 20 // 64 MiB.

// firstBackoff is how long Do waits before the first retry; it doubles at every
// attempt after that. It is a var only so that the tests don't have to wait.
var firstBackoff = time.Second

// DoGraphQL runs the given query and unmarshals the `data` field of the answer
// into `resp`, which must be a pointer (it may be nil if you don't care about
// the answer). A non-empty `errors` field is reported as a *GraphQLErrors, even
// when the status code is 200 -- that is the normal way for a GraphQL server to
// report an error, and ignoring it means silently decoding zero values.
//
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
func DoGraphQL(ctx context.Context, client *http.Client, url, query string, variables map[string]any, resp any) error {
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
	httpResp, err := Do(ctx, client, http.MethodPost, url, reqBody)
	if err != nil {
		return fmt.Errorf("error while querying: %w", err)
	}
	defer httpResp.Body.Close()

	// It would be more efficient to parse the JSON blob straight from the
	// io.Reader (would use less memory), but I don't care. If the body can't be
	// parsed as JSON, I want to see a dump of it.
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxBodySize))
	if err != nil {
		return fmt.Errorf("status code %d, error while reading body: %w", httpResp.StatusCode, err)
	}

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []GraphQLError  `json:"errors"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		if httpResp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code %d, body: %s", httpResp.StatusCode, string(body))
		}
		return fmt.Errorf("status code was 200, but the body isn't a GraphQL answer: %s\nbody: %s", err, string(body))
	}

	if len(envelope.Errors) > 0 {
		return &GraphQLErrors{StatusCode: httpResp.StatusCode, Errors: envelope.Errors}
	}
	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d, body: %s", httpResp.StatusCode, string(body))
	}
	if resp == nil || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil
	}

	if err := json.Unmarshal(envelope.Data, resp); err != nil {
		return fmt.Errorf("status code was 200 but the 'data' field could not be parsed as %T: %s\nbody: %s", resp, err, string(body))
	}
	return nil
}

// I found that after many calls, the server starts returning:
//
//	HTTP/2.0 403
//	x-amzn-errortype: ForbiddenException
//
//	{"message":"Forbidden"}
//
// Also, in some instances, it returns an error with `peer closed connection`.
//
// Do wraps client.Do and retries the transient failures with an exponential
// backoff that stops as soon as the context is cancelled. Note that a 403 is
// NOT treated as rate limiting anymore: an expired or revoked token also
// answers 403, and retrying that for minutes only delays the error. It is
// retried once, in case it really was a hiccup, and that's it.
func Do(ctx context.Context, client *http.Client, method string, url string, body []byte) (*http.Response, error) {
	const maxAttempts = 4

	backoff := firstBackoff
	forbiddenRetries := 1

	for attempt := 1; ; attempt++ {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reader)
		if err != nil {
			return nil, fmt.Errorf("while creating request: %w", err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := client.Do(req)

		var reason string
		switch {
		case err != nil && ctx.Err() != nil:
			// Don't retry when we are the ones giving up.
			return nil, fmt.Errorf("while doing request: %w", err)
		case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
			// `resp` is nil when `err` is non-nil: closing resp.Body here used
			// to panic the whole process on every connection reset.
			reason = fmt.Sprintf("connection reset (%v)", err)
		case err != nil:
			return nil, fmt.Errorf("while doing request: %w", err)
		case resp.StatusCode == http.StatusTooManyRequests,
			resp.StatusCode == http.StatusBadGateway,
			resp.StatusCode == http.StatusServiceUnavailable,
			resp.StatusCode == http.StatusGatewayTimeout:
			reason = fmt.Sprintf("status code %d", resp.StatusCode)
			resp.Body.Close()
		case resp.StatusCode == http.StatusForbidden && forbiddenRetries > 0:
			forbiddenRetries--
			reason = "status code 403"
			resp.Body.Close()
		default:
			return resp, nil
		}

		if attempt >= maxAttempts {
			return nil, fmt.Errorf("giving up after %d attempts, last failure: %s", attempt, reason)
		}
		logutil.Infof("%s, retrying in %s (attempt %d/%d)", reason, backoff, attempt, maxAttempts)
		if err := sleepCtx(ctx, backoff); err != nil {
			return nil, fmt.Errorf("while waiting to retry after %s: %w", reason, err)
		}
		backoff *= 2
	}
}

// sleepCtx waits for `d`, or until the context is cancelled, whichever comes
// first. Contrary to time.Sleep, a cancelled context doesn't have to wait for
// the whole duration to elapse.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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

func GetCouncilMissionSuppliersAPI(ctx context.Context, client *http.Client, graphqlURL, accountUUID string) ([]SupplierContractAPI, error) {
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

	var contracts []SupplierContractAPI
	_, err := paginate(ctx, "", func(ctx context.Context, after *string) (pageInfo, error) {
		var resp struct {
			CoownerAccount struct {
				UUID           string `json:"uuid"`
				TrusteeCouncil struct {
					SupplierContracts struct {
						PageInfo pageInfo `json:"pageInfo"`
						Edges    []struct {
							Node struct {
								ID          string         `json:"id"`
								Label       string         `json:"label"`
								Description string         `json:"description"`
								Number      string         `json:"number"`
								EndingDate  Time           `json:"endingDate"`
								Supplier    supplierNode   `json:"supplier"`
								Documents   []documentNode `json:"documents"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"supplierContracts"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		}

		err := DoGraphQL(ctx, client, graphqlURL, getSuppliersQuery, map[string]any{
			"accountUuid":      accountUUID,
			"description":      "",
			"supplierFullname": "",
			"first":            perPage,
			"after":            after,
		}, &resp)
		if err != nil {
			return pageInfo{}, fmt.Errorf("error while querying getCouncilMissionSuppliers: %w", err)
		}

		for _, edge := range resp.CoownerAccount.TrusteeCouncil.SupplierContracts.Edges {
			var docs []DocumentAPI
			for _, doc := range edge.Node.Documents {
				docs = append(docs, DocumentAPI{
					ID:               doc.ID,
					HashFile:         db.HashFile(doc.HashFile),
					OriginalFilename: doc.OriginalFilename,
					MimeType:         doc.MimeType,
					Category:         doc.Category,
					CreatedAt:        doc.CreatedAt.Time,
				})
			}
			contracts = append(contracts, SupplierContractAPI{
				ID:          edge.Node.ID,
				Label:       edge.Node.Label,
				Description: edge.Node.Description,
				Number:      edge.Node.Number,
				EndingDate:  edge.Node.EndingDate.Time,
				Supplier:    edge.Node.Supplier.toAPI(),
				Documents:   docs,
			})
		}
		return resp.CoownerAccount.TrusteeCouncil.SupplierContracts.PageInfo, nil
	})
	if err != nil {
		return nil, err
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
func GetInvoiceURL(ctx context.Context, client *http.Client, graphqlURL, invoiceID string) (filename, fileURL string, _ error) {
	const getInvoiceURLQuery = `query getInvoiceURL($invoiceId: String!) {invoiceURL(invoiceId: $invoiceId)}`
	var getInvoiceURLResp struct {
		InvoiceURL string `json:"invoiceURL"`
	}

	err := DoGraphQL(ctx, client, graphqlURL, getInvoiceURLQuery, map[string]any{
		"invoiceId": invoiceID,
	}, &getInvoiceURLResp)
	if err != nil {
		return "", "", fmt.Errorf("while querying getInvoiceURLResp: %w", err)
	}

	if getInvoiceURLResp.InvoiceURL == "" {
		return "", "", fmt.Errorf("getInvoiceURL: %w", ErrEmptyURL)
	}

	filename, err = getFilenameFromURL(getInvoiceURLResp.InvoiceURL)
	if err != nil {
		return "", "", fmt.Errorf("while getting filename from %s: %w", getInvoiceURLResp.InvoiceURL, err)
	}

	return filename, getInvoiceURLResp.InvoiceURL, nil
}

// To know if the URL returned was empty:
//
//	errors.Is(err, api.ErrEmptyURL)
func GetDocumentURL(ctx context.Context, client *http.Client, graphqlURL string, hash db.HashFile) (filename, fileURL string, _ error) {
	const getDocumentURLQuery = `query getDocumentURL($hash: String!) {documentURL(hash: $hash)}`
	var getDocumentURLResp struct {
		DocumentURL string `json:"documentURL"`
	}

	err := DoGraphQL(ctx, client, graphqlURL, getDocumentURLQuery, map[string]any{
		"hash": hash,
	}, &getDocumentURLResp)
	if err != nil {
		return "", "", fmt.Errorf("error while querying getDocumentURL: %w", err)
	}

	if getDocumentURLResp.DocumentURL == "" {
		return "", "", fmt.Errorf("getDocumentURL: %w", ErrEmptyURL)
	}

	filename, err = getFilenameFromURL(getDocumentURLResp.DocumentURL)
	if err != nil {
		return "", "", fmt.Errorf("error getting filename from URL: %w", err)
	}
	return filename, getDocumentURLResp.DocumentURL, nil
}

// The URLs are short-lived and look like this:
// https://fon-mil-prod-plato-prv.s3.eu-west-3.amazonaws.com/e/6/6/6/2/674836bfb753160398ee6662?X-Amz-Algorithm=AWS4-HMAC-SHA256&...&response-content-disposition=filename%3D%22IZQUIERDO%2520-%2520OSMIL806596688%2520-%25202024-11-28%2520-%252025-074.pdf%22&x-id=GetObject
//
// The file path is deduced from one of the URL's query parameters:
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
func GetBuildingAccountingCurrent(ctx context.Context, client *http.Client, graphqlURL, accountUUID string) ([]ExpenseDocumentAPI, error) {
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
		CoownerAccount struct {
			TrusteeCouncil struct {
				BankBalance       amount `json:"bankBalance"`
				AccountingCurrent struct {
					ID             string `json:"id"`
					OpeningDate    Time   `json:"openingDate"`
					ClosingDate    Time   `json:"closingDate"`
					PreviousTotal  amount `json:"previousTotal"`
					VotedTotal     amount `json:"votedTotal"`
					Total          amount `json:"total"`
					NextVotedTotal amount `json:"nextVotedTotal"`
					Allocations    []struct {
						ID             string `json:"id"`
						Name           string `json:"name"`
						Code           string `json:"code"`
						PreviousTotal  amount `json:"previousTotal"`
						VotedTotal     amount `json:"votedTotal"`
						Total          amount `json:"total"`
						NextVotedTotal amount `json:"nextVotedTotal"`
						ExpenseTypes   []struct {
							AllocationID   string `json:"allocationId"`
							Name           string `json:"name"`
							Code           string `json:"code"`
							PreviousTotal  amount `json:"previousTotal"`
							VotedTotal     amount `json:"votedTotal"`
							Total          amount `json:"total"`
							NextVotedTotal amount `json:"nextVotedTotal"`
							Expenses       []struct {
								// For some reason, expenses don't have an ID.
								// The invoice ID is sometimes empty... but we
								// use that since we have no other way.
								InvoiceID string `json:"invoiceId"`
								Piece     struct {
									ID       string `json:"id"`
									HashFile string `json:"hashFile"`
									Category string `json:"category"`
								} `json:"piece"`
								Label string `json:"label"`
								Date  Time   `json:"date"`
								// This is a union type, "Debit" or "Credit".
								Amount struct {
									amount
									Typename string `json:"__typename"`
								} `json:"amount"`
								IsFromPreviousPeriod bool `json:"isFromPreviousPeriod"`
							} `json:"expenses"`
						} `json:"expenseTypes"`
					} `json:"allocations"`
				} `json:"accountingCurrent"`
			} `json:"trusteeCouncil"`
		} `json:"coownerAccount"`
	}

	err := DoGraphQL(ctx, client, graphqlURL, getBuildingAccountingCurrentQuery, map[string]any{
		"uuid": accountUUID,
	}, &getBuildingAccountingCurrentResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getBuildingAccountingCurrentResp: %w", err)
	}

	var expenses []ExpenseDocumentAPI
	for _, allocation := range getBuildingAccountingCurrentResp.CoownerAccount.TrusteeCouncil.AccountingCurrent.Allocations {
		for _, expenseType := range allocation.ExpenseTypes {
			for _, expense := range expenseType.Expenses {
				var value int
				switch expense.Amount.Typename {
				case "Credit":
					value = -expense.Amount.Value
				case "Debit":
					value = expense.Amount.Value
				default:
					return nil, fmt.Errorf("was expecting typename 'Credit' or 'Debit', but got %q for expense %+v", expense.Amount.Typename, expense)
				}
				expenses = append(expenses, ExpenseDocumentAPI{
					HashFile:              db.HashFile(expense.Piece.HashFile),
					InvoiceID:             expense.InvoiceID,
					Label:                 expense.Label,
					Date:                  expense.Date.Time,
					Amount:                db.Amount(value),
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
func GetAccountingPeriods(ctx context.Context, client *http.Client, graphqlURL, accountUUID string) ([]AccountingPeriodAPI, error) {
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
		CoownerAccount struct {
			TrusteeCouncil struct {
				AccountingPeriods struct {
					TotalCount int      `json:"totalCount"`
					PageInfo   pageInfo `json:"pageInfo"`
					Edges      []struct {
						Node struct {
							ID          string `json:"id"`
							Name        string `json:"name"`
							OpeningDate Time   `json:"openingDate"`
							ClosingDate Time   `json:"closingDate"`
							Status      string `json:"status"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"accountingPeriods"`
			} `json:"trusteeCouncil"`
		} `json:"coownerAccount"`
	}

	err := DoGraphQL(ctx, client, graphqlURL, getAccountingPeriodsQuery, map[string]any{
		"accountUuid": accountUUID,
	}, &getAccountingPeriodsResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getAccountingPeriodsResp: %w", err)
	}

	var periods []AccountingPeriodAPI
	for _, edge := range getAccountingPeriodsResp.CoownerAccount.TrusteeCouncil.AccountingPeriods.Edges {
		periods = append(periods, AccountingPeriodAPI{
			ID:          edge.Node.ID,
			Name:        edge.Node.Name,
			OpeningDate: edge.Node.OpeningDate.Time,
			ClosingDate: edge.Node.ClosingDate.Time,
			Status:      edge.Node.Status,
		})
	}
	return periods, nil
}

// This query is light and doesn't need to be paginated. No need to remember the
// last cursor.
func GetBuildingAccountingRGDD(ctx context.Context, client *http.Client, graphqlURL, accountUUID, accountingPeriodID string) ([]ExpenseDocumentAPI, error) {
	const getBuildingAccountingRGDDQuery = `
		query getBuildingAccountingRGDD($uuid: EncodedID!, $accountingPeriodId: String) {
		  coownerAccount(uuid: $uuid) {
		    uuid
		    trusteeCouncil {
		      pastAccountingRGDD(accountingPeriodId: $accountingPeriodId) {
		        totalToAllocate {value currency}
		        totalVat {value currency}
		        totalRecoverable {value currency}
		        allocations {
		          id
		          name
		          code
		          toAllocate {value currency}
		          vat {value currency}
		          recoverable {value currency}
		          expenseTypes {
		            id
		            allocationId
		            name
		            code
		            toAllocate {value currency}
		            vat {value currency}
		            recoverable {value currency}
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
		              toAllocate {value currency}
		              vat {value currency}
		              recoverable {value currency}
		            }
		          }
		        }
		      }
		    }
		  }
		}`
	var getBuildingAccountingRGDDResp struct {
		CoownerAccount struct {
			TrusteeCouncil struct {
				PastAccountingRGDD struct {
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
								Label     string `json:"label"`
								Date      Time   `json:"date"`
								InvoiceID string `json:"invoiceId"`
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
				} `json:"pastAccountingRGDD"`
			} `json:"trusteeCouncil"`
		} `json:"coownerAccount"`
	}

	err := DoGraphQL(ctx, client, graphqlURL, getBuildingAccountingRGDDQuery, map[string]any{
		"uuid":               accountUUID,
		"accountingPeriodId": accountingPeriodID,
	}, &getBuildingAccountingRGDDResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying getBuildingAccountingRGDDResp: %w", err)
	}

	var expenses []ExpenseDocumentAPI
	for _, allocation := range getBuildingAccountingRGDDResp.CoownerAccount.TrusteeCouncil.PastAccountingRGDD.Allocations {
		for _, expenseType := range allocation.ExpenseTypes {
			for _, expense := range expenseType.Expenses {
				expenses = append(expenses, ExpenseDocumentAPI{
					InvoiceID:             expense.InvoiceID, // May be empty.
					HashFile:              db.HashFile(expense.Piece.HashFile),
					Label:                 expense.Label,
					Date:                  expense.Date.Time,
					Amount:                db.Amount(expense.ToAllocate.Value),
					AccountingAllocation:  allocation.Name,
					AccountingExpenseType: expenseType.Name,
				})
			}
		}
	}
	return expenses, nil
}

func Download(ctx context.Context, client *http.Client, fileURL string, filePath string) error {
	// No need to use the authenticated client here since the URL is
	// authenticated using one of the query parameters.
	resp, err := Do(ctx, client, http.MethodGet, fileURL, nil)
	if err != nil {
		return fmt.Errorf("while downloading invoice: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("while downloading %s: unexpected status code %d", fileURL, resp.StatusCode)
	}

	// Ensure destination directory exists.
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return fmt.Errorf("while ensuring destination directory: %v", err)
	}

	// Write to a temporary file and then atomically rename.
	tmpPath := filePath + ".part"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("while creating temp file: %v", err)
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("while streaming download to disk: %v", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("while closing temp file: %v", closeErr)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("while renaming temp file: %v", err)
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

type AccountDocumentAPI struct {
	ID               string
	HashFile         db.HashFile
	MimeType         string
	OriginalFilename string
	Category         db.DocumentCategory // Example: "reportVisit"
	CreatedAt        time.Time
}

func GetAccountDocuments(ctx context.Context, client *http.Client, graphqlURL, accountUUID string, category db.DocumentCategory) ([]AccountDocumentAPI, error) {
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

	var docs []AccountDocumentAPI
	// The "generalAssembly" category has more documents than fit in a single
	// page, so we have to follow the cursor.
	_, err := paginate(ctx, "", func(ctx context.Context, after *string) (pageInfo, error) {
		var resp struct {
			Account struct {
				Documents struct {
					TotalCount int      `json:"totalCount"`
					PageInfo   pageInfo `json:"pageInfo"`
					Edges      []struct {
						Node documentNode `json:"node"`
					} `json:"edges"`
				} `json:"documents"`
			} `json:"account"`
		}
		err := DoGraphQL(ctx, client, graphqlURL, getAccountDocumentsQuery, map[string]any{
			"accountUuid":            accountUUID,
			"originalFilename":       "",
			"subCategories":          []string{},
			"customerPortalCategory": category,
			"first":                  perPage,
			"after":                  after,
		}, &resp)
		if err != nil {
			return pageInfo{}, fmt.Errorf("error while querying getAccountDocumentsResp: %w", err)
		}

		for _, edge := range resp.Account.Documents.Edges {
			docs = append(docs, AccountDocumentAPI{
				ID:               edge.Node.ID,
				HashFile:         db.HashFile(edge.Node.HashFile),
				MimeType:         edge.Node.MimeType,
				OriginalFilename: edge.Node.OriginalFilename,
				Category:         db.DocumentCategory(edge.Node.Category),
				CreatedAt:        edge.Node.CreatedAt.Time,
			})
		}
		return resp.Account.Documents.PageInfo, nil
	})
	if err != nil {
		return nil, err
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
func GetRepairBudgets(ctx context.Context, client *http.Client, graphqlURL, accountUUID string) ([]RepairBudgetAPI, error) {
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
		RepairBudgets []struct {
			ID              string `json:"id"`
			Label           string `json:"label"`
			ValidatedAmount amount `json:"validatedAmount"`
		} `json:"repairBudgets"`
	}

	err := DoGraphQL(ctx, client, graphqlURL, getRepairBudgetsQuery, map[string]any{
		"accountUuid": accountUUID,
	}, &listRepairIDsResp)
	if err != nil {
		return nil, fmt.Errorf("error while querying listRepairIDsResp: %w", err)
	}

	var budgets []RepairBudgetAPI
	for _, repair := range listRepairIDsResp.RepairBudgets {
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
func GetRepairBudgetDetails(ctx context.Context, client *http.Client, graphqlURL, accountUUID, budgetID string) ([]ExpenseDocumentAPI, error) {
	details, err := GetRepairBudgetDetailsFull(ctx, client, graphqlURL, accountUUID, budgetID)
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
func GetRepairBudgetDetailsFull(ctx context.Context, client *http.Client, graphqlURL, accountUUID, budgetID string) (RepairBudgetDetailsAPI, error) {
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
		        totalToAllocate {value currency}
		        totalVat {value currency}
		        totalRecoverable {value currency}
		        allocations {
		          id
		          name
		          code
		          toAllocate {value currency}
		          vat {value currency}
		          recoverable {value currency}
		          expenseTypes {
		            id
		            allocationId
		            name
		            code
		            toAllocate {value currency}
		            vat {value currency}
		            recoverable {value currency}
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
		              toAllocate {value currency}
		              vat {value currency}
		              recoverable {value currency}
		            }
		          }
		        }
		      }
		    }
		  }
		}`
	var getRepairBudgetDetailsResp struct {
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
								Date      Time   `json:"date"`
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
	}

	err := DoGraphQL(ctx, client, graphqlURL, getRepairBudgetDetailsQuery, map[string]any{
		"accountUuid": accountUUID,
		"budgetId":    budgetID,
	}, &getRepairBudgetDetailsResp)
	if err != nil {
		return RepairBudgetDetailsAPI{}, fmt.Errorf("error while querying getRepairBudgetDetailsResp: %w", err)
	}

	raw := getRepairBudgetDetailsResp.CoownerAccount.TrusteeCouncil.RepairBudgets
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
				t.Expenses = append(t.Expenses, RepairExpenseAPI{
					ID:          expense.ID,
					InvoiceID:   expense.InvoiceID, // May be empty.
					HashFile:    db.HashFile(expense.Piece.HashFile),
					Label:       expense.Label,
					Date:        expense.Date.Time,
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

// GetCouncilCoowners returns every co-owner of the building. It is paginated:
// a building with more than 100 lots doesn't fit in a single page.
func GetCouncilCoowners(ctx context.Context, client *http.Client, graphqlURL, accountUUID string) ([]Coowner, error) {
	const getCouncilCoownersQuery = `
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
      }`

	var coowners []Coowner
	_, err := paginate(ctx, "", func(ctx context.Context, after *string) (pageInfo, error) {
		var resp struct {
			CoownerAccount struct {
				TrusteeCouncil struct {
					Coowners struct {
						TotalCount int      `json:"totalCount"`
						PageInfo   pageInfo `json:"pageInfo"`
						Edges      []struct {
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
								Balance amount `json:"balance"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"coowners"`
				} `json:"trusteeCouncil"`
			} `json:"coownerAccount"`
		}

		err := DoGraphQL(ctx, client, graphqlURL, getCouncilCoownersQuery, map[string]any{
			"accountUuid":      accountUUID,
			"first":            perPage,
			"after":            after,
			"customerName":     "",
			"fullAddress":      "",
			"sortBy":           map[string]string{"key": "customerName", "direction": "ASC"},
			"units":            []string(nil),
			"holderProperties": []string(nil),
		}, &resp)
		if err != nil {
			return pageInfo{}, fmt.Errorf("error while querying getCouncilCoownersResp: %w", err)
		}

		for _, edge := range resp.CoownerAccount.TrusteeCouncil.Coowners.Edges {
			var units []int
			for _, unit := range edge.Node.Units {
				unitNumber, err := strconv.Atoi(unit.CoOwnershipByLawsID)
				if err != nil {
					return pageInfo{}, fmt.Errorf("error parsing unit number %s: %w", unit.CoOwnershipByLawsID, err)
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
		return resp.CoownerAccount.TrusteeCouncil.Coowners.PageInfo, nil
	})
	if err != nil {
		return nil, err
	}
	return coowners, nil
}
