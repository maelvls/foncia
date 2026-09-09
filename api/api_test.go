package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFilenameFromURL(t *testing.T) {
	tests := []struct {
		fileURL    string
		want       string
		wantErrMsg string
	}{
		{
			fileURL:    "https://fon-mil-prod-plato-prv.s3.eu-west-3.amazonaws.com/e/6/6/6/2/674836bfb753160398ee6662?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAXMTESETVHY3LHMDR%2F20250129%2Feu-west-3%2Fs3%2Faws4_request&X-Amz-Date=20250129T171628Z&X-Amz-Expires=900&X-Amz-Signature=7c1094dee2ee4812de265c48533846f9a353a4be234180ed47b0d772c91dcbd6&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22IZQUIERDO%2520-%2520OSMIL806596688%2520-%25202024-11-28%2520-%252025-074.pdf%22&x-id=GetObject",
			want:       "IZQUIERDO - OSMIL806596688 - 2024-11-28 - 25-074.pdf",
			wantErrMsg: "",
		},
		{
			fileURL: "https://fon-mil-prod-plato-prv.s3.eu-west-3.amazonaws.com/0/1/f/d/9/66bc771ee645112312b01fd9?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20250129T181523Z&X-Amz-Expires=900&X-Amz-Signature=28b58b496179eac70b6f77dff72ecaf8578a069eae1551780667ed3716758eb1&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22VALAIS%2520-%2520OSMIL805875306%2520-%25202024-08-14%2520-%252023%2F07%2F2024.pdf%22&x-id=GetObject",
			// Orig:    "VALAIS - OSMIL805875306 - 2024-08-14 - 23/07/2024.pdf"
			want:       "VALAIS - OSMIL805875306 - 2024-08-14 - 23-07-2024.pdf",
			wantErrMsg: "",
		},
		{
			// The URL has expired or was truncated: no
			// response-content-disposition means no filename to be found.
			fileURL:    "https://fon-mil-prod-plato-prv.s3.eu-west-3.amazonaws.com/0/1/f/d/9/66bc771ee645112312b01fd9?x-id=GetObject",
			want:       "",
			wantErrMsg: "could not find response-content-disposition in URL: https://fon-mil-prod-plato-prv.s3.eu-west-3.amazonaws.com/0/1/f/d/9/66bc771ee645112312b01fd9?x-id=GetObject",
		},
	}
	for _, tt := range tests {
		t.Run(tt.fileURL, func(t *testing.T) {
			got, err := getFilenameFromURL(tt.fileURL)
			if tt.wantErrMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErrMsg)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// fastBackoff shrinks the retry backoff so that the tests that exercise the
// retry path don't take seconds.
func fastBackoff(t *testing.T) {
	t.Helper()
	old := firstBackoff
	firstBackoff = time.Millisecond
	t.Cleanup(func() { firstBackoff = old })
}

// roundTripFunc turns a func into an http.RoundTripper.
type roundTripFunc func(r *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A connection reset used to panic the whole process: the error is non-nil, so
// `resp` is nil, and Do called resp.Body.Close() on it.
func TestDo_retriesOnConnectionResetWithoutDereferencingTheNilResponse(t *testing.T) {
	fastBackoff(t)

	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			// This is what the net package hands back on an RST: an error, and
			// no response at all.
			return nil, syscall.ECONNRESET
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"data":{}}`)),
			Header:     http.Header{},
		}, nil
	})}

	require.NotPanics(t, func() {
		resp, err := Do(context.Background(), client, http.MethodPost, "http://example.com", []byte(`{}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, 200, resp.StatusCode)
	})
	assert.Equal(t, 2, calls, "the request must have been retried once")
}

func TestDo_givesUpAfterAFewAttempts(t *testing.T) {
	fastBackoff(t)

	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, syscall.ECONNRESET
	})}

	_, err := Do(context.Background(), client, http.MethodPost, "http://example.com", []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "giving up after 4 attempts")
	assert.Equal(t, 4, calls)
}

// A 403 is what an expired or revoked token looks like; it used to be retried
// ten times with 30 seconds in between, i.e. five minutes of a stuck HTTP
// handler.
func TestDo_doesNotRetry403Forever(t *testing.T) {
	fastBackoff(t)

	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(strings.NewReader(`{"message":"Forbidden"}`)),
			Header:     http.Header{},
		}, nil
	})}

	resp, err := Do(context.Background(), client, http.MethodPost, "http://example.com", []byte(`{}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, 2, calls, "a 403 is retried at most once, then handed back to the caller")
}

func TestDo_stopsWaitingWhenTheContextIsCancelled(t *testing.T) {
	old := firstBackoff
	firstBackoff = 10 * time.Second
	t.Cleanup(func() { firstBackoff = old })

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Body:       io.NopCloser(strings.NewReader(``)),
			Header:     http.Header{},
		}, nil
	})}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := Do(ctx, client, http.MethodPost, "http://example.com", []byte(`{}`))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 5*time.Second, "the backoff must be interrupted by the context")
}

// GraphQL reports errors with a 200 status code. Ignoring the `errors` field
// meant decoding `{"data":null,...}` into zero values and pretending everything
// went fine.
func TestDoGraphQL_reportsTheErrorsFieldOnA200(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"Not authorized","locations":[{"line":1,"column":7}]}]}`))
	}))
	t.Cleanup(s.Close)

	var resp struct {
		Foo string `json:"foo"`
	}
	err := DoGraphQL(context.Background(), s.Client(), s.URL, `query whatever {foo}`, nil, &resp)
	require.Error(t, err)

	var gqlErrs *GraphQLErrors
	require.ErrorAs(t, err, &gqlErrs)
	assert.Equal(t, 200, gqlErrs.StatusCode)
	require.Len(t, gqlErrs.Errors, 1)
	assert.Equal(t, "Not authorized", gqlErrs.Errors[0].Message)
	assert.Empty(t, resp.Foo)
}

func TestDoGraphQL_reportsA400(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"nope\" on type \"Query\"."}]}`))
	}))
	t.Cleanup(s.Close)

	var resp struct{}
	err := DoGraphQL(context.Background(), s.Client(), s.URL, `query whatever {nope}`, nil, &resp)
	require.Error(t, err)

	var gqlErrs *GraphQLErrors
	require.ErrorAs(t, err, &gqlErrs)
	assert.Equal(t, 400, gqlErrs.StatusCode)
	assert.Contains(t, err.Error(), `Cannot query field "nope"`)
}

func TestDoGraphQL_reportsANonJSONBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<html>nope</html>`))
	}))
	t.Cleanup(s.Close)

	var resp struct{}
	err := DoGraphQL(context.Background(), s.Client(), s.URL, `query whatever {foo}`, nil, &resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code 400")
	assert.Contains(t, err.Error(), "<html>nope</html>")
}

func TestDoGraphQL_unmarshalsTheDataField(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"foo":"bar"}}`))
	}))
	t.Cleanup(s.Close)

	var resp struct {
		Foo string `json:"foo"`
	}
	require.NoError(t, DoGraphQL(context.Background(), s.Client(), s.URL, `query whatever {foo}`, nil, &resp))
	assert.Equal(t, "bar", resp.Foo)
}

func TestTime_unmarshalJSON(t *testing.T) {
	var v struct {
		Date Time `json:"date"`
	}

	require.NoError(t, json.Unmarshal([]byte(`{"date":""}`), &v))
	assert.True(t, v.Date.IsZero(), "the API uses an empty string for a missing date")

	require.NoError(t, json.Unmarshal([]byte(`{"date":null}`), &v))
	assert.True(t, v.Date.IsZero())

	require.NoError(t, json.Unmarshal([]byte(`{"date":"2024-03-01T00:00:00.000Z"}`), &v))
	assert.Equal(t, "2024-03-01T00:00:00Z", v.Date.UTC().Format(time.RFC3339))

	// A date that isn't a date must be an error, not a silently dropped record.
	require.Error(t, json.Unmarshal([]byte(`{"date":"01/03/2024"}`), &v))
	require.Error(t, json.Unmarshal([]byte(`{"date":42}`), &v))
}

// gqlRequest is the body of a GraphQL request, as the test servers see it.
type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

func readGQLRequest(t *testing.T, r *http.Request) gqlRequest {
	t.Helper()
	var req gqlRequest
	require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
	return req
}

func missionPage(id, endCursor string, hasNextPage bool) string {
	edges := ""
	if id != "" {
		edges = fmt.Sprintf(`{"node":{"id":%q,"number":%q,"label":"l","status":"s","description":"d","startedAt":"2024-01-01T00:00:00.000Z"}}`, id, id)
	}
	return fmt.Sprintf(`{"totalCount":2,"pageInfo":{"endCursor":%q,"hasNextPage":%t},"edges":[%s]}`, endCursor, hasNextPage, edges)
}

// The incidents and the repairs are two separate paginated lists. Feeding the
// repairs cursor to the incidents query (which is what the single-cursor
// version did) silently skips missions.
func TestGetMissionsAPI_keepsTheTwoCursorsApart(t *testing.T) {
	var incidentsAfter, repairsAfter []string

	// after -> page.
	incidents := map[string]string{
		"":     missionPage("i1", "inc1", true),
		"inc1": missionPage("i2", "inc2", false),
		"inc2": missionPage("", "", false),
	}
	repairs := map[string]string{
		"":     missionPage("r1", "rep1", true),
		"rep1": missionPage("r2", "rep2", false),
		"rep2": missionPage("", "", false),
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQLRequest(t, r)
		after, _ := req.Variables["after"].(string)
		switch {
		case strings.Contains(req.Query, "missionIncidents"):
			incidentsAfter = append(incidentsAfter, after)
			page, ok := incidents[after]
			require.True(t, ok, "unexpected incidents cursor %q", after)
			fmt.Fprintf(w, `{"data":{"coownerAccount":{"uuid":"u","trusteeCouncil":{"missionIncidents":%s}}}}`, page)
		case strings.Contains(req.Query, "missionRepairs"):
			repairsAfter = append(repairsAfter, after)
			page, ok := repairs[after]
			require.True(t, ok, "unexpected repairs cursor %q", after)
			fmt.Fprintf(w, `{"data":{"coownerAccount":{"uuid":"u","trusteeCouncil":{"missionRepairs":%s}}}}`, page)
		default:
			t.Errorf("unexpected query: %s", req.Query)
		}
	}))
	t.Cleanup(s.Close)

	missions, cursor, err := GetMissionsAPI(context.Background(), s.Client(), s.URL, "account-uuid", MissionsCursor{})
	require.NoError(t, err)
	assert.Len(t, missions, 4)
	assert.Equal(t, []string{"", "inc1"}, incidentsAfter)
	assert.Equal(t, []string{"", "rep1"}, repairsAfter)
	assert.Equal(t, MissionsCursor{IncidentsCursor: "inc2", RepairsCursor: "rep2"}, cursor)

	// Now the round trip: the cursor we got back must be fed to the right
	// query. The incidents query must never see "rep2".
	incidentsAfter, repairsAfter = nil, nil
	missions, cursor2, err := GetMissionsAPI(context.Background(), s.Client(), s.URL, "account-uuid", cursor)
	require.NoError(t, err)
	assert.Empty(t, missions, "nothing new since the last sync")
	assert.Equal(t, []string{"inc2"}, incidentsAfter)
	assert.Equal(t, []string{"rep2"}, repairsAfter)
	assert.Equal(t, cursor, cursor2, "an empty page must not lose the cursor")
}

func TestGetCouncilCoowners_followsTheCursor(t *testing.T) {
	page := func(id, name, unit, endCursor string, hasNextPage bool) string {
		return fmt.Sprintf(`{"data":{"coownerAccount":{"trusteeCouncil":{"coowners":{"totalCount":2,`+
			`"pageInfo":{"endCursor":%q,"hasNextPage":%t},`+
			`"edges":[{"node":{"id":%q,"units":[{"id":"u","number":"n","coOwnershipByLawsId":%q}],`+
			`"mainHolder":{"customer":{"displayName":%q}}}}]}}}}}`, endCursor, hasNextPage, id, unit, name)
	}
	var seen []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQLRequest(t, r)
		after, _ := req.Variables["after"].(string)
		seen = append(seen, after)
		if after == "" {
			fmt.Fprint(w, page("1", "DUPONT", "12", "c1", true))
			return
		}
		fmt.Fprint(w, page("2", "MARTIN", "34", "c2", false))
	}))
	t.Cleanup(s.Close)

	coowners, err := GetCouncilCoowners(context.Background(), s.Client(), s.URL, "account-uuid")
	require.NoError(t, err)
	require.Len(t, coowners, 2, "a building with more than one page of lots must not be truncated")
	assert.Equal(t, []string{"", "c1"}, seen)
	assert.Equal(t, "DUPONT", coowners[0].DisplayName)
	assert.Equal(t, []int{34}, coowners[1].Units)
}

// The `amount` union ("Debit" or "Credit") is decoded through an embedded
// struct, and a credit must come out negative.
func TestGetBuildingAccountingCurrent_creditsAreNegative(t *testing.T) {
	const body = `{"data":{"coownerAccount":{"trusteeCouncil":{"accountingCurrent":{"allocations":[
	  {"name":"CHARGES GENERALES","expenseTypes":[{"name":"CONTRAT D'ENTRETIEN","expenses":[
	    {"invoiceId":"inv1","label":"a debit","date":"2024-03-01T00:00:00.000Z","piece":{"hashFile":"h1"},
	     "amount":{"value":1250,"currency":"EUR","__typename":"Debit"}},
	    {"invoiceId":"inv2","label":"a credit","date":"","piece":{"hashFile":""},
	     "amount":{"value":300,"currency":"EUR","__typename":"Credit"}}
	  ]}]}
	]}}}}}`
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)

	expenses, err := GetBuildingAccountingCurrent(context.Background(), s.Client(), s.URL, "account-uuid")
	require.NoError(t, err)
	require.Len(t, expenses, 2)
	assert.EqualValues(t, 1250, expenses[0].Amount)
	assert.EqualValues(t, -300, expenses[1].Amount)
	assert.Equal(t, "CHARGES GENERALES", expenses[0].AccountingAllocation)
	assert.Equal(t, "CONTRAT D'ENTRETIEN", expenses[0].AccountingExpenseType)
	assert.Equal(t, "2024-03-01T00:00:00Z", expenses[0].Date.UTC().Format(time.RFC3339))
	assert.True(t, expenses[1].Date.IsZero(), "an empty date is not an error")
}

func TestGetAccountUUID(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"accounts":[{"uuid":"the-uuid"}]}}`))
	}))
	t.Cleanup(s.Close)

	uuid, err := GetAccountUUID(context.Background(), s.Client(), s.URL)
	require.NoError(t, err)
	assert.Equal(t, "the-uuid", uuid)
}

func TestGetAccountUUID_noAccounts(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"accounts":[]}}`))
	}))
	t.Cleanup(s.Close)

	_, err := GetAccountUUID(context.Background(), s.Client(), s.URL)
	assert.EqualError(t, err, "no accounts found")
}
