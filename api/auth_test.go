package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeJWT returns an unsigned JWT whose only claim is `exp`. parseJWTExp
// doesn't verify the signature, so this is enough.
func fakeJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{"exp": exp.Unix()})
	require.NoError(t, err)
	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + ".c2ln"
}

// loginServer serves the `login` mutation and counts how many times it was
// called. Every other query answers with an empty object.
func loginServer(t *testing.T, expiry time.Time, logins *int) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		if strings.Contains(string(body), "mutation login") {
			*logins++
			fmt.Fprintf(w, `{"data":{"login":{"token":%q}}}`, fakeJWT(t, expiry))
			return
		}
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	t.Cleanup(s.Close)
	return s
}

// The token that Foncia hands out is valid for 30 days. The `serve` command
// stays up for longer than that, and it used to keep using the very first token
// forever, which turned every call to the API into an error once the token had
// expired.
func TestAuthenticatedClient_logsInAgainWhenTheTokenHasExpired(t *testing.T) {
	logins := 0
	s := loginServer(t, time.Now().Add(-1*time.Hour), &logins)

	client, err := AuthenticatedClient(&http.Client{}, s.URL, "user", Password("pass"))
	require.NoError(t, err)
	assert.Equal(t, 1, logins, "AuthenticatedClient must log in once upfront so that bad credentials fail early")

	// The token we were given is already expired, so this call must trigger a
	// new login.
	var resp struct{}
	err = DoGraphQL(context.Background(), client, s.URL, `query whatever {foo}`, nil, &resp)
	require.NoError(t, err)
	assert.Equal(t, 2, logins, "an expired token must be replaced by a fresh one")
}

func TestAuthenticatedClient_reusesTheTokenUntilItExpires(t *testing.T) {
	logins := 0
	s := loginServer(t, time.Now().Add(30*24*time.Hour), &logins)

	client, err := AuthenticatedClient(&http.Client{}, s.URL, "user", Password("pass"))
	require.NoError(t, err)
	assert.Equal(t, 1, logins)

	for range 3 {
		var resp struct{}
		require.NoError(t, DoGraphQL(context.Background(), client, s.URL, `query whatever {foo}`, nil, &resp))
	}
	assert.Equal(t, 1, logins, "a token that is still valid must not be thrown away")
}

// The whole point of the change: we only ask for a new token when we know when
// the current one expires.
func TestLoginTokenSource_setsTheExpiry(t *testing.T) {
	logins := 0
	expiry := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	s := loginServer(t, expiry, &logins)

	src := &loginTokenSource{authClient: &http.Client{}, graphqlURL: s.URL, username: "user", password: Password("pass")}
	token, gotExpiry, err := src.Token(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, token.StringOnPurpose())
	assert.WithinDuration(t, expiry, gotExpiry, time.Second)
	assert.True(t, time.Now().Before(gotExpiry))
}

// Contrary to oauth2, our transport can also notice that the server rejected
// the token, which happens when the token was revoked before its `exp`.
func TestAuthenticatedClient_logsInAgainOnA401(t *testing.T) {
	logins := 0
	rejected := 0
	var tokens []string

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		if strings.Contains(string(body), "mutation login") {
			logins++
			fmt.Fprintf(w, `{"data":{"login":{"token":%q}}}`, fakeJWT(t, time.Now().Add(30*24*time.Hour)))
			return
		}
		tokens = append(tokens, r.Header.Get("Authorization"))
		// The very first non-login call is rejected, as if the token had been
		// revoked on the server side.
		if rejected == 0 {
			rejected++
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	t.Cleanup(s.Close)

	client, err := AuthenticatedClient(&http.Client{}, s.URL, "user", Password("pass"))
	require.NoError(t, err)

	var resp struct{}
	require.NoError(t, DoGraphQL(context.Background(), client, s.URL, `query whatever {foo}`, nil, &resp))
	assert.Equal(t, 2, logins, "a rejected token must trigger a new login")
	require.Len(t, tokens, 2, "the request must have been replayed with the new token")
	assert.True(t, strings.HasPrefix(tokens[0], "Bearer "))
	assert.True(t, strings.HasPrefix(tokens[1], "Bearer "))
}

// AuthenticatedClient and GetToken used to mutate the client they were given
// (CheckRedirect, Jar, and the debug transport), despite the doc comment
// promising they didn't.
func TestAuthenticatedClient_doesNotMutateTheGivenClient(t *testing.T) {
	logins := 0
	s := loginServer(t, time.Now().Add(30*24*time.Hour), &logins)

	given := &http.Client{}
	_, err := AuthenticatedClient(given, s.URL, "user", Password("pass"))
	require.NoError(t, err)

	assert.Nil(t, given.Transport, "the caller's client must be left alone")
	assert.Nil(t, given.Jar)
	assert.Nil(t, given.CheckRedirect)
	assert.Zero(t, given.Timeout)
}

func TestParseJWTExp(t *testing.T) {
	valid := fakeJWT(t, time.Unix(1700000000, 0))
	exp, err := parseJWTExp(valid)
	require.NoError(t, err)
	assert.Equal(t, int64(1700000000), exp.Unix())

	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

	tests := []struct {
		name       string
		token      string
		wantErrMsg string
	}{
		{"empty", "", "JWT has 1 parts instead of 3"},
		{"two parts", "a.b", "JWT has 2 parts instead of 3"},
		{"four parts", "a.b.c.d", "JWT has 4 parts instead of 3"},
		{"payload is not base64", "a.!!!.c", "while decoding JWT payload: illegal base64 data at input byte 0"},
		{"payload is not JSON", "a." + b64(`not json`) + ".c", "while unmarshaling JWT payload: invalid character 'o' in literal null (expecting 'u')"},
		{"payload is not an object", "a." + b64(`["exp"]`) + ".c", "while unmarshaling JWT payload: json: cannot unmarshal array into Go value of type map[string]interface {}"},
		{"no exp claim", "a." + b64(`{"sub":"me"}`) + ".c", "JWT payload does not contain 'exp'"},
		{"exp is a string", "a." + b64(`{"exp":"1700000000"}`) + ".c", "JWT payload 'exp' is not a number"},
		{"exp is null", "a." + b64(`{"exp":null}`) + ".c", "JWT payload 'exp' is not a number"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseJWTExp(tt.token)
			assert.EqualError(t, err, tt.wantErrMsg)
		})
	}
}

// A login that answers with a GraphQL error (e.g. wrong password) must fail
// right away rather than handing out an empty token.
func TestGetToken_reportsALoginError(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"Bad credentials"}]}`))
	}))
	t.Cleanup(s.Close)

	_, _, err := GetToken(context.Background(), s.Client(), s.URL, "user", Password("pass"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Bad credentials")
}
