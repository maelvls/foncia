package api

import (
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
	err = DoGraphQL(client, s.URL, `query whatever {foo}`, nil, &resp)
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
		require.NoError(t, DoGraphQL(client, s.URL, `query whatever {foo}`, nil, &resp))
	}
	assert.Equal(t, 1, logins, "a token that is still valid must not be thrown away")
}

// The whole point of the change: oauth2 only asks for a new token when it knows
// when the current one expires.
func TestLoginTokenSource_setsTheExpiry(t *testing.T) {
	logins := 0
	expiry := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	s := loginServer(t, expiry, &logins)

	src := &loginTokenSource{authClient: &http.Client{}, graphqlURL: s.URL, username: "user", password: Password("pass")}
	token, err := src.Token()
	require.NoError(t, err)
	assert.WithinDuration(t, expiry, token.Expiry, time.Second)
	assert.True(t, token.Valid())
}
