package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRedirectURI = "https://claude.ai/api/mcp/auth_callback"
	testVerifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-and-some-more"
)

func testChallenge() string {
	sum := sha256.Sum256([]byte(testVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// noRedirect is a client that returns the redirects instead of following
// them, so that the tests can read the code in the Location header.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

func register(t *testing.T, srv *httptest.Server, body string) (status int, resp map[string]any) {
	t.Helper()
	r, err := http.Post(srv.URL+"/oauth/register", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	defer r.Body.Close()
	require.NoError(t, json.NewDecoder(r.Body).Decode(&resp))
	return r.StatusCode, resp
}

// registerPublic registers a public client the way Claude does.
func registerPublic(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	status, resp := register(t, srv, `{"client_name":"Claude","redirect_uris":["`+testRedirectURI+`"],"token_endpoint_auth_method":"none"}`)
	require.Equal(t, http.StatusCreated, status, resp)
	return resp["client_id"].(string)
}

func authorizeParams(clientID string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"state":                 {"some-state"},
		"code_challenge":        {testChallenge()},
		"code_challenge_method": {"S256"},
		"resource":              {""},
	}
}

// approve posts the consent form and returns the redirect to the client.
func approve(t *testing.T, srv *httptest.Server, params url.Values, action string, header http.Header) *http.Response {
	t.Helper()
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	form.Set("action", action)
	req, err := http.NewRequest("POST", srv.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := noRedirect.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func exchange(t *testing.T, srv *httptest.Server, form url.Values) (int, tokenResponse) {
	t.Helper()
	resp, err := http.PostForm(srv.URL+"/oauth/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var tok tokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	return resp.StatusCode, tok
}

// codeFrom reads the code that the server sent back to the client.
func codeFrom(t *testing.T, resp *http.Response) string {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, testRedirectURI, loc.Scheme+"://"+loc.Host+loc.Path)
	require.Empty(t, loc.Query().Get("error"), loc.Query().Get("error_description"))
	return loc.Query().Get("code")
}

// obtainTokens goes through the whole flow: registration, consent, code,
// token.
func obtainTokens(t *testing.T, srv *httptest.Server) tokenResponse {
	t.Helper()
	clientID := registerPublic(t, srv)
	code := codeFrom(t, approve(t, srv, authorizeParams(clientID), "allow", nil))

	status, tok := exchange(t, srv, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {testVerifier},
	})
	require.Equal(t, http.StatusOK, status, tok.Error)
	return tok
}

func TestOAuth_Metadata(t *testing.T) {
	srv := newMCPServer(t, openTestDB(t))

	t.Run("an unauthenticated /mcp points at the resource metadata", func(t *testing.T) {
		resp, err := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, `Bearer resource_metadata="`+srv.URL+`/.well-known/oauth-protected-resource/mcp"`, resp.Header.Get("WWW-Authenticate"))
	})

	for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		t.Run("protected resource metadata at "+path, func(t *testing.T) {
			var meta map[string]any
			getJSON(t, srv.URL+path, &meta)
			assert.Equal(t, srv.URL+"/mcp", meta["resource"])
			assert.Equal(t, []any{srv.URL}, meta["authorization_servers"])
		})
	}

	t.Run("authorization server metadata", func(t *testing.T) {
		var meta map[string]any
		getJSON(t, srv.URL+"/.well-known/oauth-authorization-server", &meta)
		assert.Equal(t, srv.URL, meta["issuer"])
		assert.Equal(t, srv.URL+"/oauth/authorize", meta["authorization_endpoint"])
		assert.Equal(t, srv.URL+"/oauth/token", meta["token_endpoint"])
		assert.Equal(t, srv.URL+"/oauth/register", meta["registration_endpoint"])
		assert.Equal(t, []any{"S256"}, meta["code_challenge_methods_supported"])
	})
}

func getJSON(t *testing.T, u string, v any) {
	t.Helper()
	resp, err := http.Get(u)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	require.NoError(t, json.NewDecoder(resp.Body).Decode(v))
}

func TestOAuth_Flow(t *testing.T) {
	srv := newMCPServer(t, openTestDB(t))

	t.Run("the consent page names the client and the co-owner", func(t *testing.T) {
		clientID := registerPublic(t, srv)
		resp, err := http.Get(srv.URL + "/oauth/authorize?" + authorizeParams(clientID).Encode())
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		assert.Contains(t, string(body), "Autoriser Claude ?")
		assert.Contains(t, string(body), testUser)
		assert.Contains(t, string(body), "claude.ai")
		assert.Equal(t, "frame-ancestors 'none'", resp.Header.Get("Content-Security-Policy"))
	})

	t.Run("tokens, then a refresh that rotates the refresh token", func(t *testing.T) {
		clientID := registerPublic(t, srv)
		code := codeFrom(t, approve(t, srv, authorizeParams(clientID), "allow", nil))
		form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "code_verifier": {testVerifier}}

		status, tok := exchange(t, srv, form)
		require.Equal(t, http.StatusOK, status, tok.Error)
		assert.Equal(t, "Bearer", tok.TokenType)
		assert.Equal(t, 3600, tok.ExpiresIn)
		assert.NotEmpty(t, tok.AccessToken)

		status, again := exchange(t, srv, form)
		assert.Equal(t, http.StatusBadRequest, status, "a code can only be used once")
		assert.Equal(t, "invalid_grant", again.Error)

		refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tok.RefreshToken}}
		status, refreshed := exchange(t, srv, refresh)
		require.Equal(t, http.StatusOK, status, refreshed.Error)
		assert.NotEqual(t, tok.RefreshToken, refreshed.RefreshToken)

		status, _ = exchange(t, srv, refresh)
		assert.Equal(t, http.StatusBadRequest, status, "a refresh token can only be used once")

		assert.Equal(t, http.StatusOK, mcpStatus(t, srv, refreshed.AccessToken))
		assert.Equal(t, http.StatusUnauthorized, mcpStatus(t, srv, "made-up"))
	})

	t.Run("a wrong PKCE verifier is refused", func(t *testing.T) {
		clientID := registerPublic(t, srv)
		code := codeFrom(t, approve(t, srv, authorizeParams(clientID), "allow", nil))

		status, tok := exchange(t, srv, url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "code_verifier": {strings.Repeat("x", 43)}})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_grant", tok.Error)
	})

	t.Run("a confidential client must give its secret", func(t *testing.T) {
		status, resp := register(t, srv, `{"client_name":"ChatGPT","redirect_uris":["`+testRedirectURI+`"]}`)
		require.Equal(t, http.StatusCreated, status)
		clientID, secret := resp["client_id"].(string), resp["client_secret"].(string)
		require.NotEmpty(t, secret)
		form := func() url.Values {
			code := codeFrom(t, approve(t, srv, authorizeParams(clientID), "allow", nil))
			return url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "code_verifier": {testVerifier}}
		}

		status, tok := exchange(t, srv, form())
		assert.Equal(t, http.StatusUnauthorized, status)
		assert.Equal(t, "invalid_client", tok.Error)

		f := form()
		f.Set("client_secret", secret)
		status, tok = exchange(t, srv, f)
		assert.Equal(t, http.StatusOK, status, tok.Error)
	})

	t.Run("denying sends access_denied back to the client", func(t *testing.T) {
		clientID := registerPublic(t, srv)
		resp := approve(t, srv, authorizeParams(clientID), "deny", nil)

		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		loc, _ := url.Parse(resp.Header.Get("Location"))
		assert.Equal(t, "access_denied", loc.Query().Get("error"))
		assert.Equal(t, "some-state", loc.Query().Get("state"))
		assert.Equal(t, srv.URL, loc.Query().Get("iss"))
	})

	t.Run("no code without the reverse proxy's login", func(t *testing.T) {
		clientID := registerPublic(t, srv)
		resp := approve(t, srv, authorizeParams(clientID), "allow", http.Header{"Test-Not-Logged-In": {"1"}})
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("a cross-site approval is refused", func(t *testing.T) {
		clientID := registerPublic(t, srv)
		resp := approve(t, srv, authorizeParams(clientID), "allow", http.Header{"Sec-Fetch-Site": {"cross-site"}})
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("an unregistered redirect URI is shown, not followed", func(t *testing.T) {
		clientID := registerPublic(t, srv)
		params := authorizeParams(clientID)
		params.Set("redirect_uri", "https://evil.example.com/callback")
		resp, err := noRedirect.Get(srv.URL + "/oauth/authorize?" + params.Encode())
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("PKCE is required", func(t *testing.T) {
		clientID := registerPublic(t, srv)
		params := authorizeParams(clientID)
		params.Del("code_challenge")
		resp, err := noRedirect.Get(srv.URL + "/oauth/authorize?" + params.Encode())
		require.NoError(t, err)
		defer resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		assert.Equal(t, "invalid_request", loc.Query().Get("error"))
	})

	t.Run("redirect URIs that run code are refused", func(t *testing.T) {
		status, resp := register(t, srv, `{"client_name":"x","redirect_uris":["javascript:alert(1)"]}`)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_redirect_uri", resp["error"])
	})
}

func mcpStatus(t *testing.T, srv *httptest.Server, token string) int {
	t.Helper()
	req, err := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestValidRedirectURI(t *testing.T) {
	for u, want := range map[string]bool{
		"https://claude.ai/api/mcp/auth_callback":               true,
		"https://chatgpt.com/connector_platform_oauth_redirect": true,
		"http://localhost:6274/oauth/callback":                  true,
		"http://127.0.0.1/cb":                                   true,
		"cursor://anysphere.cursor-retrieval/oauth/callback":    true,
		"http://example.com/cb":                                 false,
		"https://example.com/cb#frag":                           false,
		"javascript:alert(1)":                                   false,
		"data:text/html,hi":                                     false,
		"/relative":                                             false,
	} {
		assert.Equal(t, want, validRedirectURI(u), u)
	}
}
