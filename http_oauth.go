package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// OAuth 2.1 authorization server for the MCP endpoint, so that MCP clients
// (Claude, ChatGPT, Grok) connect to /mcp the way the MCP spec expects:
// protected resource metadata (RFC 9728) pointing at this server's metadata
// (RFC 8414), dynamic client registration (RFC 7591), authorization code with
// mandatory PKCE S256, and rotating refresh tokens.
//
// This process has no login of its own: the reverse proxy in front of it
// logs the co-owners in with Google and tells us who they are with
// --auth-header. So /oauth/authorize, where a co-owner approves a client,
// MUST be behind the proxy's login, like the web UI. The other endpoints are
// called by the clients' servers, without the co-owner's cookie: the proxy
// must let /mcp, /oauth/token, /oauth/register and /.well-known/oauth-* through
// without a login.
//
// The codes and tokens are random strings of which only the SHA-256 is kept in
// the database, so there is no signing key to configure or to leak.

const (
	oauthCodeTTL    = 5 * time.Minute
	oauthAccessTTL  = time.Hour
	oauthRefreshTTL = 30 * 24 * time.Hour
)

type oauthServer struct {
	sqlDB      *sql.DB
	issuer     string // Example: "https://suivi-terra-nostra-2.vls.dev", with the base path.
	basePath   string
	userHeader string // Set by the reverse proxy on /oauth/authorize. Example: "X-Token-User-Email".
}

// resource is the MCP endpoint's URL, the audience of the access tokens.
func (o oauthServer) resource() string { return o.issuer + "/mcp" }

// protectedResourceMetadataURL is where RFC 9728 puts the metadata of the
// resource: the well-known prefix at the root of the host, then the
// resource's path.
func (o oauthServer) protectedResourceMetadataURL() string {
	u, err := url.Parse(o.resource())
	if err != nil {
		return "/.well-known/oauth-protected-resource" + o.basePath + "/mcp"
	}
	return u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource" + u.Path
}

// addOAuthHandlers mounts the MCP endpoint and the OAuth endpoints. The ones
// called by the clients' servers go on rootMux, outside of --allowed-users
// since these requests don't carry the co-owner's identity; /oauth/authorize,
// opened in the co-owner's browser, goes on subMux like the web UI.
func addOAuthHandlers(rootMux, subMux *http.ServeMux, o oauthServer, mcpHandler http.Handler) {
	p := o.basePath
	rootMux.Handle(p+"/mcp", o.requireToken(mcpHandler))
	rootMux.HandleFunc("GET /.well-known/oauth-protected-resource"+p+"/mcp", o.handleProtectedResourceMetadata)
	// Grok asks for this one when the one above fails.
	rootMux.HandleFunc("GET /.well-known/oauth-protected-resource", o.handleProtectedResourceMetadata)
	rootMux.HandleFunc("GET /.well-known/oauth-authorization-server"+p, o.handleAuthServerMetadata)
	rootMux.HandleFunc("POST "+p+"/oauth/register", o.handleRegister)
	rootMux.HandleFunc("POST "+p+"/oauth/token", o.handleToken)
	for _, path := range []string{p + "/oauth/register", p + "/oauth/token", "/.well-known/"} {
		rootMux.HandleFunc("OPTIONS "+path, handleOAuthPreflight)
	}

	subMux.HandleFunc("GET /oauth/authorize", o.handleAuthorize)
	// The approval is a POST from the consent page. Refusing cross-site POSTs
	// means another site can't make a co-owner approve a client unknowingly.
	subMux.Handle("POST /oauth/authorize", http.NewCrossOriginProtection().Handler(http.HandlerFunc(o.handleApprove)))
}

// oauthCORS lets browser-based MCP clients reach the metadata, registration,
// token and MCP endpoints. None of them use cookies.
func oauthCORS(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Protocol-Version, Mcp-Session-Id")
	h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
}

func handleOAuthPreflight(w http.ResponseWriter, _ *http.Request) {
	oauthCORS(w)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logutil.Errorf("while writing a JSON response: %v", err)
	}
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func (o oauthServer) handleAuthServerMetadata(w http.ResponseWriter, _ *http.Request) {
	oauthCORS(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         o.issuer,
		"authorization_endpoint":                         o.issuer + "/oauth/authorize",
		"token_endpoint":                                 o.issuer + "/oauth/token",
		"registration_endpoint":                          o.issuer + "/oauth/register",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (o oauthServer) handleProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	oauthCORS(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 o.resource(),
		"authorization_servers":    []string{o.issuer},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Suivi Terra Nostra 2",
	})
}

// requireToken lets through the requests that carry a valid access token for
// /mcp. The others get the WWW-Authenticate challenge that starts an MCP
// client's OAuth flow.
func (o oauthServer) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauthCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		challenge := fmt.Sprintf("Bearer resource_metadata=%q", o.protectedResourceMetadataURL())
		token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found || token == "" {
			w.Header().Set("WWW-Authenticate", challenge)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_request", "an access token is required")
			return
		}
		g, err := db.GetOAuthToken(r.Context(), o.sqlDB, db.OAuthAccess, hashToken(token))
		if err == nil && g.Resource != o.resource() {
			err = fmt.Errorf("the token is for %s", g.Resource)
		}
		if err != nil {
			if !errors.Is(err, db.ErrOAuthNotFound) {
				logutil.Errorf("while checking an MCP access token from %s: %v", r.RemoteAddr, err)
			}
			w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "unknown or expired access token")
			return
		}
		logutil.Debugf("mcp: request from %s for %s", r.RemoteAddr, g.Email)
		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------------------
// Dynamic client registration (RFC 7591). Open to anyone: a client gets nothing
// until a co-owner approves it.
// -----------------------------------------------------------------------------

// validRedirectURI accepts https URLs, http on loopback (native apps and
// local tools) and private-use schemes (RFC 8252), never fragments or
// schemes that run code in the browser.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Fragment != "" || len(raw) > 2000 {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u.Host != ""
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	case "javascript", "data", "file", "vbscript", "about", "blob":
		return false
	}
	return true
}

func (o oauthServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	oauthCORS(w)
	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ClientName              string   `json:"client_name"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON body")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "between 1 and 10 redirect_uris are required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "unsupported redirect URI: "+u)
			return
		}
	}
	req.ClientName = strings.TrimSpace(req.ClientName)
	if len(req.ClientName) > 100 {
		req.ClientName = req.ClientName[:100]
	}

	c := db.OAuthClient{ID: randomToken(), Name: req.ClientName, RedirectURIs: req.RedirectURIs, CreatedAt: time.Now()}
	secret := ""
	switch req.TokenEndpointAuthMethod {
	case "none":
	case "", "client_secret_basic", "client_secret_post":
		// RFC 7591's default is client_secret_basic.
		if req.TokenEndpointAuthMethod == "" {
			req.TokenEndpointAuthMethod = "client_secret_basic"
		}
		secret = randomToken()
		c.SecretHash = hashToken(secret)
	default:
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method")
		return
	}
	if err := db.CreateOAuthClient(r.Context(), o.sqlDB, c); err != nil {
		logutil.Errorf("%v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not save the client")
		return
	}
	logutil.Infof("oauth: client %q registered from %s, redirect URIs: %s", c.Name, r.RemoteAddr, strings.Join(c.RedirectURIs, " "))

	resp := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        c.CreatedAt.Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"token_endpoint_auth_method": req.TokenEndpointAuthMethod,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	}
	if secret != "" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, resp)
}

// -----------------------------------------------------------------------------
// Authorization endpoint.
// -----------------------------------------------------------------------------

type authzRequest struct {
	Client      db.OAuthClient
	RedirectURI string
	State       string
	Challenge   string
}

// parseAuthorize validates an authorization request. Until the client and
// redirect URI are known good, errors are shown to the co-owner (redirect is
// false); after that they go back to the client.
func (o oauthServer) parseAuthorize(ctx context.Context, v url.Values) (req *authzRequest, redirect bool, code, desc string) {
	c, err := db.GetOAuthClient(ctx, o.sqlDB, v.Get("client_id"))
	if err != nil {
		if !errors.Is(err, db.ErrOAuthNotFound) {
			logutil.Errorf("%v", err)
		}
		return nil, false, "invalid_client", "Application inconnue. Retire le connecteur et ajoute-le à nouveau."
	}
	req = &authzRequest{Client: c, RedirectURI: v.Get("redirect_uri"), State: v.Get("state")}
	if req.RedirectURI == "" && len(c.RedirectURIs) == 1 {
		req.RedirectURI = c.RedirectURIs[0]
	}
	if !slices.Contains(c.RedirectURIs, req.RedirectURI) {
		return nil, false, "invalid_request", "Cette adresse de retour n'a pas été enregistrée par l'application."
	}
	switch {
	case v.Get("response_type") != "code":
		return req, true, "unsupported_response_type", "only response_type=code is supported"
	case v.Get("code_challenge") == "" || v.Get("code_challenge_method") != "S256":
		return req, true, "invalid_request", "PKCE with code_challenge_method=S256 is required"
	}
	req.Challenge = v.Get("code_challenge")
	if res := strings.TrimRight(v.Get("resource"), "/"); res != "" && res != o.resource() {
		return req, true, "invalid_target", "the only resource here is " + o.resource()
	}
	return req, false, "", ""
}

// redirectToClient sends the browser back to the client with the given
// parameters plus iss (RFC 9207).
func (o oauthServer) redirectToClient(w http.ResponseWriter, r *http.Request, req *authzRequest, params url.Values) {
	u, _ := url.Parse(req.RedirectURI)
	q := u.Query()
	for k, vs := range params {
		q[k] = vs
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", o.issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (o oauthServer) authorizeError(w http.ResponseWriter, r *http.Request, req *authzRequest, redirect bool, code, desc string) {
	if redirect {
		o.redirectToClient(w, r, req, url.Values{"error": {code}, "error_description": {desc}})
		return
	}
	renderErr(w, http.StatusBadRequest, desc)
}

// user returns the co-owner logged in by the reverse proxy, or "".
func (o oauthServer) user(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.Header.Get(o.userHeader)))
}

var oauthTmpl = template.Must(template.New("oauth").Parse(oauthHTML))

// handleAuthorize shows the consent page.
func (o oauthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req, redirect, code, desc := o.parseAuthorize(r.Context(), q)
	if code != "" {
		o.authorizeError(w, r, req, redirect, code, desc)
		return
	}
	email := o.user(r)
	if email == "" {
		logutil.Errorf("oauth: no %s header on /oauth/authorize; is it behind the reverse proxy's login?", o.userHeader)
		renderErr(w, http.StatusUnauthorized, "Connecte-toi d'abord sur le site, puis recommence.")
		return
	}

	name := cmp.Or(req.Client.Name, "Une application sans nom")
	dest := req.RedirectURI
	if ru, err := url.Parse(req.RedirectURI); err == nil && ru.Host != "" {
		dest = ru.Host
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	err := oauthTmpl.Execute(w, map[string]any{
		"Email":  email,
		"Client": name,
		"Dest":   dest,
		"Action": o.basePath + "/oauth/authorize",
		"Params": q,
	})
	if err != nil {
		logutil.Errorf("executing the oauth template: %v", err)
	}
}

// handleApprove issues the authorization code once the co-owner clicked
// "Autoriser".
func (o oauthServer) handleApprove(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		renderErr(w, http.StatusBadRequest, "Formulaire invalide.")
		return
	}
	req, redirect, code, desc := o.parseAuthorize(r.Context(), r.PostForm)
	if code != "" {
		o.authorizeError(w, r, req, redirect, code, desc)
		return
	}
	email := o.user(r)
	if email == "" {
		renderErr(w, http.StatusUnauthorized, "Connecte-toi d'abord sur le site, puis recommence.")
		return
	}
	if r.PostForm.Get("action") != "allow" {
		o.redirectToClient(w, r, req, url.Values{"error": {"access_denied"}})
		return
	}

	authCode := randomToken()
	err := db.CreateOAuthToken(r.Context(), o.sqlDB, db.OAuthCode, hashToken(authCode), db.OAuthGrant{
		ClientID:      req.Client.ID,
		Email:         email,
		RedirectURI:   req.RedirectURI,
		CodeChallenge: req.Challenge,
		Resource:      o.resource(),
		ExpiresAt:     time.Now().Add(oauthCodeTTL),
	})
	if err != nil {
		logutil.Errorf("%v", err)
		o.authorizeError(w, r, req, true, "server_error", "could not save the authorization code")
		return
	}
	logutil.Infof("oauth: %s approved the client %q", email, req.Client.Name)
	o.redirectToClient(w, r, req, url.Values{"code": {authCode}})
}

// -----------------------------------------------------------------------------
// Token endpoint.
// -----------------------------------------------------------------------------

func (o oauthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	oauthCORS(w)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	f := r.PostForm

	// Client authentication: HTTP Basic (form-urlencoded parts, RFC 6749
	// §2.3.1), or client_id and client_secret in the body.
	clientID, secret := f.Get("client_id"), f.Get("client_secret")
	if id, sec, ok := r.BasicAuth(); ok {
		clientID, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(sec)
	}
	client, err := db.GetOAuthClient(r.Context(), o.sqlDB, clientID)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	if client.SecretHash != "" && subtle.ConstantTimeCompare([]byte(hashToken(secret)), []byte(client.SecretHash)) != 1 {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "bad client secret")
		return
	}

	var g db.OAuthGrant
	switch f.Get("grant_type") {
	case "authorization_code":
		g, err = db.ConsumeOAuthToken(r.Context(), o.sqlDB, db.OAuthCode, hashToken(f.Get("code")))
		if err != nil || g.ClientID != client.ID {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or already used code")
			return
		}
		if ru := f.Get("redirect_uri"); ru != "" && ru != g.RedirectURI {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match")
			return
		}
		verifier := f.Get("code_verifier")
		sum := sha256.Sum256([]byte(verifier))
		if len(verifier) < 43 || len(verifier) > 128 ||
			subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(g.CodeChallenge)) != 1 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	case "refresh_token":
		// Rotation: the refresh token is consumed and a new one is issued.
		g, err = db.ConsumeOAuthToken(r.Context(), o.sqlDB, db.OAuthRefresh, hashToken(f.Get("refresh_token")))
		if err != nil || g.ClientID != client.ID {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or already used refresh token")
			return
		}
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
		return
	}
	if res := strings.TrimRight(f.Get("resource"), "/"); res != "" && res != g.Resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "the only resource here is "+g.Resource)
		return
	}

	access, refresh := randomToken(), randomToken()
	now := time.Now()
	grant := db.OAuthGrant{ClientID: client.ID, Email: g.Email, Resource: g.Resource}
	grant.ExpiresAt = now.Add(oauthAccessTTL)
	err = db.CreateOAuthToken(r.Context(), o.sqlDB, db.OAuthAccess, hashToken(access), grant)
	if err == nil {
		grant.ExpiresAt = now.Add(oauthRefreshTTL)
		err = db.CreateOAuthToken(r.Context(), o.sqlDB, db.OAuthRefresh, hashToken(refresh), grant)
	}
	if err != nil {
		logutil.Errorf("%v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not save the tokens")
		return
	}
	if f.Get("grant_type") == "authorization_code" {
		logutil.Infof("oauth: tokens issued to %q for %s", client.Name, g.Email)
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(oauthAccessTTL.Seconds()),
		"refresh_token": refresh,
	})
}

// randomToken returns 256 random bits, URL-safe.
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // Never fails, see its doc.
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken is what the database keeps instead of a code, token or secret.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
