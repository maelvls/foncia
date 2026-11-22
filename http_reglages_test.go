package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	autreAdmin = "autre-admin@example.com"
	clientID   = "123-abc.apps.googleusercontent.com"
)

// fauxGoogle is Google's token endpoint and the Gmail API. The code
// "code-<nom>" gives the refresh token "rt-<nom>", whose access token
// "at-<nom>" reads the mailbox of <nom>@example.com.
type fauxGoogle struct {
	*httptest.Server
	mu       sync.Mutex
	echanges []url.Values // The authorization codes that were exchanged.
	listes   int          // How many times the messages were listed.
}

func nouveauFauxGoogle(t *testing.T) *fauxGoogle {
	t.Helper()
	g := &fauxGoogle{}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			require.NoError(t, r.ParseForm())
			nom := ""
			switch r.PostForm.Get("grant_type") {
			case "authorization_code":
				g.echanges = append(g.echanges, r.PostForm)
				nom = strings.TrimPrefix(r.PostForm.Get("code"), "code-")
			case "refresh_token":
				nom = strings.TrimPrefix(r.PostForm.Get("refresh_token"), "rt-")
			}
			if nom == "" || nom == "refuse" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + nom, "refresh_token": "rt-" + nom, "token_type": "Bearer", "expires_in": 3600})
		case "/gmail/profile":
			nom := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer at-")
			_ = json.NewEncoder(w).Encode(map[string]string{"emailAddress": nom + "@example.com"})
		case "/gmail/messages":
			g.listes++
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

// reglagesServer serves the site with the e-mail collection turned on for
// the mailbox of admin, and a Google client already set.
func reglagesServer(t *testing.T) (srv *httptest.Server, sqlDB *sql.DB, client *http.Client, google *fauxGoogle, fichier string) {
	t.Helper()
	google = nouveauFauxGoogle(t)
	fichier = filepath.Join(t.TempDir(), "gmail-token.json")
	require.NoError(t, ecrireGmailToken(fichier, gmailToken{ClientID: clientID, ClientSecret: "secret", AuthURI: google.URL + "/auth", TokenURI: google.URL + "/token"}))

	oldFile, oldAccount, oldQuery, oldAPI := *gmailTokenFile, *gmailAccount, *gmailQuery, *gmailAPIFlag
	*gmailTokenFile, *gmailAccount, *gmailQuery, *gmailAPIFlag = fichier, admin, "from:foncia.com", google.URL+"/gmail"
	t.Cleanup(func() {
		*gmailTokenFile, *gmailAccount, *gmailQuery, *gmailAPIFlag = oldFile, oldAccount, oldQuery, oldAPI
	})

	srv, sqlDB, client, _ = sourcesServer(t)
	*adminUsers = admin + ", " + autreAdmin // sourcesServer puts the old value back.
	return srv, sqlDB, client, google, fichier
}

// ouvrirGoogle starts a login and returns where the browser is sent.
func ouvrirGoogle(t *testing.T, client *http.Client, srv *httptest.Server) url.Values {
	t.Helper()
	code, loc := post(t, client, admin, srv.URL+"/reglages/gmail/connecter", nil)
	require.Equal(t, http.StatusSeeOther, code)
	u, err := url.Parse(loc)
	require.NoError(t, err)
	return u.Query()
}

// coller pastes the address of the localhost page Google would have sent
// the browser to, and returns where the site goes next.
func coller(t *testing.T, client *http.Client, srv *httptest.Server, state, code string) url.Values {
	t.Helper()
	colle := gmailRedirect + "?" + url.Values{"state": {state}, "code": {code}, "scope": {gmailScope}}.Encode()
	status, loc := post(t, client, admin, srv.URL+"/reglages/gmail/code", url.Values{"url": {colle}})
	require.Equal(t, http.StatusSeeOther, status)
	u, err := url.Parse(loc)
	require.NoError(t, err)
	assert.Equal(t, "/reglages", u.Path)
	return u.Query()
}

func TestReglagesGmail(t *testing.T) {
	srv, sqlDB, client, google, fichier := reglagesServer(t)

	t.Run("the page is for the administrators, the buttons for the account of the mailbox", func(t *testing.T) {
		code, _ := getAs(t, client, membre, srv.URL+"/reglages")
		assert.Equal(t, http.StatusForbidden, code)

		code, body := getAs(t, client, autreAdmin, srv.URL+"/reglages")
		require.Equal(t, http.StatusOK, code)
		assert.Contains(t, body, "Pas reliée")
		assert.Contains(t, body, "from:foncia.com")
		assert.Contains(t, body, "ouvre le site avec "+admin)
		assert.NotContains(t, body, "/reglages/gmail/connecter")
		assert.NotContains(t, body, "secret", "the secret of the client is never written in the page")

		code, body = getAs(t, client, admin, srv.URL+"/reglages")
		require.Equal(t, http.StatusOK, code)
		assert.Contains(t, body, "/reglages/gmail/connecter")
		assert.Contains(t, body, clientID)

		for _, chemin := range []string{"client", "connecter", "code", "deconnecter"} {
			code, _ := post(t, client, autreAdmin, srv.URL+"/reglages/gmail/"+chemin, url.Values{"url": {gmailRedirect + "?state=s&code=code-mael"}})
			assert.Equal(t, http.StatusForbidden, code, chemin)
			code, _ = post(t, client, membre, srv.URL+"/reglages/gmail/"+chemin, nil)
			assert.Equal(t, http.StatusForbidden, code, chemin)
		}
	})

	t.Run("a form on another site can't change the connection", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/reglages/gmail/deconnecter", nil)
		require.NoError(t, err)
		req.Header.Set(*authHeader, admin)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("Google is asked for the right account, to read only", func(t *testing.T) {
		q := ouvrirGoogle(t, client, srv)
		assert.Equal(t, clientID, q.Get("client_id"))
		assert.Equal(t, gmailScope, q.Get("scope"))
		assert.Equal(t, gmailRedirect, q.Get("redirect_uri"))
		assert.Equal(t, admin, q.Get("login_hint"))
		assert.Equal(t, "offline", q.Get("access_type"))
		assert.Equal(t, "consent", q.Get("prompt"))
		assert.Equal(t, "S256", q.Get("code_challenge_method"))
		assert.NotEmpty(t, q.Get("state"))
	})

	t.Run("another mailbox is refused and nothing is kept", func(t *testing.T) {
		q := ouvrirGoogle(t, client, srv)
		retour := coller(t, client, srv, q.Get("state"), "code-intrus")
		assert.Contains(t, retour.Get("erreur"), "intrus@example.com")
		assert.Contains(t, retour.Get("erreur"), "rien n'a été enregistré")

		tok, err := lireGmailToken(fichier)
		require.NoError(t, err)
		assert.False(t, tok.relie())
		assert.Empty(t, tok.RefreshToken)

		_, body := getAs(t, client, admin, srv.URL+"/reglages?"+retour.Encode())
		assert.Contains(t, body, "Pas reliée")
		assert.Contains(t, body, "intrus@example.com")
	})

	t.Run("what is pasted must be the address Google gave for a login started here", func(t *testing.T) {
		for nom, colle := range map[string]string{
			"not an address":      "bonjour",
			"no code":             gmailRedirect + "?state=abc",
			"refused at Google":   gmailRedirect + "?state=abc&error=access_denied",
			"a state never given": gmailRedirect + "?state=abc&code=code-mael",
		} {
			status, loc := post(t, client, admin, srv.URL+"/reglages/gmail/code", url.Values{"url": {colle}})
			assert.Equal(t, http.StatusSeeOther, status, nom)
			assert.Contains(t, loc, "erreur=", nom)
		}
		tok, err := lireGmailToken(fichier)
		require.NoError(t, err)
		assert.False(t, tok.relie())
	})

	t.Run("the mailbox of the account is connected", func(t *testing.T) {
		q := ouvrirGoogle(t, client, srv)
		retour := coller(t, client, srv, q.Get("state"), "code-mael")
		assert.Empty(t, retour.Get("erreur"))
		assert.Contains(t, retour.Get("flash"), "La boîte de "+admin+" est reliée")

		// The code went to Google with the proof that the same browser
		// session asked for it (PKCE).
		dernier := google.echanges[len(google.echanges)-1]
		assert.Equal(t, gmailRedirect, dernier.Get("redirect_uri"))
		somme := sha256.Sum256([]byte(dernier.Get("code_verifier")))
		assert.Equal(t, q.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(somme[:]))

		tok, err := lireGmailToken(fichier)
		require.NoError(t, err)
		assert.Equal(t, "rt-mael", tok.RefreshToken)
		assert.Equal(t, admin, tok.Account)
		assert.Equal(t, admin, tok.ConnectedBy)
		assert.False(t, tok.ConnectedAt.IsZero())
		assert.Equal(t, clientID, tok.ClientID, "the client stays")
		st, err := os.Stat(fichier)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())

		_, body := getAs(t, client, admin, srv.URL+"/reglages")
		assert.Contains(t, body, `<span class="badge levee">Reliée</span>`)
		assert.Contains(t, body, "Pas encore de passage")
		assert.NotContains(t, body, "rt-mael", "the token is never written in the page")

		t.Run("a code only works once", func(t *testing.T) {
			retour := coller(t, client, srv, q.Get("state"), "code-mael")
			assert.Contains(t, retour.Get("erreur"), "expiré")
		})
	})

	t.Run("the collector reads the mailbox once connected, and says how it went", func(t *testing.T) {
		g, err := newGmailCollecteur(sqlDB)
		require.NoError(t, err)
		n, err := g.collecter(t.Context())
		require.NoError(t, err)
		assert.Zero(t, n)
		assert.Equal(t, 1, google.listes)

		_, body := getAs(t, client, admin, srv.URL+"/reglages")
		assert.Contains(t, body, "0 nouveau(x) e-mail(s)")

		t.Run("and stops as soon as it is disconnected", func(t *testing.T) {
			code, loc := post(t, client, admin, srv.URL+"/reglages/gmail/deconnecter", nil)
			require.Equal(t, http.StatusSeeOther, code)
			assert.Contains(t, loc, "flash=")

			tok, err := lireGmailToken(fichier)
			require.NoError(t, err)
			assert.Empty(t, tok.RefreshToken)
			assert.Empty(t, tok.Account)
			assert.Equal(t, clientID, tok.ClientID, "the client stays, to connect again")

			_, err = g.collecter(t.Context())
			assert.ErrorIs(t, err, errGmailPasRelie)
			assert.Equal(t, 1, google.listes, "nothing more was read")

			_, body := getAs(t, client, admin, srv.URL+"/reglages")
			assert.Contains(t, body, "Pas reliée")
		})
	})

	t.Run("another client forgets the mailbox", func(t *testing.T) {
		q := ouvrirGoogle(t, client, srv)
		coller(t, client, srv, q.Get("state"), "code-mael")

		code, loc := post(t, client, admin, srv.URL+"/reglages/gmail/client", url.Values{"client_id": {clientID}})
		require.Equal(t, http.StatusSeeOther, code)
		assert.Contains(t, loc, "pas+chang")
		tok, err := lireGmailToken(fichier)
		require.NoError(t, err)
		assert.True(t, tok.relie(), "the same client, its secret left empty: nothing changes")

		code, loc = post(t, client, admin, srv.URL+"/reglages/gmail/client", url.Values{"client_id": {"autre"}, "client_secret": {"s"}})
		require.Equal(t, http.StatusSeeOther, code)
		assert.Contains(t, loc, "erreur=")

		code, _ = post(t, client, admin, srv.URL+"/reglages/gmail/client", url.Values{"client_id": {"456.apps.googleusercontent.com"}, "client_secret": {"s2"}})
		require.Equal(t, http.StatusSeeOther, code)
		tok, err = lireGmailToken(fichier)
		require.NoError(t, err)
		assert.Equal(t, "456.apps.googleusercontent.com", tok.ClientID)
		assert.Equal(t, "s2", tok.ClientSecret)
		assert.False(t, tok.relie())
		assert.Equal(t, google.URL+"/token", tok.TokenURI)
	})
}

// A token file made by hand for another mailbox isn't read either.
func TestGmailCollecteurAutreBoite(t *testing.T) {
	_, sqlDB, _, google, fichier := reglagesServer(t)
	require.NoError(t, ecrireGmailToken(fichier, gmailToken{ClientID: clientID, ClientSecret: "secret", RefreshToken: "rt-intrus", TokenURI: google.URL + "/token"}))

	g, err := newGmailCollecteur(sqlDB)
	require.NoError(t, err)
	_, err = g.collecter(t.Context())
	require.ErrorContains(t, err, "intrus@example.com")
	assert.Zero(t, google.listes, "not a single message was listed")

	c, err := lireGmailCollecte(t.Context(), sqlDB)
	require.NoError(t, err)
	assert.Contains(t, c.Erreur, "intrus@example.com")
	assert.True(t, c.Reussie.IsZero())

	t.Run("a token Google no longer wants asks to connect again", func(t *testing.T) {
		require.NoError(t, ecrireGmailToken(fichier, gmailToken{ClientID: clientID, ClientSecret: "secret", RefreshToken: "rt-refuse", TokenURI: google.URL + "/token"}))
		_, err := g.collecter(t.Context())
		require.Error(t, err)
		c, err := lireGmailCollecte(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.True(t, c.Refuse(), c.Erreur)
	})

	t.Run("the right mailbox is read after that, without a restart", func(t *testing.T) {
		require.NoError(t, ecrireGmailToken(fichier, gmailToken{ClientID: clientID, ClientSecret: "secret", RefreshToken: "rt-mael", TokenURI: google.URL + "/token"}))
		_, err := g.collecter(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, google.listes)
		c, err := lireGmailCollecte(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Empty(t, c.Erreur)
		assert.False(t, c.Reussie.IsZero())
	})

	t.Run("no token file yet is a mailbox that isn't connected", func(t *testing.T) {
		require.NoError(t, os.Remove(fichier))
		_, err := g.collecter(t.Context())
		assert.ErrorIs(t, err, errGmailPasRelie)
	})
}

func TestStatsSources(t *testing.T) {
	sqlDB := testDB(t)
	stats, err := db.StatsSources(t.Context(), sqlDB)
	require.NoError(t, err)
	assert.Empty(t, stats)

	hier := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	for i, canal := range []db.SourceCanal{db.CanalGmail, db.CanalGmail, db.CanalFoncia} {
		_, err := db.InsertSource(t.Context(), sqlDB, db.SourceDB{Canal: canal, ExtID: strconv.Itoa(i), Sujet: "s", Date: hier.Add(time.Duration(i) * time.Hour), Etat: db.SourceATrier})
		require.NoError(t, err)
	}
	stats, err = db.StatsSources(t.Context(), sqlDB)
	require.NoError(t, err)
	assert.Equal(t, 2, stats[db.CanalGmail].N)
	assert.True(t, stats[db.CanalGmail].Dernier.Equal(hier.Add(time.Hour)))
	assert.Equal(t, 1, stats[db.CanalFoncia].N)
	assert.Zero(t, stats[db.CanalWhatsApp].N)

	// The page shows them.
	srv, _, client, _, _ := reglagesServer(t)
	code, body := getAs(t, client, admin, srv.URL+"/reglages")
	require.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "Aucun e-mail collecté")
}
