package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAudience = "https://suivi.example.com"

// issuer is a test double of the house's issuer: a key, its JWKS file, and
// tokens signed with it.
type issuer struct {
	key  *ecdsa.PrivateKey
	jwks string
}

func newIssuer(t *testing.T) issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := key.PublicKey.Bytes() // 0x04 || X || Y
	require.NoError(t, err)
	set := map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(pub[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(pub[33:]),
	}}}
	b, err := json.Marshal(set)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "jwks.json")
	require.NoError(t, os.WriteFile(path, b, 0o600))
	return issuer{key: key, jwks: path}
}

func (i issuer) token(t *testing.T, sub, aud string, exp time.Time) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1", "typ": "JWT"})
	c, _ := json.Marshal(map[string]any{"iss": "https://vls.dev", "sub": sub, "aud": aud,
		"iat": time.Now().Unix(), "nbf": time.Now().Unix(), "exp": exp.Unix()})
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, sum[:])
	require.NoError(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// apiServer serves /api/v1 as ServeHTTP mounts it, for docker:residence.
func apiServer(t *testing.T) (*httptest.Server, *sql.DB, issuer) {
	t.Helper()
	sqlDB := openTestDB(t)
	iss := newIssuer(t)
	a := apiV1{sqlDB: sqlDB, client: http.DefaultClient, poll: 10 * time.Millisecond,
		lastSync: func() (time.Time, error) { return time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC), nil }}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", calledBy(newWorkloads(iss.jwks, "https://vls.dev", testAudience), []string{"docker:residence"}, a.routes()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, sqlDB, iss
}

func apiGet(t *testing.T, url, token string, header ...string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func TestAPIAccess(t *testing.T) {
	srv, _, iss := apiServer(t)
	url := srv.URL + "/api/v1/etat"
	later := time.Now().Add(time.Hour)

	status, body := apiGet(t, url, iss.token(t, "docker:residence", testAudience, later))
	assert.Equal(t, http.StatusOK, status, string(body))
	assert.Contains(t, string(body), `"derniere_synchro":"2026-11-27T10:00:00Z"`)

	for name, tc := range map[string]struct {
		token  string
		header []string
		want   int
	}{
		"no token":                 {"", nil, http.StatusUnauthorized},
		"not a JWT":                {"abc", nil, http.StatusUnauthorized},
		"a token for another site": {iss.token(t, "docker:residence", "https://whatsapp.vls.dev", later), nil, http.StatusUnauthorized},
		"an expired token":         {iss.token(t, "docker:residence", testAudience, time.Now().Add(-time.Minute)), nil, http.StatusUnauthorized},
		"a service that may not":   {iss.token(t, "docker:aspi", testAudience, later), nil, http.StatusForbidden},
		"through the proxy, even with a good token": {iss.token(t, "docker:residence", testAudience, later), []string{"X-Forwarded-For", "1.2.3.4"}, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			status, _ := apiGet(t, url, tc.token, tc.header...)
			assert.Equal(t, tc.want, status)
		})
	}

	t.Run("signed by another key", func(t *testing.T) {
		other := newIssuer(t)
		status, _ := apiGet(t, url, other.token(t, "docker:residence", testAudience, later))
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

func changementsOf(t *testing.T, srv *httptest.Server, token, query string) apiChangements {
	t.Helper()
	status, body := apiGet(t, srv.URL+"/api/v1/changements"+query, token)
	require.Equal(t, http.StatusOK, status, string(body))
	var out apiChangements
	require.NoError(t, json.Unmarshal(body, &out))
	return out
}

func TestAPIChangements(t *testing.T) {
	ctx := t.Context()
	srv, sqlDB, iss := apiServer(t)
	token := iss.token(t, "docker:residence", testAudience, time.Now().Add(time.Hour))

	pdf := filepath.Join(t.TempDir(), "facture.pdf")
	require.NoError(t, os.WriteFile(pdf, []byte("%PDF-1.4 la facture"), 0o600))
	require.NoError(t, db.SaveMissionsToDB(ctx, sqlDB, db.MissionDB{ID: "m1", Label: "Fuite", StartedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}))
	require.NoError(t, db.UpsertExpensesWithDB(ctx, sqlDB, db.ExpenseDocumentDB{
		Label: "ACME", Amount: 100, Date: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
		HashFile: "h1", FilePath: pdf, Source: db.SourceAccounting,
	}))

	t.Run("from 0, everything, then nothing more", func(t *testing.T) {
		out := changementsOf(t, srv, token, "")
		require.Len(t, out.Changements, 2)
		assert.Equal(t, "mission", out.Changements[0].Kind)
		assert.Equal(t, "expense", out.Changements[1].Kind)
		assert.Equal(t, "/api/v1/fichiers/invoice/h1", out.Changements[1].Fichier)
		assert.Empty(t, out.Changements[0].Fichier)
		assert.Equal(t, out.Fin, out.Curseur)

		again := changementsOf(t, srv, token, "?depuis="+itoa(out.Curseur))
		assert.Empty(t, again.Changements)
		assert.Equal(t, out.Curseur, again.Curseur, "the cursor stays where it was")
	})

	t.Run("page by page", func(t *testing.T) {
		first := changementsOf(t, srv, token, "?limite=1")
		require.Len(t, first.Changements, 1)
		assert.Less(t, first.Curseur, first.Fin, "more to read")
		second := changementsOf(t, srv, token, "?limite=1&depuis="+itoa(first.Curseur))
		require.Len(t, second.Changements, 1)
		assert.Equal(t, "expense", second.Changements[0].Kind)
	})

	t.Run("the long poll answers as soon as something comes", func(t *testing.T) {
		fin := changementsOf(t, srv, token, "?depuis=fin")
		assert.Empty(t, fin.Changements)

		go func() {
			time.Sleep(100 * time.Millisecond)
			_ = db.SaveMissionsToDB(ctx, sqlDB, db.MissionDB{ID: "m2", Label: "Ascenseur", StartedAt: time.Now()})
		}()
		start := time.Now()
		out := changementsOf(t, srv, token, "?attendre=10&depuis="+itoa(fin.Curseur))
		assert.Less(t, time.Since(start), 5*time.Second)
		require.Len(t, out.Changements, 1)
		assert.Equal(t, "m2", out.Changements[0].Ref)
		assert.Equal(t, "nouveau", out.Changements[0].Action)
	})

	t.Run("and gives up empty-handed after attendre", func(t *testing.T) {
		out := changementsOf(t, srv, token, "?attendre=1&depuis=fin")
		assert.Empty(t, out.Changements)
	})

	t.Run("bad parameters", func(t *testing.T) {
		for _, q := range []string{"?depuis=-1", "?depuis=hier", "?limite=0", "?attendre=x"} {
			status, _ := apiGet(t, srv.URL+"/api/v1/changements"+q, token)
			assert.Equal(t, http.StatusBadRequest, status, q)
		}
	})

	t.Run("the PDF", func(t *testing.T) {
		status, body := apiGet(t, srv.URL+"/api/v1/fichiers/invoice/h1", token)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "%PDF-1.4 la facture", string(body))

		status, _ = apiGet(t, srv.URL+"/api/v1/fichiers/invoice/nope", token)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = apiGet(t, srv.URL+"/api/v1/fichiers/autre/h1", token)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = apiGet(t, srv.URL+"/api/v1/fichiers/invoice/h1", "")
		assert.Equal(t, http.StatusUnauthorized, status, "the files want a token too")
	})
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
