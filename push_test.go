package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pushService stands for Google's or Apple's: it keeps what it's sent, and
// answers 410 under /gone, as for a device that unsubscribed.
type pushService struct {
	mu   sync.Mutex
	reqs []pushReq
}

type pushReq struct {
	path string
	hdr  http.Header
	body []byte
}

func (ps *pushService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	ps.mu.Lock()
	ps.reqs = append(ps.reqs, pushReq{r.URL.Path, r.Header.Clone(), b})
	ps.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/gone") {
		w.WriteHeader(http.StatusGone)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (ps *pushService) to(path string) []pushReq {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	var out []pushReq
	for _, r := range ps.reqs {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

// device is a browser's side of a subscription: its keys, to decrypt.
type device struct {
	priv *ecdh.PrivateKey
	auth []byte
	abo  db.PushAbonnementDB
}

func newDevice(t *testing.T, endpoint, email string) *device {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	enc := base64.RawURLEncoding.EncodeToString
	return &device{priv: priv, auth: auth, abo: db.PushAbonnementDB{
		Endpoint: endpoint, Email: email, UA: "Mozilla/5.0 (iPhone)",
		P256dh: enc(priv.PublicKey().Bytes()), Auth: enc(auth),
	}}
}

// decrypt undoes RFC 8291's aes128gcm, as the browser does.
func (d *device) decrypt(t *testing.T, body []byte) pushEvent {
	t.Helper()
	require.True(t, len(body) > 21+65 && body[20] == 65, "not an aes128gcm header")
	salt, serverKey, record := body[:16], body[21:86], body[86:]
	pub, err := ecdh.P256().NewPublicKey(serverKey)
	require.NoError(t, err)
	secret, err := d.priv.ECDH(pub)
	require.NoError(t, err)
	info := append(append([]byte("WebPush: info\x00"), d.priv.PublicKey().Bytes()...), serverKey...)
	ikm, _ := hkdf.Key(sha256.New, secret, d.auth, string(info), 32)
	cek, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, record, nil)
	require.NoError(t, err, "decrypt")
	plain = bytes.TrimRight(plain, "\x00")
	require.True(t, len(plain) > 0 && plain[len(plain)-1] == 2, "no last-record delimiter")
	var ev pushEvent
	require.NoError(t, json.Unmarshal(plain[:len(plain)-1], &ev))
	return ev
}

// testPusher is a pusher on an empty database whose devices are at a fake
// push service.
func testPusher(t *testing.T) (*pusher, *sql.DB, *pushService, *httptest.Server) {
	t.Helper()
	sqlDB, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	ps := &pushService{}
	srv := httptest.NewTLSServer(ps)
	t.Cleanup(srv.Close)
	p, err := openPush(t.Context(), sqlDB, "https://copro.example")
	require.NoError(t, err)
	p.client = srv.Client()
	return p, sqlDB, ps, srv
}

func endpoints(t *testing.T, sqlDB *sql.DB, email string) []string {
	t.Helper()
	abos, err := db.ListPushAbonnements(t.Context(), sqlDB, email)
	require.NoError(t, err)
	out := []string{}
	for _, a := range abos {
		out = append(out, a.Endpoint)
	}
	return out
}

func TestPushNotify(t *testing.T) {
	p, sqlDB, ps, srv := testPusher(t)

	phone := newDevice(t, srv.URL+"/phone", "anne@example.com")
	laptop := newDevice(t, srv.URL+"/laptop", "bob@example.com")
	laptop.abo.Events = map[string]bool{pushFactures: false}
	gone := newDevice(t, srv.URL+"/gone/1", "bob@example.com")
	for _, d := range []*device{phone, laptop, gone} {
		require.Empty(t, p.subscribe(t.Context(), d.abo))
	}

	p.notify(t.Context(), pushEvent{Kind: pushFactures, Title: "Nouvelle facture", Body: "Ascenseur (120,00 €)", URL: "/#abc"})

	// The phone gets it, encrypted for it alone, with what the push services
	// ask for.
	got := ps.to("/phone")
	require.Len(t, got, 1)
	assert.Equal(t, pushEvent{Kind: pushFactures, Title: "Nouvelle facture", Body: "Ascenseur (120,00 €)", URL: "/#abc"}, phone.decrypt(t, got[0].body))
	assert.Equal(t, "aes128gcm", got[0].hdr.Get("Content-Encoding"))
	assert.Equal(t, "86400", got[0].hdr.Get("TTL"))
	assert.Contains(t, got[0].hdr.Get("Authorization"), "vapid t=")
	assert.Less(t, len(got[0].body), 4096, "the push services refuse more than 4 kB")

	// The laptop turned the invoices off; the device that is gone is forgotten.
	assert.Empty(t, ps.to("/laptop"))
	assert.Len(t, ps.to("/gone/1"), 1)
	assert.Equal(t, []string{srv.URL + "/phone", srv.URL + "/laptop"}, endpoints(t, sqlDB, ""))

	// A kind nobody turned off reaches both.
	p.notify(t.Context(), pushEvent{Kind: pushMissions, Title: "Nouvelle intervention"})
	assert.Len(t, ps.to("/phone"), 2)
	require.Len(t, ps.to("/laptop"), 1)
	assert.Equal(t, "Nouvelle intervention", laptop.decrypt(t, ps.to("/laptop")[0].body).Title)

	t.Run("a long text is cut rather than refused by the push service", func(t *testing.T) {
		p.notify(t.Context(), pushEvent{Kind: pushMissions, Title: "Longue", Body: strings.Repeat("é", 5000)})
		got := ps.to("/phone")
		require.Len(t, got, 3)
		assert.Less(t, len(got[2].body), 4096)
		body := phone.decrypt(t, got[2].body).Body
		assert.True(t, strings.HasSuffix(body, "é…"), "cut on a character")
		assert.LessOrEqual(t, len(body), pushMaxBody)
	})

	t.Run("with --allowed-users, somebody who left the list gets nothing more", func(t *testing.T) {
		p.allowed = map[string]bool{"bob@example.com": true}
		p.notify(t.Context(), pushEvent{Kind: pushMissions, Title: "Pour Bob"})
		assert.Equal(t, 3, len(ps.to("/phone")), "the phone of Anne got nothing new")
		assert.Equal(t, 3, len(ps.to("/laptop")))
	})

	t.Run("a nil pusher sends nothing", func(t *testing.T) {
		var none *pusher
		none.notify(t.Context(), pushEvent{Kind: pushMissions})
	})
}

func TestPushKeysAreKept(t *testing.T) {
	p, sqlDB, _, _ := testPusher(t)
	again, err := openPush(t.Context(), sqlDB, "")
	require.NoError(t, err)
	assert.Equal(t, p.vapid, again.vapid, "new keys would cut every subscription")
	assert.NotEmpty(t, p.vapid.Public)
}

func TestPushSubscribe(t *testing.T) {
	p, sqlDB, _, srv := testPusher(t)
	d := newDevice(t, srv.URL+"/phone", "anne@example.com")

	bad := d.abo
	bad.Endpoint = "http://push.example/x"
	assert.Equal(t, "Adresse d'abonnement invalide.", p.subscribe(t.Context(), bad))
	bad = d.abo
	bad.P256dh = "AAAA"
	assert.Equal(t, "Abonnement invalide.", p.subscribe(t.Context(), bad))
	bad = d.abo
	bad.Auth = "AAAA"
	assert.Equal(t, "Abonnement invalide.", p.subscribe(t.Context(), bad))
	assert.Empty(t, endpoints(t, sqlDB, ""))

	// The choices only keep the kinds that exist.
	d.abo.Events = map[string]bool{pushFactures: false, "n'importe quoi": true}
	require.Empty(t, p.subscribe(t.Context(), d.abo))
	abos, err := db.ListPushAbonnements(t.Context(), sqlDB, "anne@example.com")
	require.NoError(t, err)
	require.Len(t, abos, 1)
	assert.Equal(t, map[string]bool{pushFactures: false}, abos[0].Events)
	created := abos[0].CreatedAt

	// The page subscribing again (each visit of an old page) keeps the
	// choices and the date.
	d.abo.Events = nil
	require.Empty(t, p.subscribe(t.Context(), d.abo))
	abos, err = db.ListPushAbonnements(t.Context(), sqlDB, "")
	require.NoError(t, err)
	require.Len(t, abos, 1)
	assert.Equal(t, map[string]bool{pushFactures: false}, abos[0].Events)
	assert.True(t, created.Equal(abos[0].CreatedAt))

	// One person can't fill the table.
	for i := 1; i < pushMaxParEmail; i++ {
		require.Empty(t, p.subscribe(t.Context(), newDevice(t, fmt.Sprintf("%s/d%d", srv.URL, i), "anne@example.com").abo))
	}
	assert.Equal(t, "Trop d'appareils abonnés : retirez-en un d'abord.", p.subscribe(t.Context(), newDevice(t, srv.URL+"/trop", "anne@example.com").abo))
	assert.Empty(t, p.subscribe(t.Context(), newDevice(t, srv.URL+"/bob", "bob@example.com").abo))
}

func TestAnnonces(t *testing.T) {
	mission := func(id, label string) db.MissionDB { return db.MissionDB{ID: id, Label: label} }
	facture := func(hash, invoice, label string, cents int) db.ExpenseDocumentDB {
		return db.ExpenseDocumentDB{HashFile: db.HashFile(hash), InvoiceID: invoice, Label: label, Amount: db.Amount(cents)}
	}

	assert.Empty(t, annonces("", nil, nil))

	// One of each: what it is, and a click opens its row.
	assert.Equal(t, []pushEvent{
		{Kind: pushMissions, Title: "Nouvelle intervention", Body: "Fuite au garage", URL: "/copro/#m1"},
		{Kind: pushFactures, Title: "Nouvelle facture", Body: "Ascenseur (120,50 €)", URL: "/copro/#h1"},
	}, annonces("/copro", []db.MissionDB{mission("m1", "Fuite au garage")}, []db.ExpenseDocumentDB{facture("h1", "i1", "Ascenseur", 12050)}))

	// The row of an invoice without a PDF is named after the invoice.
	assert.Equal(t, "/#i2", annonces("", nil, []db.ExpenseDocumentDB{facture("", "i2", "Eau", 100)})[0].URL)

	// Several: one notification, which opens the list.
	evs := annonces("", []db.MissionDB{mission("m1", "Fuite"), mission("m2", "Porte")}, []db.ExpenseDocumentDB{
		facture("h1", "", "A", 100), facture("h2", "", "B", 200), facture("h3", "", "C", 300), facture("h4", "", "D", 400), facture("h5", "", "E", 500),
	})
	assert.Equal(t, []pushEvent{
		{Kind: pushMissions, Title: "2 nouvelles interventions", Body: "Fuite\nPorte", URL: "/?filter=missions"},
		{Kind: pushFactures, Title: "5 nouvelles factures", Body: "A (1,00 €)\nB (2,00 €)\nC (3,00 €)\net 2 autres", URL: "/?filter=expenses"},
	}, evs)
}

func TestTronquer(t *testing.T) {
	assert.Equal(t, "court", tronquer("court", 10))
	assert.Equal(t, "éé…", tronquer("éééééé", 8), "never in the middle of a character")
	assert.Equal(t, "un…", tronquer("un deux trois", 6), "no space before the ellipsis")
}

// pushServer serves every route of the site that needs no Foncia account, as
// ServeHTTP mounts them, on an empty database: two routes that clash would
// panic here.
func pushServer(t *testing.T) (*httptest.Server, *sql.DB, *pushService, *httptest.Server) {
	t.Helper()
	p, sqlDB, ps, pushSrv := testPusher(t)
	mux := newTestMux(t, sqlDB)
	c := copro{sqlDB: sqlDB, push: p}
	addCoownersHandlers(mux, c)
	addPushHandlers(mux, c)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, sqlDB, ps, pushSrv
}

// pushCall posts JSON as the given user and returns the status and the answer.
func pushCall(t *testing.T, user, url string, body any) (int, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(*authHeader, user)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	}
	return resp.StatusCode, out
}

func pushInfoOf(t *testing.T, user, url string) (key string, kinds []pushKind, devices []pushDevice) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url+"/api/push", nil)
	require.NoError(t, err)
	req.Header.Set(*authHeader, user)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var info struct {
		Key     string
		Kinds   []pushKind
		Devices []pushDevice
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&info))
	return info.Key, info.Kinds, info.Devices
}

func subscription(d *device) map[string]any {
	return map[string]any{"endpoint": d.abo.Endpoint, "keys": map[string]string{"p256dh": d.abo.P256dh, "auth": d.abo.Auth}}
}

func TestPushHTTP(t *testing.T) {
	srv, sqlDB, ps, pushSrv := pushServer(t)
	client := http.DefaultClient

	t.Run("the page and what it loads", func(t *testing.T) {
		status, body := get(t, client, srv.URL+"/notifications")
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, `<script src="/push.js"></script>`)
		assert.Contains(t, body, `<link rel="manifest" href="/manifest.webmanifest">`)
		assert.Contains(t, body, `href="/notifications" class="actif"`)

		for path, contentType := range map[string]string{
			"/sw.js":                "text/javascript; charset=utf-8",
			"/push.js":              "text/javascript; charset=utf-8",
			"/manifest.webmanifest": "application/manifest+json",
		} {
			resp, err := client.Get(srv.URL + path)
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode, path)
			assert.Equal(t, contentType, resp.Header.Get("Content-Type"), path)
		}

		// Every page with the navigation bar links to it and to the manifest.
		status, body = get(t, client, srv.URL+"/")
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, `href="/notifications"`)
		assert.Contains(t, body, `<link rel="manifest" href="/manifest.webmanifest">`)
		assert.NotContains(t, body, "ntfy", "the page of the invoices no longer sends people to Ntfy")
	})

	phone := newDevice(t, pushSrv.URL+"/phone", "anne@example.com")

	t.Run("a device turns the notifications on, picks the kinds, tests and leaves", func(t *testing.T) {
		key, kinds, devices := pushInfoOf(t, "Anne@Example.com", srv.URL)
		assert.NotEmpty(t, key)
		assert.Equal(t, pushKinds, kinds)
		assert.Empty(t, devices)

		status, out := pushCall(t, "Anne@Example.com", srv.URL+"/api/push/subscribe", map[string]any{"subscription": subscription(phone)})
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, map[string]any{"ok": true, "message": "Notifications activées sur cet appareil."}, out)

		_, out = pushCall(t, "anne@example.com", srv.URL+"/api/push/subscribe", map[string]any{"subscription": subscription(phone), "events": map[string]bool{pushMissions: false}})
		assert.Equal(t, map[string]any{"ok": true, "message": "Choix enregistré."}, out)

		_, _, devices = pushInfoOf(t, "anne@example.com", srv.URL)
		require.Len(t, devices, 1)
		assert.Equal(t, phone.abo.Endpoint, devices[0].Endpoint)
		assert.Equal(t, map[string]bool{pushMissions: false}, devices[0].Events)
		assert.Equal(t, "Go-http-client/1.1", devices[0].UA)

		// The test reaches the device even with a kind turned off.
		_, out = pushCall(t, "anne@example.com", srv.URL+"/api/push/test", map[string]any{})
		assert.Equal(t, map[string]any{"ok": true, "message": "Test envoyé à 1 appareil(s)."}, out)
		got := ps.to("/phone")
		require.Len(t, got, 1)
		assert.Equal(t, "/notifications", phone.decrypt(t, got[0].body).URL)
	})

	t.Run("each person only sees and removes their own devices", func(t *testing.T) {
		_, _, devices := pushInfoOf(t, "bob@example.com", srv.URL)
		assert.Empty(t, devices)
		_, out := pushCall(t, "bob@example.com", srv.URL+"/api/push/test", map[string]any{})
		assert.Equal(t, map[string]any{"ok": false, "message": "Aucun appareil abonné."}, out)
		_, out = pushCall(t, "bob@example.com", srv.URL+"/api/push/unsubscribe", map[string]any{"endpoint": phone.abo.Endpoint})
		assert.Equal(t, map[string]any{"ok": false, "message": "Appareil inconnu."}, out)
		assert.Len(t, endpoints(t, sqlDB, ""), 1)

		_, out = pushCall(t, "anne@example.com", srv.URL+"/api/push/unsubscribe", map[string]any{"endpoint": phone.abo.Endpoint})
		assert.Equal(t, map[string]any{"ok": true, "message": "Notifications désactivées."}, out)
		assert.Empty(t, endpoints(t, sqlDB, ""))
	})

	t.Run("a form of another site can't subscribe a device", func(t *testing.T) {
		b, _ := json.Marshal(map[string]any{"subscription": subscription(phone)})
		for _, path := range []string{"/api/push/subscribe", "/api/push/unsubscribe", "/api/push/test"} {
			resp, err := client.Post(srv.URL+path, "text/plain", bytes.NewReader(b))
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode, path)
		}
		assert.Empty(t, endpoints(t, sqlDB, ""))
	})
}

func TestPushPageWithoutPusher(t *testing.T) {
	sqlDB, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	mux := http.NewServeMux()
	addPushHandlers(mux, copro{sqlDB: sqlDB, basePath: "/copro"})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	status, body := get(t, http.DefaultClient, srv.URL+"/notifications")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "ne sont pas disponibles")
	assert.NotContains(t, body, "push.js")
	status, _ = get(t, http.DefaultClient, srv.URL+"/api/push")
	assert.Equal(t, http.StatusNotFound, status)

	// The manifest follows the base path.
	status, body = get(t, http.DefaultClient, srv.URL+"/manifest.webmanifest")
	require.Equal(t, http.StatusOK, status)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &m))
	assert.Equal(t, "/copro/", m["scope"])
	assert.Equal(t, "/copro/", m["start_url"])
	assert.Equal(t, "standalone", m["display"])
}
