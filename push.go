package main

import (
	"context"
	"crypto/ecdh"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// The notifications of the site (Web Push). Each person turns them on, one
// device at a time, on the page "Notifications" (on an iPhone, from the site
// installed on the home screen). Each message is encrypted for the device and
// posted to the device's push service (Apple's, Google's, Mozilla's), which
// wakes static/sw.js up and can't read it.

//go:embed static/sw.js static/push.js
var pushFS embed.FS

var pushContact = flag.String("push-contact", "", "E-mail or https URL given to the push services (Apple, Google, Mozilla) with each notification, for them to reach whoever runs this server (the VAPID subject). Empty means --baseurl, which Apple refuses unless it is an https URL.")

const (
	pushTimeout = 30 * time.Second
	pushTTL     = 24 * 3600 // s: a phone off for the night still gets them
	// A person's phones, tablets and computers; and all of them together.
	pushMaxParEmail = 10
	pushMaxTotal    = 300
	// The push services take 4 kB at most, encryption included.
	pushRecordSize = 3072
	pushMaxTitle   = 150
	pushMaxBody    = 1500
)

const (
	pushMissions = "missions"
	pushFactures = "factures"
	pushTest     = "test"
)

type pushKind struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// pushKinds are the kinds of news, which each device turns on or off.
var pushKinds = []pushKind{
	{pushMissions, "Nouvelles interventions (ordres de mission et de réparation)"},
	{pushFactures, "Nouvelles factures"},
}

// pushEvent is a notification, as sw.js gets it.
type pushEvent struct {
	Kind  string `json:"kind"`
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"url"` // What a click opens: a path of the site.
}

type vapidKeys struct {
	Public  string `json:"publicKey"`
	Private string `json:"privateKey"`
}

// pusher sends the notifications. The devices are in the push_abonnements
// table and the VAPID keys in the reglages table (push_vapid): new keys would
// cut every subscription.
type pusher struct {
	sqlDB   *sql.DB
	vapid   vapidKeys
	contact string
	// The e-mails that still get the news; nil when --allowed-users is
	// empty, since the reverse proxy is then the only one to know.
	allowed map[string]bool
	client  webpush.HTTPClient

	mu      sync.Mutex
	failing map[string]bool // Endpoints whose last send failed, logged once.
}

func openPush(ctx context.Context, sqlDB *sql.DB, contact string) (*pusher, error) {
	p := &pusher{sqlDB: sqlDB, contact: contact, client: &http.Client{Timeout: pushTimeout}, failing: map[string]bool{}}

	// Only the first process to ask keeps the keys it made.
	var k vapidKeys
	var err error
	if k.Private, k.Public, err = webpush.GenerateVAPIDKeys(); err != nil {
		return nil, fmt.Errorf("while making the VAPID keys: %w", err)
	}
	b, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	v, err := db.InitReglage(ctx, sqlDB, "push_vapid", string(b))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(v), &p.vapid); err != nil || p.vapid.Public == "" || p.vapid.Private == "" {
		return nil, fmt.Errorf("the VAPID keys in reglages (push_vapid) are invalid")
	}

	for _, u := range strings.Split(*allowedUsers, ",") {
		if u = strings.TrimSpace(strings.ToLower(u)); u != "" {
			if p.allowed == nil {
				p.allowed = map[string]bool{}
			}
			p.allowed[u] = true
		}
	}
	return p, nil
}

func wants(a db.PushAbonnementDB, kind string) bool {
	on, ok := a.Events[kind]
	return !ok || on
}

// notify sends ev to the devices that want its kind. Nothing is returned:
// what went wrong is logged, and a notification is never worth failing a sync.
func (p *pusher) notify(ctx context.Context, ev pushEvent) {
	if p == nil {
		return
	}
	all, err := db.ListPushAbonnements(ctx, p.sqlDB, "")
	if err != nil {
		logutil.Errorf("push: %v", err)
		return
	}
	var to []db.PushAbonnementDB
	for _, a := range all {
		if wants(a, ev.Kind) && (p.allowed == nil || p.allowed[a.Email]) {
			to = append(to, a)
		}
	}
	if len(to) == 0 {
		return
	}
	errs := p.send(ctx, ev, to)
	logutil.Infof("push: %s to %d of %d device(s): %s", ev.Kind, len(to)-len(errs), len(to), ev.Title)
}

// send delivers ev to each of to at once and returns the errors, one per
// device that didn't get it.
func (p *pusher) send(ctx context.Context, ev pushEvent, to []db.PushAbonnementDB) []error {
	ev.Title = tronquer(ev.Title, pushMaxTitle)
	ev.Body = tronquer(ev.Body, pushMaxBody)
	msg, _ := json.Marshal(ev)
	errs := make([]error, len(to))
	var wg sync.WaitGroup
	for i, a := range to {
		wg.Go(func() { errs[i] = p.deliver(ctx, msg, a) })
	}
	wg.Wait()
	return slices.DeleteFunc(errs, func(err error) bool { return err == nil })
}

func (p *pusher) deliver(ctx context.Context, msg []byte, a db.PushAbonnementDB) error {
	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	// A copy: webpush-go appends the padding to the message it gets.
	resp, err := webpush.SendNotificationWithContext(ctx, slices.Clone(msg), &webpush.Subscription{
		Endpoint: a.Endpoint,
		Keys:     webpush.Keys{P256dh: a.P256dh, Auth: a.Auth},
	}, &webpush.Options{
		HTTPClient:      p.client,
		Subscriber:      p.contact,
		VAPIDPublicKey:  p.vapid.Public,
		VAPIDPrivateKey: p.vapid.Private,
		TTL:             pushTTL,
		Urgency:         webpush.UrgencyNormal,
		// webpush-go pads to the whole record: 4 kB by default, right at
		// the push services' limit.
		RecordSize: pushRecordSize,
	})
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
			// The device unsubscribed, or its browser forgot it. Not with
			// ctx: a sync that is being cancelled must still forget it.
			logutil.Infof("push: %s's %s is gone (%d), removed", a.Email, pushHost(a.Endpoint), resp.StatusCode)
			if _, err := db.DeletePushAbonnement(context.WithoutCancel(ctx), p.sqlDB, a.Endpoint, ""); err != nil {
				logutil.Errorf("push: %v", err)
			}
			p.mu.Lock()
			delete(p.failing, a.Endpoint)
			p.mu.Unlock()
			return errors.New("abonnement expiré, retiré")
		case resp.StatusCode >= 300:
			err = fmt.Errorf("%s: %s %s", pushHost(a.Endpoint), resp.Status, strings.TrimSpace(string(body)))
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		delete(p.failing, a.Endpoint)
		return nil
	}
	if !p.failing[a.Endpoint] {
		p.failing[a.Endpoint] = true
		logutil.Errorf("push: to %s: %v", a.Email, err)
	}
	return err
}

func pushHost(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil {
		return u.Host
	}
	return "?"
}

// tronquer cuts s to max bytes at most, on a character, and says so with "…".
func tronquer(s string, max int) string {
	if len(s) <= max {
		return s
	}
	const fin = "…"
	s = s[:max-len(fin)]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return strings.TrimRight(s, " \n") + fin
}

// subscribe adds a device, or updates it. events nil keeps the device's
// choices. It returns what went wrong, in words for the person who asked, or
// "" when the device is in.
func (p *pusher) subscribe(ctx context.Context, a db.PushAbonnementDB) string {
	u, err := url.Parse(a.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(a.Endpoint) > 2048 {
		return "Adresse d'abonnement invalide."
	}
	// The browser's keys (base64url): a P-256 point and a 16-byte secret.
	pub, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(a.P256dh, "="))
	if err == nil {
		_, err = ecdh.P256().NewPublicKey(pub)
	}
	auth, err2 := base64.RawURLEncoding.DecodeString(strings.TrimRight(a.Auth, "="))
	if err != nil || err2 != nil || len(auth) != 16 {
		return "Abonnement invalide."
	}
	if len(a.UA) > 512 {
		a.UA = a.UA[:512]
	}
	if a.Events != nil {
		// Only the kinds that exist, so that the page can't fill the row.
		events := map[string]bool{}
		for _, k := range pushKinds {
			if on, ok := a.Events[k.ID]; ok {
				events[k.ID] = on
			}
		}
		a.Events = events
	}
	a.CreatedAt = time.Now()
	err = db.UpsertPushAbonnement(ctx, p.sqlDB, a, pushMaxParEmail, pushMaxTotal)
	if errors.Is(err, db.ErrTropDAbonnements) {
		return "Trop d'appareils abonnés : retirez-en un d'abord."
	}
	if err != nil {
		logutil.Errorf("push: %v", err)
		return "Erreur interne, voir les logs du serveur."
	}
	p.mu.Lock()
	delete(p.failing, a.Endpoint)
	p.mu.Unlock()
	return ""
}

// What a sync found, as notifications: one for the missions and one for the
// expenses, so that a sync that brings ten invoices doesn't make a phone buzz
// ten times.
func annonces(basePath string, missions []db.MissionDB, expenses []db.ExpenseDocumentDB) []pushEvent {
	var evs []pushEvent
	switch n := len(missions); {
	case n == 1:
		m := missions[0]
		evs = append(evs, pushEvent{Kind: pushMissions, Title: "Nouvelle intervention", Body: missionToNtfyBody(m), URL: basePath + "/#" + m.ID})
	case n > 1:
		lignes := make([]string, 0, n)
		for _, m := range missions {
			lignes = append(lignes, m.Label)
		}
		evs = append(evs, pushEvent{Kind: pushMissions, Title: fmt.Sprintf("%d nouvelles interventions", n), Body: resumer(lignes), URL: basePath + "/?filter=missions"})
	}
	switch n := len(expenses); {
	case n == 1:
		e := expenses[0]
		// The same anchor as the row of the page (templates/index.html).
		ancre := string(e.HashFile)
		if ancre == "" {
			ancre = e.InvoiceID
		}
		evs = append(evs, pushEvent{Kind: pushFactures, Title: "Nouvelle facture", Body: e.Label + " (" + e.Amount.String() + ")", URL: basePath + "/#" + ancre})
	case n > 1:
		lignes := make([]string, 0, n)
		for _, e := range expenses {
			lignes = append(lignes, e.Label+" ("+e.Amount.String()+")")
		}
		evs = append(evs, pushEvent{Kind: pushFactures, Title: fmt.Sprintf("%d nouvelles factures", n), Body: resumer(lignes), URL: basePath + "/?filter=expenses"})
	}
	return evs
}

// resumer lists the first lines, one per line, and counts the others.
func resumer(lignes []string) string {
	const max = 4
	if len(lignes) <= max {
		return strings.Join(lignes, "\n")
	}
	reste := len(lignes) - (max - 1)
	return strings.Join(lignes[:max-1], "\n") + fmt.Sprintf("\net %d autres", reste)
}

// The page's side: /notifications and static/push.js.

func addPushHandlers(mux *http.ServeMux, c copro) {
	mux.HandleFunc("GET /notifications", func(w http.ResponseWriter, r *http.Request) {
		c.render(w, "notifications", struct {
			page
			Disponible bool
		}{c.page(r, "notifications"), c.push != nil})
	})
	mux.HandleFunc("GET /sw.js", pushAsset("static/sw.js"))
	mux.HandleFunc("GET /push.js", pushAsset("static/push.js"))
	mux.HandleFunc("GET /manifest.webmanifest", c.manifest)
	if c.push == nil {
		return
	}
	mux.HandleFunc("GET /api/push", c.pushInfo)
	mux.HandleFunc("POST /api/push/subscribe", c.pushSubscribe)
	mux.HandleFunc("POST /api/push/unsubscribe", c.pushUnsubscribe)
	mux.HandleFunc("POST /api/push/test", c.pushTest)
}

// pushAsset serves an embedded script, revalidated each time. sw.js is served
// from the root of the site so that its scope is the whole site.
func pushAsset(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := pushFS.ReadFile(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	}
}

// manifest makes the site installable on the home screen, which an iPhone
// requires before it lets a site send notifications. The icons are not in
// this binary: the reverse proxy serves them at the root of the site.
func (c copro) manifest(w http.ResponseWriter, r *http.Request) {
	type icon struct {
		Src   string `json:"src"`
		Sizes string `json:"sizes"`
		Type  string `json:"type"`
	}
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":             "Suivi Terra Nostra 2",
		"short_name":       "Terra Nostra 2",
		"description":      "Les factures, les interventions, les documents et les comptes de la copropriété, tels que Foncia les publie.",
		"lang":             "fr",
		"id":               c.basePath + "/",
		"start_url":        c.basePath + "/",
		"scope":            c.basePath + "/",
		"display":          "standalone",
		"theme_color":      "#ffffff",
		"background_color": "#ffffff",
		"icons": []icon{
			{c.basePath + "/favicon.svg", "any", "image/svg+xml"},
			{c.basePath + "/apple-touch-icon.png", "180x180", "image/png"},
			{c.basePath + "/icon.png", "512x512", "image/png"},
		},
	})
}

func pushJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func pushAnswer(w http.ResponseWriter, ok bool, message string) {
	pushJSON(w, map[string]any{"ok": ok, "message": message})
}

type pushDevice struct {
	Endpoint string          `json:"endpoint"`
	UA       string          `json:"ua"`
	Created  time.Time       `json:"created"`
	Events   map[string]bool `json:"events"`
}

// pushInfo is what the page shows: the key to subscribe with, the kinds of
// news, and the caller's devices (without their keys, which the page has no
// use for).
func (c copro) pushInfo(w http.ResponseWriter, r *http.Request) {
	abos, err := db.ListPushAbonnements(r.Context(), c.sqlDB, currentUser(r))
	if err != nil {
		logutil.Errorf("push: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	devices := []pushDevice{}
	for _, a := range abos {
		devices = append(devices, pushDevice{a.Endpoint, a.UA, a.CreatedAt, a.Events})
	}
	pushJSON(w, map[string]any{"key": c.push.vapid.Public, "kinds": pushKinds, "devices": devices})
}

type pushRequest struct {
	Subscription struct {
		Endpoint string `json:"endpoint"`
		Keys     struct {
			P256dh string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	} `json:"subscription"`
	Endpoint string          `json:"endpoint"` // unsubscribe
	Events   map[string]bool `json:"events"`
}

// readPushRequest wants JSON said as JSON: a form of another site can't say
// so without the browser asking this server first (CORS), which protects the
// people logged in from requests they didn't make.
func readPushRequest(w http.ResponseWriter, r *http.Request) (pushRequest, bool) {
	var req pushRequest
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return req, false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func (c copro) pushSubscribe(w http.ResponseWriter, r *http.Request) {
	req, ok := readPushRequest(w, r)
	if !ok {
		return
	}
	probleme := c.push.subscribe(r.Context(), db.PushAbonnementDB{
		Endpoint: req.Subscription.Endpoint,
		P256dh:   req.Subscription.Keys.P256dh,
		Auth:     req.Subscription.Keys.Auth,
		Email:    currentUser(r),
		UA:       r.UserAgent(),
		Events:   req.Events,
	})
	switch {
	case probleme != "":
		pushAnswer(w, false, probleme)
	case req.Events != nil:
		pushAnswer(w, true, "Choix enregistré.")
	default:
		pushAnswer(w, true, "Notifications activées sur cet appareil.")
	}
}

func (c copro) pushUnsubscribe(w http.ResponseWriter, r *http.Request) {
	req, ok := readPushRequest(w, r)
	if !ok {
		return
	}
	found, err := db.DeletePushAbonnement(r.Context(), c.sqlDB, req.Endpoint, currentUser(r))
	switch {
	case err != nil:
		logutil.Errorf("push: %v", err)
		pushAnswer(w, false, "Erreur interne, voir les logs du serveur.")
	case !found:
		pushAnswer(w, false, "Appareil inconnu.")
	default:
		pushAnswer(w, true, "Notifications désactivées.")
	}
}

// pushTest sends a notification to the caller's devices, whatever kinds they
// want, and says how it went.
func (c copro) pushTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := readPushRequest(w, r); !ok {
		return
	}
	to, err := db.ListPushAbonnements(r.Context(), c.sqlDB, currentUser(r))
	if err != nil {
		logutil.Errorf("push: %v", err)
		pushAnswer(w, false, "Erreur interne, voir les logs du serveur.")
		return
	}
	if len(to) == 0 {
		pushAnswer(w, false, "Aucun appareil abonné.")
		return
	}
	errs := c.push.send(r.Context(), pushEvent{
		Kind:  pushTest,
		Title: "Terra Nostra 2",
		Body:  "Les notifications arrivent bien sur cet appareil.",
		URL:   c.basePath + "/notifications",
	}, to)
	msg := fmt.Sprintf("Test envoyé à %d appareil(s).", len(to)-len(errs))
	if len(errs) > 0 {
		msg += fmt.Sprintf(" %d échec(s) : %v", len(errs), errors.Join(errs...))
	}
	pushAnswer(w, len(errs) == 0, msg)
}
