package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// The WhatsApp conversations about the building, read from the whatsapp
// service of the Pi (vls.dev/whatsapp, /internal/*), which is linked to
// Maël's account. Only the conversations listed here are read.
//
// One source is one exchange: the messages of a conversation that follow each
// other with less than --whatsapp-gap between them. An exchange is recorded
// once nobody wrote in it for --whatsapp-settle, so that it is read whole.

var (
	whatsappURL       = flag.String("whatsapp-url", "", "URL of the whatsapp service of the Pi, e.g. http://whatsapp:8093. Empty disables the WhatsApp collection.")
	whatsappTokenFile = flag.String("whatsapp-token-file", "", "File holding the token of the whatsapp service's /internal API (its state/internal.token).")
	whatsappChats     = flag.String("whatsapp-chats", "", "Comma-separated JIDs of the conversations about the building that are read whole (groups 1203…@g.us, people 336…@s.whatsapp.net).")
	whatsappFiltered  = flag.String("whatsapp-filtered-chats", "", "Comma-separated JIDs of conversations that only sometimes are about the building (the residents' group): only the exchanges matching --whatsapp-keywords are kept.")
	whatsappContacts  = flag.String("whatsapp-contacts", `\((prop |loc )?[A-D]\d{2}\)`, "Regular expression on the address-book names: the conversations with the people it matches are read whole, e.g. « Léa (C11) ». Empty for none.")
	whatsappKeywords  = flag.String("whatsapp-keywords", `(?i)portail|garage|fuite|infiltr|ascenseur|syndic|foncia|panne|vmc|badge|vigik|interphone|digicode|porte|éclairage|lumière|ampoule|toiture|dégât|degat|sinistre|travaux|devis|AG\b|assemblée|conseil syndical|poubelle|encombrant|nuisible|cafard|rat\b|tgbt|compteur|eau chaude|solaire|ballon|irve|borne|recharge`, "Regular expression that an exchange of --whatsapp-filtered-chats must match to be kept.")
	whatsappGap       = flag.Duration("whatsapp-gap", 3*time.Hour, "Silence that separates two exchanges of a conversation.")
	whatsappSettle    = flag.Duration("whatsapp-settle", time.Hour, "How long an exchange must have been quiet before it is recorded.")
)

type whatsappCollecteur struct {
	sqlDB    *sql.DB
	client   *http.Client
	base     string
	token    string
	chats    map[string]bool // Read whole.
	filtered map[string]bool // Only the exchanges matching keywords.
	contacts *regexp.Regexp  // nil: none.
	keywords *regexp.Regexp
	now      func() time.Time
}

func newWhatsappCollecteur(sqlDB *sql.DB) (*whatsappCollecteur, error) {
	raw, err := os.ReadFile(*whatsappTokenFile)
	if err != nil {
		return nil, fmt.Errorf("--whatsapp-token-file: %w", err)
	}
	w := &whatsappCollecteur{
		sqlDB:    sqlDB,
		client:   &http.Client{Timeout: 2 * time.Minute},
		base:     strings.TrimRight(*whatsappURL, "/"),
		token:    strings.TrimSpace(string(raw)),
		chats:    jidSet(*whatsappChats),
		filtered: jidSet(*whatsappFiltered),
		now:      time.Now,
	}
	if *whatsappContacts != "" {
		if w.contacts, err = regexp.Compile(*whatsappContacts); err != nil {
			return nil, fmt.Errorf("--whatsapp-contacts: %w", err)
		}
	}
	if w.keywords, err = regexp.Compile(*whatsappKeywords); err != nil {
		return nil, fmt.Errorf("--whatsapp-keywords: %w", err)
	}
	return w, nil
}

func jidSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, j := range strings.Split(s, ",") {
		if j = strings.TrimSpace(j); j != "" {
			out[j] = true
		}
	}
	return out
}

func (w *whatsappCollecteur) nom() string { return "whatsapp" }

type waChat struct {
	JID         string    `json:"jid"`
	Name        string    `json:"name"`
	IsGroup     bool      `json:"is_group"`
	ContactName string    `json:"contact_name"`
	LastAt      time.Time `json:"last_at"`
}

type waMessage struct {
	Chat       string    `json:"chat"`
	ChatName   string    `json:"chat_name"`
	ID         string    `json:"id"`
	SenderName string    `json:"sender_name"`
	FromMe     bool      `json:"from_me"`
	Time       time.Time `json:"time"`
	Kind       string    `json:"kind"`
	Text       string    `json:"text"`
	Deleted    bool      `json:"deleted"`
	Mimetype   string    `json:"mimetype"`
	Filename   string    `json:"filename"`
	Size       int64     `json:"size"`
}

func (w *whatsappCollecteur) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		resp.Body.Close()
		return nil, &waError{status: resp.StatusCode, msg: strings.TrimSpace(string(body)), path: path}
	}
	return resp, nil
}

type waError struct {
	status    int
	msg, path string
}

func (e *waError) Error() string { return fmt.Sprintf("whatsapp %s: %d %s", e.path, e.status, e.msg) }

func (w *whatsappCollecteur) getJSON(ctx context.Context, path string, out any) error {
	resp, err := w.get(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// suivies returns the conversations to read and whether each is filtered.
func (w *whatsappCollecteur) suivies(ctx context.Context) ([]waChat, map[string]bool, error) {
	var chats []waChat
	if err := w.getJSON(ctx, "/internal/chats", &chats); err != nil {
		return nil, nil, err
	}
	var out []waChat
	filtre := map[string]bool{}
	for _, c := range chats {
		switch {
		case w.chats[c.JID]:
		case w.filtered[c.JID]:
			filtre[c.JID] = true
		case !c.IsGroup && w.contacts != nil && w.contacts.MatchString(c.ContactName):
		default:
			continue
		}
		out = append(out, c)
	}
	return out, filtre, nil
}

func (w *whatsappCollecteur) collecter(ctx context.Context) (int, error) {
	chats, filtre, err := w.suivies(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, c := range chats {
		k, err := w.collecterChat(ctx, c, filtre[c.JID])
		n += k
		if err != nil {
			errs = append(errs, fmt.Errorf("%s (%s): %w", c.Name, c.JID, err))
		}
	}
	return n, errors.Join(errs...)
}

func reglageWhatsapp(jid string) string { return "whatsapp_depuis:" + jid }

func (w *whatsappCollecteur) collecterChat(ctx context.Context, c waChat, filtre bool) (int, error) {
	cle := reglageWhatsapp(c.JID)
	v, err := db.GetReglage(ctx, w.sqlDB, cle)
	if err != nil {
		return 0, err
	}
	var depuis time.Time
	if v == "" {
		if depuis, err = debutCollecte(w.now()); err != nil {
			return 0, err
		}
	} else {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("setting %s: %w", cle, err)
		}
		depuis = time.Unix(n, 0)
	}
	if !c.LastAt.IsZero() && !c.LastAt.After(depuis) {
		return 0, nil
	}

	n := 0
	for range 20 { // 500 messages a page; more is a backlog for the next round.
		var msgs []waMessage
		if err := w.getJSON(ctx, "/internal/messages?"+url.Values{"chat": {c.JID}, "after": {strconv.FormatInt(depuis.Unix(), 10)}}.Encode(), &msgs); err != nil {
			return n, err
		}
		echanges, ouvert := decouperEchanges(msgs, *whatsappGap, w.now().Add(-*whatsappSettle))
		for _, e := range echanges {
			if !filtre || w.keywords.MatchString(texteEchange(e)) {
				ok, err := w.enregistrer(ctx, c, e)
				if err != nil {
					return n, err
				}
				if ok {
					n++
				}
			}
			depuis = e[len(e)-1].Time
			if err := db.SetReglage(ctx, w.sqlDB, cle, strconv.FormatInt(depuis.Unix(), 10)); err != nil {
				return n, err
			}
		}
		if len(echanges) == 0 && !ouvert && len(msgs) > 0 {
			// Only reactions and deleted messages: nothing to record, but
			// no reason to read them again.
			depuis = msgs[len(msgs)-1].Time
			if err := db.SetReglage(ctx, w.sqlDB, cle, strconv.FormatInt(depuis.Unix(), 10)); err != nil {
				return n, err
			}
		}
		if len(msgs) < 500 || ouvert || len(echanges) == 0 {
			return n, nil
		}
	}
	return n, nil
}

// decouperEchanges splits messages (oldest first) into exchanges. The last
// one is left out, and ouvert is true, when its last message is after
// calmeAvant: people may still be writing.
func decouperEchanges(msgs []waMessage, gap time.Duration, calmeAvant time.Time) (echanges [][]waMessage, ouvert bool) {
	var cur []waMessage
	for _, m := range msgs {
		if m.Deleted || m.Kind == "reaction" || m.Kind == "sticker" {
			continue
		}
		if len(cur) > 0 && m.Time.Sub(cur[len(cur)-1].Time) > gap {
			echanges = append(echanges, cur)
			cur = nil
		}
		cur = append(cur, m)
	}
	if len(cur) > 0 {
		if cur[len(cur)-1].Time.After(calmeAvant) {
			return echanges, true
		}
		echanges = append(echanges, cur)
	}
	return echanges, false
}

func texteEchange(e []waMessage) string {
	var b strings.Builder
	for _, m := range e {
		b.WriteString(m.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

var libelleMedia = map[string]string{
	"image": "photo", "video": "vidéo", "voice": "message vocal", "audio": "audio", "document": "document",
	"location": "position", "contact": "contact", "poll": "sondage",
}

// enregistrer records an exchange as one source: one line per message, and
// the photos and documents as attachments.
func (w *whatsappCollecteur) enregistrer(ctx context.Context, c waChat, e []waMessage) (bool, error) {
	ext := c.JID + "/" + e[0].ID
	if known, err := db.SourceExists(ctx, w.sqlDB, db.CanalWhatsApp, ext); err != nil || known {
		return false, err
	}
	var lignes []string
	var auteurs []string
	vus := map[string]bool{}
	var fichiers []db.SourceFichier
	jour := ""
	for _, m := range e {
		qui := m.SenderName
		if m.FromMe {
			qui = "Maël"
		}
		if !vus[qui] {
			vus[qui] = true
			auteurs = append(auteurs, qui)
		}
		d := m.Time.In(paris)
		prefixe := d.Format("15:04")
		if j := d.Format("02/01"); j != jour {
			jour = j
			prefixe = j + " " + prefixe
		}
		texte := strings.TrimSpace(m.Text)
		if l, ok := libelleMedia[m.Kind]; ok {
			pj := "[" + l + "]"
			if m.Kind == "image" || m.Kind == "document" {
				f, err := w.media(ctx, c, m)
				switch {
				case err == nil:
					fichiers = append(fichiers, f)
				case isGone(err):
					pj = "[" + l + " plus disponible sur WhatsApp]"
				default:
					return false, err
				}
			}
			texte = strings.TrimSpace(pj + " " + texte)
		}
		lignes = append(lignes, prefixe+" "+qui+" : "+texte)
	}
	titre := c.Name
	if !c.IsGroup && c.ContactName != "" {
		titre = c.ContactName
	}
	_, err := enregistrerSource(ctx, w.sqlDB, db.SourceDB{
		Canal:    db.CanalWhatsApp,
		ExtID:    ext,
		Fil:      c.JID,
		FilTitre: titre,
		Auteur:   strings.Join(auteurs, ", "),
		Texte:    nettoyerTexte(strings.Join(lignes, "\n")),
		Date:     e[0].Time,
		Fichiers: fichiers,
	})
	return err == nil, err
}

func isGone(err error) bool {
	var we *waError
	return errors.As(err, &we) && (we.status == http.StatusGone || we.status == http.StatusNotFound)
}

func (w *whatsappCollecteur) media(ctx context.Context, c waChat, m waMessage) (db.SourceFichier, error) {
	if m.Size > maxFichier {
		return db.SourceFichier{}, &waError{status: http.StatusGone, msg: "trop gros", path: m.ID}
	}
	resp, err := w.get(ctx, "/internal/media?"+url.Values{"chat": {c.JID}, "id": {m.ID}}.Encode())
	if err != nil {
		return db.SourceFichier{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFichier+1))
	if err != nil {
		return db.SourceFichier{}, err
	}
	nom := m.Filename
	if nom == "" {
		ext := ".jpg"
		if m.Kind == "document" {
			ext = ""
		}
		nom = "WhatsApp " + m.Time.In(paris).Format("2006-01-02 15.04.05") + ext
	}
	f, err := stockerFichier(ctx, w.sqlDB, bytes.NewReader(data), nom, m.Mimetype, db.FichierWhatsApp, m.SenderName)
	if errors.Is(err, errTropGros) {
		return db.SourceFichier{}, &waError{status: http.StatusGone, msg: "trop gros", path: m.ID}
	}
	if err != nil {
		return db.SourceFichier{}, err
	}
	logutil.Debugf("whatsapp: kept %s from %s", nom, c.Name)
	return db.SourceFichier{FichierDB: f, NomDansMessage: nomPropre(nom)}, nil
}
