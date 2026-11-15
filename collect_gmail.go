package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
	"golang.org/x/oauth2"
)

// The e-mails about the building, read from Gmail with a read-only token
// (scope gmail.readonly). Only the messages matching --gmail-query are read.

var (
	gmailTokenFile = flag.String("gmail-token-file", "", "JSON file with the OAuth client and refresh token of a Gmail account (client_id, client_secret, refresh_token), with the gmail.readonly scope. Empty disables the e-mail collection.")
	gmailQuery     = flag.String("gmail-query", "", "Gmail search (as in the search box) of the e-mails about the building. The collector adds after:<date> itself.")
	gmailAccount   = flag.String("gmail-account", "", "The e-mail address of the account, for the \"voir dans Gmail\" links.")
	gmailAPIFlag   = flag.String("gmail-api", gmailAPI, "Base URL of the Gmail API, for tests.")
)

const gmailAPI = "https://gmail.googleapis.com/gmail/v1/users/me"

type gmailCollecteur struct {
	sqlDB   *sql.DB
	client  *http.Client
	query   string
	account string
	api     string // gmailAPI, or a test server.
}

type gmailToken struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	TokenURI     string `json:"token_uri"`
}

func newGmailCollecteur(ctx context.Context, sqlDB *sql.DB) (*gmailCollecteur, error) {
	raw, err := os.ReadFile(*gmailTokenFile)
	if err != nil {
		return nil, fmt.Errorf("--gmail-token-file: %w", err)
	}
	var tok gmailToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("--gmail-token-file %s: %w", *gmailTokenFile, err)
	}
	if tok.ClientID == "" || tok.RefreshToken == "" {
		return nil, fmt.Errorf("--gmail-token-file %s: client_id and refresh_token are needed", *gmailTokenFile)
	}
	if strings.TrimSpace(*gmailQuery) == "" {
		return nil, fmt.Errorf("--gmail-query is needed with --gmail-token-file: without it, every e-mail of the account would be read")
	}
	tokenURL := tok.TokenURI
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	conf := oauth2.Config{ClientID: tok.ClientID, ClientSecret: tok.ClientSecret, Endpoint: oauth2.Endpoint{TokenURL: tokenURL}}
	client := oauth2.NewClient(ctx, conf.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}))
	client.Timeout = 2 * time.Minute
	return &gmailCollecteur{sqlDB: sqlDB, client: client, query: *gmailQuery, account: *gmailAccount, api: *gmailAPIFlag}, nil
}

func (g *gmailCollecteur) nom() string { return "gmail" }

const reglageGmailDepuis = "gmail_depuis"

func (g *gmailCollecteur) collecter(ctx context.Context) (int, error) {
	depuis, err := g.depuis(ctx)
	if err != nil {
		return 0, err
	}
	// A day of margin: Gmail's after: is by day for some messages, and a
	// message can take a while to be indexed.
	q := g.query + " after:" + strconv.FormatInt(depuis.Add(-24*time.Hour).Unix(), 10)
	ids, err := g.lister(ctx, q)
	if err != nil {
		return 0, err
	}
	n := 0
	plusRecent := depuis
	var errs []error
	// Oldest first, so that a reply comes after the message it answers and
	// gets filed with it.
	for i := len(ids) - 1; i >= 0; i-- {
		id := ids[i]
		known, err := db.SourceExists(ctx, g.sqlDB, db.CanalGmail, id)
		if err != nil {
			return n, err
		}
		if known {
			continue
		}
		s, err := g.lire(ctx, id)
		if err != nil {
			errs = append(errs, fmt.Errorf("message %s: %w", id, err))
			continue
		}
		ok, err := enregistrerSource(ctx, g.sqlDB, s)
		if err != nil {
			errs = append(errs, fmt.Errorf("message %s: %w", id, err))
			continue
		}
		if ok {
			n++
		}
		if s.Date.After(plusRecent) {
			plusRecent = s.Date
		}
	}
	if len(errs) == 0 && plusRecent.After(depuis) {
		if err := db.SetReglage(ctx, g.sqlDB, reglageGmailDepuis, plusRecent.UTC().Format(time.RFC3339)); err != nil {
			return n, err
		}
	}
	return n, errors.Join(errs...)
}

func (g *gmailCollecteur) depuis(ctx context.Context) (time.Time, error) {
	v, err := db.GetReglage(ctx, g.sqlDB, reglageGmailDepuis)
	if err != nil {
		return time.Time{}, err
	}
	if v == "" {
		return debutCollecte(time.Now())
	}
	return time.Parse(time.RFC3339, v)
}

func (g *gmailCollecteur) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.api+path, nil)
	if err != nil {
		return err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 3*maxFichier))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gmail %s: %s: %s", path, resp.Status, bytes.TrimSpace(body[:min(len(body), 300)]))
	}
	return json.Unmarshal(body, out)
}

// lister returns the ids of the messages matching q, newest first.
func (g *gmailCollecteur) lister(ctx context.Context, q string) ([]string, error) {
	var ids []string
	page := ""
	for range 50 {
		v := url.Values{"q": {q}, "maxResults": {"200"}}
		if page != "" {
			v.Set("pageToken", page)
		}
		var resp struct {
			Messages []struct {
				ID string `json:"id"`
			} `json:"messages"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := g.get(ctx, "/messages?"+v.Encode(), &resp); err != nil {
			return nil, err
		}
		for _, m := range resp.Messages {
			ids = append(ids, m.ID)
		}
		if resp.NextPageToken == "" {
			return ids, nil
		}
		page = resp.NextPageToken
	}
	return ids, nil
}

type gmailPart struct {
	MimeType string `json:"mimeType"`
	Filename string `json:"filename"`
	Headers  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"headers"`
	Body struct {
		AttachmentID string `json:"attachmentId"`
		Size         int64  `json:"size"`
		Data         string `json:"data"`
	} `json:"body"`
	Parts []gmailPart `json:"parts"`
}

func (p gmailPart) header(name string) string {
	for _, h := range p.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

type gmailMessage struct {
	ID           string    `json:"id"`
	ThreadID     string    `json:"threadId"`
	InternalDate string    `json:"internalDate"` // Milliseconds.
	Payload      gmailPart `json:"payload"`
}

// lire fetches a message, its text and its attachments.
func (g *gmailCollecteur) lire(ctx context.Context, id string) (db.SourceDB, error) {
	var m gmailMessage
	if err := g.get(ctx, "/messages/"+url.PathEscape(id)+"?format=full", &m); err != nil {
		return db.SourceDB{}, err
	}
	s := db.SourceDB{
		Canal:  db.CanalGmail,
		ExtID:  m.ID,
		Fil:    m.ThreadID,
		Auteur: adresses(m.Payload.header("From")),
		Sujet:  decoderEntete(m.Payload.header("Subject")),
	}
	if ms, err := strconv.ParseInt(m.InternalDate, 10, 64); err == nil {
		s.Date = time.UnixMilli(ms)
	} else if d, err := mail.ParseDate(m.Payload.header("Date")); err == nil {
		s.Date = d
	} else {
		s.Date = time.Now()
	}
	var dest []string
	for _, h := range []string{"To", "Cc"} {
		if v := adresses(m.Payload.header(h)); v != "" {
			dest = append(dest, v)
		}
	}
	s.Destinataires = strings.Join(dest, ", ")
	if g.account != "" {
		s.URL = "https://mail.google.com/mail/u/" + url.PathEscape(g.account) + "/#all/" + m.ID
	}

	var plain, htmlText string
	var pjs []gmailPart
	var walk func(p gmailPart)
	walk = func(p gmailPart) {
		switch {
		case p.Filename != "" && (p.Body.AttachmentID != "" || p.Body.Data != ""):
			pjs = append(pjs, p)
		case p.MimeType == "text/plain" && plain == "":
			plain = decoderCorps(p.Body.Data)
		case p.MimeType == "text/html" && htmlText == "":
			htmlText = texteDuHTML(decoderCorps(p.Body.Data))
		}
		for _, c := range p.Parts {
			walk(c)
		}
	}
	walk(m.Payload)
	texte := plain
	if strings.TrimSpace(texte) == "" {
		texte = htmlText
	}
	s.Texte = nettoyerTexte(texte)

	for _, p := range pjs {
		if !pieceJointeUtile(p.Filename, p.MimeType, p.Body.Size) {
			continue
		}
		data := p.Body.Data
		if p.Body.AttachmentID != "" {
			var att struct {
				Data string `json:"data"`
			}
			if err := g.get(ctx, "/messages/"+url.PathEscape(id)+"/attachments/"+url.PathEscape(p.Body.AttachmentID), &att); err != nil {
				return s, fmt.Errorf("attachment %s: %w", p.Filename, err)
			}
			data = att.Data
		}
		raw, err := base64.URLEncoding.DecodeString(padBase64(data))
		if err != nil {
			return s, fmt.Errorf("attachment %s: %w", p.Filename, err)
		}
		f, err := stockerFichier(ctx, g.sqlDB, bytes.NewReader(raw), p.Filename, p.MimeType, db.FichierGmail, s.Auteur)
		if errors.Is(err, errTropGros) {
			logutil.Infof("gmail: skipping %s of message %s: %v", p.Filename, id, err)
			continue
		}
		if err != nil {
			return s, err
		}
		s.Fichiers = append(s.Fichiers, db.SourceFichier{FichierDB: f, NomDansMessage: nomPropre(decoderEntete(p.Filename))})
	}
	return s, nil
}

func padBase64(s string) string {
	s = strings.TrimRight(s, "=")
	if r := len(s) % 4; r != 0 {
		s += strings.Repeat("=", 4-r)
	}
	return s
}

func decoderCorps(data string) string {
	raw, err := base64.URLEncoding.DecodeString(padBase64(data))
	if err != nil {
		return ""
	}
	return string(bytes.ToValidUTF8(raw, []byte("�")))
}

var wordDecoder = new(mime.WordDecoder)

func decoderEntete(s string) string {
	if d, err := wordDecoder.DecodeHeader(s); err == nil {
		return d
	}
	return s
}

// adresses rewrites "From"/"To" for reading: « Jean Dupont <jean.dupont@foncia.com> ».
func adresses(v string) string {
	list, err := mail.ParseAddressList(v)
	if err != nil {
		return strings.TrimSpace(decoderEntete(v))
	}
	var out []string
	for _, a := range list {
		if a.Name != "" {
			out = append(out, a.Name+" <"+a.Address+">")
		} else {
			out = append(out, a.Address)
		}
	}
	return strings.Join(out, ", ")
}

// pieceJointeUtile keeps the documents and the photos, not the logos of the
// signatures nor the calendar invitations.
func pieceJointeUtile(nom, typ string, taille int64) bool {
	if taille > maxFichier {
		return false
	}
	ext := strings.ToLower(nom[strings.LastIndex(nom, ".")+1:])
	switch {
	case typ == "application/pdf" || ext == "pdf":
		return true
	case strings.HasPrefix(typ, "image/") || ext == "jpg" || ext == "jpeg" || ext == "png" || ext == "heic" || ext == "gif" || ext == "webp":
		// Signature logos and pixels weigh a few kilobytes.
		return taille >= 20<<10
	}
	switch ext {
	case "doc", "docx", "xls", "xlsx", "odt", "ods", "csv", "txt", "rtf", "eml", "msg":
		return true
	}
	return false
}

var (
	reBalisesBloc   = regexp.MustCompile(`(?i)<\s*(br|/p|/div|/tr|/li|/h[1-6])\s*/?>`)
	reStyleScript   = regexp.MustCompile(`(?is)<\s*(style|script|head)[^>]*>.*?<\s*/\s*(style|script|head)\s*>`)
	reBalises       = regexp.MustCompile(`(?s)<[^>]*>`)
	reLignesVides   = regexp.MustCompile(`\n[ \t\x{00a0}]*(\n[ \t\x{00a0}]*){2,}`)
	reCitationDebut = regexp.MustCompile(`(?m)^(Le .{4,160}a écrit\s*:|On .{4,160}wrote\s*:|-{2,}\s*(Original Message|Message d'origine|Mail original)\s*-{2,}|De\s*:\s.+\n(Envoyé|Date)\s*:)`)
)

func texteDuHTML(h string) string {
	h = reStyleScript.ReplaceAllString(h, "")
	h = reBalisesBloc.ReplaceAllString(h, "\n")
	h = reBalises.ReplaceAllString(h, "")
	return strings.ReplaceAll(html.UnescapeString(h), " ", " ")
}

// maxTexte is how much of a message is kept: enough for any real e-mail, not
// for a newsletter pasted three times.
const maxTexte = 20000

// nettoyerTexte drops the quoted previous messages (they are their own
// sources, or not about the building) and the runs of blank lines.
func nettoyerTexte(t string) string {
	t = strings.ReplaceAll(t, "\r\n", "\n")
	if loc := reCitationDebut.FindStringIndex(t); loc != nil && loc[0] > 0 {
		t = t[:loc[0]]
	}
	var lignes []string
	for _, l := range strings.Split(t, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), ">") {
			continue
		}
		lignes = append(lignes, strings.TrimRight(l, " \t "))
	}
	t = strings.TrimSpace(reLignesVides.ReplaceAllString(strings.Join(lignes, "\n"), "\n\n"))
	if r := []rune(t); len(r) > maxTexte {
		t = string(r[:maxTexte]) + "\n[…]"
	}
	return t
}
