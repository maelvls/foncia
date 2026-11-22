package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/oauth2"
)

// The connection to the Gmail mailbox, kept in --gmail-token-file: the OAuth
// client and the refresh token of a login that can only read
// (gmail.readonly). /reglages writes the file (http_reglages.go), the
// collector reads it again on every run (collect_gmail.go).
//
// The OAuth client is a « Desktop app » one, such as the one a command-line
// tool already uses: nothing to declare at Google, but Google only sends
// those back to http://localhost, where nothing answers. The page asks for
// the address of that page that doesn't load, and reads the code in it.

const (
	gmailScope     = "https://www.googleapis.com/auth/gmail.readonly"
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	// gmailRedirect is where Google sends the browser back with the code.
	// Nothing listens there.
	gmailRedirect = "http://localhost:18446/"
)

// gmailToken is the content of --gmail-token-file. A file made by hand
// (brain/gmail-token.py) only has the first three fields.
type gmailToken struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// As in Google's client_secret.json. Empty means Google's; the tests
	// point them at a fake.
	AuthURI  string `json:"auth_uri,omitempty"`
	TokenURI string `json:"token_uri,omitempty"`

	// What /reglages noted when the mailbox was connected there: the address
	// as Google gave it, when, and who did it.
	Account     string    `json:"account,omitempty"`
	ConnectedAt time.Time `json:"connected_at,omitzero"`
	ConnectedBy string    `json:"connected_by,omitempty"`
}

// relie tells whether a mailbox is connected.
func (t gmailToken) relie() bool { return t.ClientID != "" && t.RefreshToken != "" }

// memeJeton tells whether an HTTP client made from o still works for t.
func (t gmailToken) memeJeton(o gmailToken) bool {
	return t.ClientID == o.ClientID && t.ClientSecret == o.ClientSecret && t.RefreshToken == o.RefreshToken && t.TokenURI == o.TokenURI
}

func (t gmailToken) conf() oauth2.Config {
	e := oauth2.Endpoint{AuthURL: t.AuthURI, TokenURL: t.TokenURI}
	if e.AuthURL == "" {
		e.AuthURL = googleAuthURL
	}
	if e.TokenURL == "" {
		e.TokenURL = googleTokenURL
	}
	return oauth2.Config{ClientID: t.ClientID, ClientSecret: t.ClientSecret, Endpoint: e, RedirectURL: gmailRedirect, Scopes: []string{gmailScope}}
}

// client is an HTTP client that reads the mailbox with the refresh token.
func (t gmailToken) client(ctx context.Context) *http.Client {
	return gmailClientDe(ctx, t.conf(), &oauth2.Token{RefreshToken: t.RefreshToken})
}

func gmailClientDe(ctx context.Context, conf oauth2.Config, tok *oauth2.Token) *http.Client {
	// The client outlives the request or the run that makes it, and it
	// renews its access token with this context.
	client := oauth2.NewClient(ctx, conf.TokenSource(context.WithoutCancel(ctx), tok))
	client.Timeout = 2 * time.Minute
	return client
}

// lireGmailToken reads the token file. A file that doesn't exist yet is a
// mailbox that isn't connected, not an error.
func lireGmailToken(path string) (gmailToken, error) {
	var tok gmailToken
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return tok, nil
	}
	if err != nil {
		return tok, fmt.Errorf("--gmail-token-file: %w", err)
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return gmailToken{}, fmt.Errorf("--gmail-token-file %s: %w", path, err)
	}
	return tok, nil
}

// ecrireGmailToken replaces the token file in one go, readable by its owner
// only. The file keeps the owner it had (or gets that of its directory): the
// server often runs as root in its container, on a directory that belongs to
// the person who deploys it.
func ecrireGmailToken(path string, tok gmailToken) error {
	raw, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gmail-token-*")
	if err != nil {
		return fmt.Errorf("--gmail-token-file: %w", err)
	}
	defer os.Remove(tmp.Name()) // Nothing left once renamed.
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("--gmail-token-file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("--gmail-token-file: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("--gmail-token-file: %w", err)
	}
	proprietaire, err := os.Stat(path)
	if err != nil {
		proprietaire, err = os.Stat(dir)
	}
	if err == nil {
		if st, ok := proprietaire.Sys().(*syscall.Stat_t); ok {
			// Only root can give a file away: best effort.
			_ = os.Chown(tmp.Name(), int(st.Uid), int(st.Gid))
		}
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("--gmail-token-file: %w", err)
	}
	return nil
}

// gmailAdresse asks Google whose mailbox the client reads.
func gmailAdresse(ctx context.Context, client *http.Client, api string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"/profile", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gmail /profile: %s: %s", resp.Status, strings.TrimSpace(string(body[:min(len(body), 300)])))
	}
	var p struct {
		EmailAddress string `json:"emailAddress"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", fmt.Errorf("gmail /profile: %w", err)
	}
	if p.EmailAddress == "" {
		return "", errors.New("gmail /profile: no address in the answer")
	}
	return p.EmailAddress, nil
}

// memeAdresse compares two e-mail addresses.
func memeAdresse(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
