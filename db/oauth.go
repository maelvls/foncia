package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// OAuth 2.1 clients and tokens, for the MCP endpoint. See http_oauth.go.
// -----------------------------------------------------------------------------

// ErrOAuthNotFound is returned for an unknown client, and for a token that is
// unknown, expired or of another kind.
var ErrOAuthNotFound = errors.New("not found")

type OAuthClient struct {
	ID           string
	Name         string   // Example: "Claude".
	RedirectURIs []string // Example: ["https://claude.ai/api/mcp/auth_callback"].
	SecretHash   string   // SHA-256 of the client secret, hex. Empty for a public client.
	CreatedAt    time.Time
}

func CreateOAuthClient(ctx context.Context, db *sql.DB, c OAuthClient) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "INSERT INTO oauth_clients (id, name, redirect_uris, secret_hash, created_at) VALUES (?, ?, ?, ?, ?)",
		c.ID, c.Name, string(uris), c.SecretHash, formatTime(c.CreatedAt))
	if err != nil {
		return fmt.Errorf("while saving the OAuth client %q: %w", c.Name, err)
	}
	return nil
}

func GetOAuthClient(ctx context.Context, db *sql.DB, id string) (OAuthClient, error) {
	var c OAuthClient
	var uris, createdAt string
	err := db.QueryRowContext(ctx, "SELECT id, name, redirect_uris, secret_hash, created_at FROM oauth_clients WHERE id = ?", id).
		Scan(&c.ID, &c.Name, &uris, &c.SecretHash, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OAuthClient{}, ErrOAuthNotFound
	}
	if err != nil {
		return OAuthClient{}, fmt.Errorf("while querying the OAuth client %q: %w", id, err)
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return OAuthClient{}, fmt.Errorf("while parsing the redirect URIs of the OAuth client %q: %w", id, err)
	}
	c.CreatedAt, err = parseTime("created_at", createdAt)
	if err != nil {
		return OAuthClient{}, err
	}
	return c, nil
}

type OAuthTokenKind string

const (
	OAuthCode    OAuthTokenKind = "code"
	OAuthAccess  OAuthTokenKind = "access"
	OAuthRefresh OAuthTokenKind = "refresh"
)

// OAuthGrant is what a code or a token stands for.
type OAuthGrant struct {
	ClientID      string
	Email         string // The co-owner who approved the client.
	RedirectURI   string // Codes only.
	CodeChallenge string // Codes only.
	Resource      string // Example: "https://suivi-terra-nostra-2.vls.dev/mcp".
	ExpiresAt     time.Time
}

// CreateOAuthToken saves a token. hash is the token's SHA-256, never the token
// itself. The expired tokens are deleted on the way.
func CreateOAuthToken(ctx context.Context, db *sql.DB, kind OAuthTokenKind, hash string, g OAuthGrant) error {
	return inTx(ctx, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM oauth_tokens WHERE expires_at <= ?", time.Now().Unix())
		if err != nil {
			return fmt.Errorf("while deleting the expired OAuth tokens: %w", err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO oauth_tokens (hash, kind, client_id, email, redirect_uri, code_challenge, resource, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			hash, kind, g.ClientID, g.Email, g.RedirectURI, g.CodeChallenge, g.Resource, g.ExpiresAt.Unix())
		if err != nil {
			return fmt.Errorf("while saving the OAuth %s: %w", kind, err)
		}
		return nil
	})
}

const oauthGrantColumns = "client_id, email, redirect_uri, code_challenge, resource, expires_at"

func scanOAuthGrant(row *sql.Row) (OAuthGrant, error) {
	var g OAuthGrant
	var expiresAt int64
	err := row.Scan(&g.ClientID, &g.Email, &g.RedirectURI, &g.CodeChallenge, &g.Resource, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OAuthGrant{}, ErrOAuthNotFound
	}
	if err != nil {
		return OAuthGrant{}, err
	}
	g.ExpiresAt = time.Unix(expiresAt, 0)
	return g, nil
}

// GetOAuthToken returns the grant of a token that hasn't expired.
func GetOAuthToken(ctx context.Context, db *sql.DB, kind OAuthTokenKind, hash string) (OAuthGrant, error) {
	return scanOAuthGrant(db.QueryRowContext(ctx,
		"SELECT "+oauthGrantColumns+" FROM oauth_tokens WHERE hash = ? AND kind = ? AND expires_at > ?",
		hash, kind, time.Now().Unix()))
}

// ConsumeOAuthToken deletes a token and returns its grant, so that a code or
// a refresh token can only be used once, even by two concurrent requests.
func ConsumeOAuthToken(ctx context.Context, db *sql.DB, kind OAuthTokenKind, hash string) (OAuthGrant, error) {
	return scanOAuthGrant(db.QueryRowContext(ctx,
		"DELETE FROM oauth_tokens WHERE hash = ? AND kind = ? AND expires_at > ? RETURNING "+oauthGrantColumns,
		hash, kind, time.Now().Unix()))
}

// DeleteOAuthTokensByEmail revokes everything a co-owner approved. It returns
// the number of codes and tokens deleted.
func DeleteOAuthTokensByEmail(ctx context.Context, db *sql.DB, email string) (int64, error) {
	res, err := db.ExecContext(ctx, "DELETE FROM oauth_tokens WHERE email = ?", strings.ToLower(email))
	if err != nil {
		return 0, fmt.Errorf("while deleting the OAuth tokens of %s: %w", email, err)
	}
	return res.RowsAffected()
}
