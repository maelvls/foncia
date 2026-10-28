-- OAuth 2.1, for the MCP clients (Claude, ChatGPT, Grok) that connect to /mcp.
-- See http_oauth.go. These tables are new and empty; nothing else changes.

-- Clients register themselves (RFC 7591) before sending the user to
-- /oauth/authorize.
CREATE TABLE oauth_clients (
    id            TEXT PRIMARY KEY NOT NULL,
    name          TEXT NOT NULL, -- "Claude", "ChatGPT"... As given by the client.
    redirect_uris TEXT NOT NULL, -- JSON array.
    secret_hash   TEXT NOT NULL, -- SHA-256 of the client secret, '' for a public client.
    created_at    TEXT NOT NULL
) STRICT;

-- Authorization codes, access tokens and refresh tokens. Only their SHA-256 is
-- kept, so a copy of the database doesn't give access to anything.
CREATE TABLE oauth_tokens (
    hash           TEXT PRIMARY KEY NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('code', 'access', 'refresh')),
    client_id      TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    email          TEXT NOT NULL, -- The co-owner who approved the client.
    redirect_uri   TEXT NOT NULL, -- Codes only.
    code_challenge TEXT NOT NULL, -- Codes only: PKCE S256.
    resource       TEXT NOT NULL, -- The MCP endpoint's URL (RFC 8707).
    expires_at     INTEGER NOT NULL -- Unix seconds.
) STRICT;

CREATE INDEX idx_oauth_tokens_expires_at ON oauth_tokens (expires_at);
CREATE INDEX idx_oauth_tokens_email ON oauth_tokens (email);
