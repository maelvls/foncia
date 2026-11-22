# The `foncia` CLI

The `foncia` CLI lets you list all "missionRepairs" and "missionIncidents". It
also lets you create a server that notifies you using ntfy.sh when a new
"missionIncident" or "missionRepair" is created. Example:

![suivi-foncia](https://github.com/user-attachments/assets/a7cfef68-5432-4756-9244-9c866e43a298)


I've created this for two reasons:

1. I wanted to be aware of anything happening in my building, preferably in
   real-time on my phone.
2. I found that the `description` field of "missionIncidents" and
   "missionRepairs" had disappeared since the migration from the old myFoncia
   website to the new "fonciamillenium" website, and I found that I could access
   that field using the GraphQL API.

## Comptes travaux

A "compte travaux" is the account that tracks the expenses of a single works
project voted at a general assembly. In the Foncia GraphQL API, they are called
"repair budgets". To list them:

```bash
foncia comptes-travaux
```

```text
64850e809256a30838192303  REFECTION ASCENSEURS                 0,00 €
6939a432a558318b60013568  GSM BAT C                         1003,71 €
6939b0fe0152f9f336085179  REPRISE INSTALLATION SOLAIRE      2924,54 €
```

The amount on the right is the amount voted at the general assembly. Add
`--totals` to also show the balance of each "compte travaux"; it is slower since
it does one extra API call per "compte travaux".

To see the expenses charged to one of them, pass its ID or a case-insensitive
fragment of its label:

```bash
foncia comptes-travaux "REPRISE INSTALLATION SOLAIRE"
```

```text
REPRISE INSTALLATION SOLAIRE (6939b0fe0152f9f336085179)
  Montant voté: 2924,54 €
  Solde:        -1922,61 €
  Dont TVA:     12,94 €
  Récupérable:  0,00 €

  CHARGES GENERALES [001] 77,64 €
    HCC HONORAIRES TRAVAUX [1703] 77,64 €
      14 Dec 2025        77,64 € Honoraires REPRISE INSTALLATION SOLAIRE

  CHARGES GENERALES_FT [001_FT] -2000,25 €
    HCC MOBILISATION FONDS TRAVAUX [1937] -2000,25 €
      01 Jan 2026     -2000,25 € MOBILISATION FT TRAVAUX REPRISE INSTALLATION SOLAIRE 01/01/2026 1/1
```

The "solde" is the balance of the account: expenses charged to it are positive,
and the funds mobilized to pay for them are negative, which means a negative
balance is money that has been called but not spent yet.

Use `--json` to get the raw data instead of the table. Amounts are in cents.

## Convocations d'assemblée générale

The documents attached to the general assemblies — the convocations, the signed
procès-verbaux, and the annexes (accounts, water meter readings, etc.) — show up
in the web UI under the filter "Assemblées générales".

They are indexed by the sync but **not downloaded** by default: there are more
than a hundred of them, and some convocations weigh tens of megabytes. When a
document isn't on disk, the UI shows a "Télécharger depuis Foncia" link;
`/dl/doc/<hash_file>` then downloads the PDF into `--invoices-dir`, remembers
where it put it, and serves it. The next hits are served straight from disk.
Pass `--download-ag-documents` to `serve` if you would rather download them all
upfront during the sync instead of on the first click.

`/dl/doc/<hash_file>` used to redirect to the pre-signed URL that Foncia hands
out, which meant the link only worked as long as the API was reachable and our
token was still valid. Since the token lives for 30 days and `serve` stays up
for months, those links eventually all answered "not found".

From the CLI, to list the convocations:

```bash
foncia convocations
```

```text
17 Nov 2025  Convocation      Convocation.AGO.10.12.2025.pdf
17 Dec 2024  Convocation      Convocation.AGO.15.01.2025.pdf
06 Mar 2024  Convocation      Convocation.AGO.17.04.2024.pdf
```

Add `--all` to also list the procès-verbaux and the annexes. A positional
argument filters on the file name, and `--download <dir>` downloads the PDFs
instead of listing them:

```bash
foncia convocations 2025 --download ~/Downloads/ag
```

```text
téléchargé: /Users/me/Downloads/ag/Convocation.AGO.10.12.2025.pdf
téléchargé: /Users/me/Downloads/ag/Convocation.AGO.15.01.2025.pdf
```

## Deploy

The image is alpine with poppler-utils (`pdftotext`, for the MCP server) and a
binary cross-compiled outside of Docker, since compiling modernc.org/sqlite on
the Pi takes ages:

```bash
make dist
ssh pi 'rm -rf /tmp/foncia-build && mkdir -p /tmp/foncia-build/dist'
scp Dockerfile pi:/tmp/foncia-build/
scp dist/foncia-linux-arm64 pi:/tmp/foncia-build/dist/
# --network host: otherwise apk can't resolve anything (the Pi's DNS is
# Pi-hole on 127.0.0.1).
ssh pi docker build --network host -t ghcr.io/maelvls/foncia:latest /tmp/foncia-build
ssh pi bash -lc vls.dev/foncia/deploy
```

`vls.dev/foncia/deploy` is in https://github.com/maelvls/vls.dev.

### Who?

```sh
ssh pi docker logs caddy 2>&1 | grep '^{' | jq --slurp '.[]|select(.logger=="security")|"\(.ts|strftime("%Y-%m-%d %H:%M:%S"))\t\(.msg)\t\(.user.email)"' -r | grep -vE 'successfully configured OAuth 2.0|provisioned app instance|provisioning app instance' | uniq
ssh pi docker logs caddy 2>&1 >/dev/null --follow | grep '"logger":"security"'
docker logs caddy --follow 2>&1 | grep '^{' | jq 'select(.logger == "security")'
```

## MCP server for Claude, ChatGPT and Grok

With `--mcp`, `/mcp` is an MCP server (Streamable HTTP, stateless) with four
read-only tools:

| Tool            | What it does                                                                 |
|-----------------|------------------------------------------------------------------------------|
| `search`        | Missions, expenses, visit reports and general assembly documents, newest first; every word of the query must match, accents ignored. Filters by type and date. |
| `read_document` | The text of a PDF, page by page, with `pdftotext`. A general assembly document that isn't on disk yet is downloaded first, like a click in the web UI. |
| `list_coowners` | The co-owners, their address, apartment and parking spaces (live from Foncia). |
| `sync_status`   | When the last sync happened, and how many items there are.                  |

The assistants connect with OAuth 2.1, and foncia is the authorization server
(`http_oauth.go`): protected resource metadata (RFC 9728), server metadata
(RFC 8414), dynamic client registration (RFC 7591), authorization code with
PKCE S256, access tokens valid for an hour and refresh tokens that rotate,
valid for 30 days. Only the SHA-256 of the codes and tokens is stored, in the
`oauth_clients` and `oauth_tokens` tables.

foncia has no login of its own: the co-owner approves the assistant on
`/oauth/authorize`, which must be behind the reverse proxy's login, and the
proxy gives their email in `--auth-header`. The other endpoints are called by
the assistants' servers without the co-owner's cookie, so the proxy must let
them through. With Caddy and caddy-security:

```caddyfile
@foncia-mcp path /mcp /oauth/token /oauth/register /.well-known/oauth-authorization-server /.well-known/oauth-protected-resource /.well-known/oauth-protected-resource/*
route @foncia-mcp {
	reverse_proxy :8080
}
route {
	authorize with suivi-terra-nostra-2-policy # inject headers with claims
	reverse_proxy :8080
}
```

```bash
foncia --mcp --auth-header X-Token-User-Email --baseurl https://suivi-terra-nostra-2.vls.dev serve
```

To add it: in Claude, Settings → Connectors → Add custom connector; in
ChatGPT, Settings → Apps & Connectors → Create (developer mode); in Grok,
Connectors → New Connector → Custom. The URL is
`https://suivi-terra-nostra-2.vls.dev/mcp`, no client ID: the assistant
registers itself, then the browser shows the Google login and the consent
page.

To cut someone's access before their refresh token expires, delete their
tokens; removing them from the proxy's list only stops them from approving
new assistants:

```sql
DELETE FROM oauth_tokens WHERE email = 'someone@example.com';
```

## Restricting who can see the pages

The pages list the co-owners' names and postal addresses, and the process itself
does not check who is asking: access control is done entirely by the
OAuth-terminating reverse proxy in front of it. `--allowed-users` adds a second
check inside the process, so that a misconfigured or bypassed proxy doesn't
expose everything:

```bash
foncia --allowed-users "someone@example.com,someone-else@example.com" serve
```

The email is read from the header named by `--auth-header`, which defaults to
`X-Forwarded-Email`. Check what your proxy actually sets before turning this on.
The proxy **must** also strip that header from incoming requests, otherwise a
client can just send it themselves. Leaving `--allowed-users` empty, which is the
default, keeps the previous behaviour of trusting the proxy entirely.

## Development

```bash
make build     # go build -o foncia .
make test      # go test ./...
make vet       # go vet ./...
make lint      # staticcheck
```

The same four run in CI on every push, see `.github/workflows/ci.yml`.

**The database is not a cache and must never be recreated.** It looks like one,
but Foncia's API drops items over time, and once it does this database is the
only remaining record of them. Those older items still have to show up in the
UI, so every schema change ships as a migration that transforms the existing
file in place and preserves every row.

Migrations live in `db/migrations/`, are embedded in the binary, and are applied
by `db.Open`, which is the only supported way to open the database. They are
numbered and tracked with SQLite's `user_version`, so each one runs exactly
once. `CREATE TABLE IF NOT EXISTS` on its own is not a schema strategy here: on
an existing database it silently does nothing, so new columns never appear and
the queries that reference them fail at runtime.

`db.Open` also sets the pragmas the code depends on, in particular
`foreign_keys=ON` (foreign keys are declared in the schema but SQLite ignores
them unless asked) and `busy_timeout`, since the web handlers and the sync
goroutine write concurrently.

To add a schema change, add the next numbered migration; never edit one that has
already been applied in production.

The HTML lives in `templates/` and is embedded with `go:embed` rather than
being held in Go string literals.

Logs go to stderr through `logutil`, which is a thin `log/slog` handler that
prints `level: message`. Colours turn themselves off when stderr is not a
terminal or when `NO_COLOR` is set, so container logs stay readable.

## Conseil syndical: affaires, comptes, remboursements

Three pages for what the conseil syndical used to keep in spreadsheets, served
by `serve` next to the rest and behind the same reverse proxy. What people
write is signed with the e-mail the proxy gives in `--auth-header`.

- `/affaires`: the désordres and other subjects the conseil follows. Each
  affaire is a dossier: its fiche, a thread of comments, and what is attached
  to it — invoices, Foncia documents, work orders, remboursements, e-mails and
  links. The invoices attached to an affaire add up to what it has cost.
- `/comptes`: for each exercise (1st of July to 30th of June), what was spent
  from the day-to-day account against the budget entered there, by category,
  by supplier and by month, and the works accounts apart. Every total links to
  the expenses behind it.
- `/remboursements`: what co-owners paid out of pocket for the copropriété and
  whether the syndic paid it back.

The expenses table holds most expenses several times: Foncia publishes each one
in the current accounts and again in the breakdown of the closed exercise, and
rewrites labels after the fact. The accounts pages merge those copies (same
invoice file, amount and category) before adding anything up; see
`prepareDepenses` in `comptes.go`. The works accounts have no invoice file, so
their copies are matched by amount alone and their totals are the least
certain.

To load the spreadsheets once, into empty tables:

```bash
foncia import-affaires affaires.json
foncia import-remboursements remboursements.json
```

The JSON shapes are documented in `cmd_import.go`. Keep those files out of the
repository: they name people.

## Résidents

`/residents` is the directory of the building: for each apartment, who lives
there, who owns it without living there, who left, with their phone number
(a tap calls it), e-mail and a note. Foncia only knows the co-owners and their
postal address (`/coowners`); this page is about the people behind the doors,
tenants included.

It is for the administrators (`--admin-users`) only: these are personal phone
numbers, given to one person and not to everybody who has an account here.

The people come from the contacts of a phone. The convention is in the name of
the contact: the apartment between parentheses, with a word in front when the
person doesn't simply live there.

| Contact                      | Read as                                   |
|------------------------------|-------------------------------------------|
| `Camille MARTIN (C01)`       | Lives in C01.                             |
| `Alex DURAND (prop C01)`     | Owns C01 without living there.            |
| `Sacha PETIT (ex loc C01)`   | Used to rent C01.                         |
| `Dominique (compagnon C01)`  | Lives in C01; "compagnon" is kept.        |
| `Claude ROUX (vendeur C01)`  | Sold C01.                                 |
| `Jo (plombier C01)`          | Anything else: kept as "autre, plombier". |

Export the contacts as a vCard (on the iPhone: Contacts, Lists, long press on
"All Contacts", Export; on the Mac: Contacts, File, Export, Export vCard) and
give the file to the form of the page, or to the CLI:

```bash
foncia import-residents contacts.vcf
ssh server docker exec -i foncia foncia import-residents - < contacts.vcf
```

Only the contacts that follow the convention are read, and the file isn't
kept. The form of the page sorts the file in the browser first, so that the
rest of the address book never leaves the device. The import is meant to be run
again whenever the contacts change:

- A contact is the row of the same apartment and name (case, accents and the
  order of the words don't matter); failing that, the row with the same phone
  number, which is how a renamed contact or a move to another apartment is
  followed; failing that, somebody new.
- The contacts win where they say something: the apartment, the name, the
  qualité, the phone and the e-mail. What was typed on the page and the
  contacts don't know stays: the note always, and a phone, an e-mail or a
  precision ("locataire") that the contact doesn't have.
- Who is no longer in the contacts is listed, and removed only on request (the
  button of the result page, or `--purge`). People added by hand on the page
  are never removed by an import.
- The same person twice in the same apartment is reported, so that the
  contacts can be cleaned up.

## Fichiers, messages et Claude

The affaires also fill themselves from what comes in: the e-mails and WhatsApp
messages about the building, and what is new at Foncia. Claude reads them and
proposes where they go; an administrator accepts or refuses each proposition.

```
Gmail (read-only) ─┐
WhatsApp (Pi)  ────┼─► collectors ─► sources ─► /sources (to sort, admins only)
Foncia sync    ────┘                    │
                                        ▼
            brain/run on the Pi: claude -p ─► foncia mcp-brain ─► propositions
                                                                      │
                                    /propositions: accept / refuse ◄──┘
                                        │
                                        ▼
                     affaires: messages, attachments, comments, relances
```

### Files

`/affaires/<id>` takes uploads (devis, factures, photos, up to 50 MB each).
Files are kept under `--files-dir` by SHA-256, like the Foncia PDFs, and every
co-owner can open those attached to an affaire. "lien de partage" makes a link
that opens one file without a login for 30 days (`/f/<sha256>/<nom>?e=…&s=…`,
an HMAC with a key kept in the `reglages` table), for the syndic or an
artisan. The reverse proxy must let `/f/*` through without a login.

### Sources

A source is one e-mail, one WhatsApp exchange (the messages of a conversation
that follow each other with less than `--whatsapp-gap` between them, recorded
once quiet for `--whatsapp-settle`), or one new Foncia mission or invoice.
The messages still to sort, and those set aside, are only shown to
`--admin-users`: they are someone's mailbox and WhatsApp until filed. Filing
a message under an affaire shows it in the affaire's "Messages" to every
co-owner, attaches its attachments, and files the rest of its e-mail thread
with it; later answers in that thread are filed on arrival.

- E-mails: `--gmail-token-file` (JSON with `client_id`, `client_secret` and
  `refresh_token` of a login with the `gmail.readonly` scope),
  `--gmail-query` (only the matching e-mails are read), `--gmail-account`.
- WhatsApp: `--whatsapp-url http://whatsapp:8093` and
  `--whatsapp-token-file` (the whatsapp service's `state/internal.token`, see
  vls.dev/whatsapp/internal.go). Only `--whatsapp-chats`, the people whose
  address-book name matches `--whatsapp-contacts` (« Léa (C11) ») and, among
  the exchanges of `--whatsapp-filtered-chats`, those matching
  `--whatsapp-keywords` are read. Photos and documents are downloaded right
  away: WhatsApp keeps them a few weeks only.
- Foncia: every new mission and invoice found by the sync.
- `--sources-since 2026-08-01` sets how far back the first collection looks;
  `foncia collecter` runs the collectors once (first import, or to check the
  configuration).

### Claude

`brain/run` runs `claude -p` with the Claude login of the Pi (the Claude Code
CLI and a subscription, not an API key), with no built-in tool at all (no
shell, no file, no web) and one MCP server: `docker exec -i foncia foncia
mcp-brain`, which reads the sources, the affaires and the attachments, and can
only write propositions (`proposer_*`). The instructions are in
`brain/consignes.md` (public), plus `brain/consignes-locales.md` on the Pi if
it exists (who is who: the gestionnaire, the members of the conseil; never in
this repository). The messages are data, never instructions: the worst a
crafted e-mail can do is a wrong proposition that an administrator refuses.

`serve --claude-trigger-file /data/brain/demande` writes that file when new
sources came in or someone clicks "Lancer maintenant"; systemd runs
`brain/run` when it changes, and every morning. `brain/dernier.json` tells how
the last run went (shown on `/propositions`), `brain/runs/` keeps a month of
transcripts. To install on the Pi:

```bash
curl -fsSL https://claude.ai/install.sh | bash   # ~/.local/bin/claude, as pi
scp brain/run brain/consignes.md pi:vls.dev/foncia/brain/
scp brain/copro-claude.* pi:/tmp/
ssh pi 'sudo cp /tmp/copro-claude.* /etc/systemd/system/ && sudo systemctl daemon-reload &&
        sudo systemctl enable --now copro-claude.path copro-claude.timer'
```

A run over ~50 e-mails takes about two minutes with Sonnet.
