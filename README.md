# The `foncia` CLI

The `foncia` CLI lets you list all "missionRepairs" and "missionIncidents". It
also lets you create a server that notifies you when a new "missionIncident",
"missionRepair" or invoice is created (see [Notifications](#notifications)).
Example:

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

With `--mcp`, `/mcp` is an MCP server (Streamable HTTP, stateless) with five
read-only tools:

| Tool            | What it does                                                                 |
|-----------------|------------------------------------------------------------------------------|
| `search`        | Missions, expenses, visit reports and general assembly documents, newest first; every word of the query must match, accents ignored. Filters by type and date. |
| `read_document` | The text of a PDF, page by page, with `pdftotext`. A general assembly document that isn't on disk yet is downloaded first, like a click in the web UI. |
| `list_coowners` | The co-owners, their address, apartment and parking spaces (live from Foncia). |
| `sync_status`   | When the last sync happened, and how many items there are.                  |
| `changes`       | What appeared or changed, after a cursor (see [API for the services of the house](#api-for-the-services-of-the-house)). |

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

## Notifications

After each sync, `foncia serve` tells what is new at Foncia: the new missions
("Nouvelle intervention") and the new invoices ("Nouvelle facture"). Nothing is
sent for the first sync of an empty database.

**From the site (Web Push).** Each person turns the notifications on, one
device at a time, on the page **Notifications** (`/notifications`), picks the
kinds of news, can send a test, and removes a device from there. On an iPhone or
an iPad, the site must first be installed on the home screen (Share → "Sur
l'écran d'accueil"), which the web manifest allows; Apple gives no notifications
to a site open in a Safari tab.

- A sync that finds one mission or one invoice sends it with its label, and a
  click opens its row; a sync that finds several sends one notification per
  kind ("5 nouvelles factures", the first ones listed), which opens the list.
- Each message is encrypted for the device (RFC 8291) and posted to the push
  service of its browser (Apple, Google, Mozilla), which can't read it.
- The devices are in the `push_abonnements` table, each with the e-mail given by
  `--auth-header`; a device whose push service answers 404 or 410 is removed.
  The server's VAPID keys are made at the first start and kept in `reglages`
  (`push_vapid`): losing the database cuts every subscription, and each device
  has to be turned on again.
- The push services want to know who runs the server: `--push-contact` (an
  e-mail or an https URL), which defaults to `--baseurl`. Apple refuses anything
  else than an https URL or an e-mail.
- The reverse proxy must serve `/sw.js`, `/push.js`, `/manifest.webmanifest` and
  `/api/push*` like the pages (behind the login), and the icons
  (`/icon.png`, `/apple-touch-icon.png`, `/favicon.svg`), which are not in the
  binary.
- Somebody removed from the reverse proxy's list keeps getting the
  notifications of the devices they turned on, since foncia doesn't know that
  list: delete their rows (`DELETE FROM push_abonnements WHERE email = '…'`),
  or give the list with `--allowed-users`, which the notifications follow.

**With Ntfy.** `--ntfy-topic` also sends each new mission and invoice to that
topic of <https://ntfy.sh>, for whoever follows it with the Ntfy app. A topic is
public to anybody who knows its name. Empty (the default) sends nothing there.

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

## What the site shows

The site is a mirror of what Foncia publishes on
<https://my-foncia.fonciamillenium.net/>, kept up to date by the sync every
`--sync-period`, and nothing else:

- `/`: the missions (interventions, with their work orders), the invoices and
  the documents (visit reports, general assembly documents), newest first.
- `/comptes`: for each exercise (1st of July to 30th of June), what was spent
  from the day-to-day account against the budget entered there, by category,
  by supplier and by month, and the works accounts apart. Every total links to
  the expenses behind it.
- `/coproprietaires`: the co-owners as Foncia knows them, with their postal
  address, apartment and parking spaces, asked from Foncia at most once an
  hour (the last answer is shown when Foncia doesn't answer). `/residents` and
  `/coowners`, their former pages, lead there.
- `/notifications`, see [Notifications](#notifications).

The expenses table holds most expenses several times: Foncia publishes each one
in the current accounts and again in the breakdown of the closed exercise, and
rewrites labels after the fact. The accounts pages merge those copies (same
invoice file, amount and category) before adding anything up; see
`prepareDepenses` in `comptes.go`. The works accounts have no invoice file, so
their copies are matched by amount alone and their totals are the least
certain.

Until 2026-11-27 the site also kept the affaires of the conseil syndical, the
remboursements, the residents from a phone's address book, and collected the
e-mails and WhatsApp messages about the building for Claude to sort. Filing
those is now the job of an agent of its own, which follows this site through
`/api/v1`. Their tables (`affaires*`, `remboursements`, `residents`,
`sources*`, `fichiers`, `propositions`) are still in the database, untouched;
the flags of the collectors (`--gmail-*`, `--whatsapp-*`, `--admin-users`…)
are accepted and ignored.

## API for the services of the house

`/api/v1` is for the other services of the house, the agent that files the
pieces of the copropriété in a knowledge base first. They call it as
themselves, with the workload identity that the house's issuer
(vls.dev/oidc) signs for them every 10 minutes: no token to share or keep.

| Endpoint | What it gives |
|---|---|
| `GET /api/v1/changements?depuis=<seq>&attendre=<s>&limite=<n>` | What appeared or changed in the mirror, oldest first, after the cursor `depuis`. |
| `GET /api/v1/fichiers/<typ>/<id>` | A PDF, the `fichier` of a change. A general assembly document that isn't on disk yet is downloaded from Foncia first. |
| `GET /api/v1/etat` | When the last sync happened, whether it failed, and the end of the journal. |

**The journal.** Every mission, work order, expense, account document and
contract that appears or changes gets a row in the `changements` table, numbered
in order (`seq`). The rows are written by SQLite triggers
(`db/migrations/0008_changements.sql`), so every way a row is written lands
there, and the sync's upserts, which rewrite the same values every few minutes,
write nothing when nothing changed. What the database held before is in the
journal first, oldest first, as `existant`: a reader that starts from 0 replays
eleven years of history, then follows what comes.

```json
{
  "curseur": 3105,
  "fin": 3105,
  "changements": [
    {
      "seq": 3105, "at": "2026-11-27T09:10:02.512Z",
      "type": "expense", "id": "a1b2…", "action": "nouveau",
      "objet": {"libelle": "ACME - CONTRAT", "montant_centimes": 41049, "date": "2026-11-26T00:00:00Z", "compte": "accounting", "…": "…"},
      "fichier": "/api/v1/fichiers/invoice/66eda6344b41c38804f77fc1"
    }
  ]
}
```

- The reader keeps `curseur` and gives it back as `depuis`. Nothing is lost
  while it is away. `curseur < fin` means there is more to read right away.
  `depuis=fin` starts from now.
- `objet` is the thing as it is now, not as it was when the row was written.
  An invoice whose PDF was downloaded after it appeared comes back as
  `modifie`, with `pdf_telecharge` now true.
- `attendre` (seconds, at most 50) makes it a long poll: when nothing comes
  after the cursor, the answer waits for something to come, and leaves empty
  otherwise. A reader loops on it; no websocket, nothing to reconnect.
- `limite`: 200 changes by default, 1000 at most.

**Who may call.** A call is let through (`workload.go`, the same check as
vls.dev/whatsapp) when its `Authorization: Bearer` token is signed (ES256) by
the issuer, whose public keys are in `--workload-jwks`; when it has the
issuer's `iss` (`--workload-issuer`, `https://vls.dev`), this service as `aud`
(`--workload-audience`, by default `--baseurl`), and a `sub` named in
`--api-callers`; and when it didn't come through the reverse proxy: a request
that carries `X-Forwarded-For` is refused even with a good token. Without
`--workload-jwks`, there is no `/api/v1`.

```bash
foncia --workload-jwks /run/oidc/.well-known/jwks.json --api-callers docker:residence \
  --baseurl https://suivi-terra-nostra-2.vls.dev serve
```

On the caller's side: `residence@https://suivi-terra-nostra-2.vls.dev` in the
command of oidc's compose, `/run/oidc/residence/suivi-terra-nostra-2.vls.dev`
mounted read-only, and its `token` file read again at each call.

The same journal is the MCP tool `changes`, for the assistants.
