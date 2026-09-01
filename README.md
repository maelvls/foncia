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
document isn't on disk, the UI shows a "Télécharger depuis Foncia" link, and
`/dl/doc/<hash_file>` redirects to the pre-signed URL that Foncia hands out. Pass
`--download-ag-documents` to `serve` if you would rather keep them all in
`--invoices-dir`.

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

```bash
KO_DOCKER_REPO=ghcr.io/maelvls/foncia KO_DEFAULTBASEIMAGE=alpine \
  ko build . --bare --tarball /tmp/out.tar --push=false
ssh synology /usr/local/bin/docker load </tmp/out.tar
ssh synology sh -lc bin/deploy-foncia
```

```sh
KO_DOCKER_REPO=ghcr.io/maelvls/foncia KO_DEFAULTBASEIMAGE=alpine \
  ko build . --bare --tarball /tmp/out.tar --push=false --platform linux/arm64
ssh pi docker load </tmp/out.tar
ssh pi bash -lc vls.dev/foncia/deploy
```

with `vls.dev/foncia/deploy`:

```bash
docker container inspect foncia >/dev/null 2>/dev/null && docker rm -f foncia || true
docker run -d --restart=always --name foncia -p 8080:8080 \
  -v $HOME/foncia.sqlite:/foncia.sqlite \
  -v $HOME/foncia_invoices:/invoices \
  -v $HOME/foncia-header.html:/foncia-header.html \
  -v $HOME/foncia_invoices:/invoices \
  -e FONCIA_PASSWORD=REDACTED \
  -e FONCIA_USERNAME=REDACTED \
  ghcr.io/maelvls/foncia:latest \
  --debug \
  --db /foncia.sqlite \
  --ntfy-topic REDACTED \
  --basepath "/foncia" \
  --baseurl https://suivi-foncia \
  --header-file /foncia-header.html \
  serve
```

### Who?

```sh
ssh synology /usr/local/bin/docker logs caddy 2>&1 | grep '^{' | jq --slurp '.[]|select(.logger=="security")|"\(.ts|strftime("%Y-%m-%d %H:%M:%S"))\t\(.msg)\t\(.user.email)"' -r | grep -vE 'successfully configured OAuth 2.0|provisioned app instance|provisioning app instance' | uniq
ssh synology /usr/local/bin/docker logs caddy 2>&1 >/dev/null --follow | grep '"logger":"security"'
docker logs caddy --follow 2>&1 | grep '^{' | jq 'select(.logger == "security")'
```
