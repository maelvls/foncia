# The `foncia` CLI

The `foncia` CLI lets you list all "missionRepairs" and "missionIncidents". It
also lets you create a server that notifies you using ntfy.sh when a new
"missionIncident" or "missionRepair" is created.

I've created this for two reasons:

1. I wanted to be aware of anything happening in my building, preferably in
   real-time on my phone.
2. I found that the `description` field of "missionIncidents" and
   "missionRepairs" had disappeared since the migration from the old myFoncia
   website to the new "fonciamillenium" website, and I found that I could access
   that field using the GraphQL API.

## Deploy

```bash
KO_DOCKER_REPO=ghcr.io/maelvls/foncia KO_DEFAULTBASEIMAGE=alpine \
  ko build . --bare --tarball /tmp/out.tar --push=false
ssh remote /usr/local/bin/docker load </tmp/out.tar
ssh remote sh -lc bin/deploy-foncia
```

with `bin/deploy-foncia`:

```bash
docker container inspect foncia >/dev/null 2>/dev/null && docker rm -f foncia || true
docker run -d --restart=always --name foncia -p 8080:8080 -v $HOME/foncia.sqlite:/foncia.sqlite \
  -e FONCIA_PASSWORD=REDACTED \
  -e FONCIA_USERNAME=REDACTED \
  ghcr.io/maelvls/foncia:latest \
  --debug \
  --db /foncia.sqlite \
  --ntfy-topic REDACTED \
  serve
```
