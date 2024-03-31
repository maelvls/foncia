# The `foncia` CLI

The `foncia` CLI lets you list all "missionRepairs" and "missionIncidents". It
also lets you create a server that notifies you using ntfy.sh when a new
"missionIncident" or "missionRepair" is created.

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
