#!/usr/bin/env python3
"""Makes the read-only Gmail token of --gmail-token-file.

Opens the browser on Google's consent page for the gmail.readonly scope only,
with the OAuth client of a Desktop app (its client_secret.json, e.g. the one
of gws: ~/.config/gw/profiles/<profile>/gws/client_secret.json), and writes
{client_id, client_secret, refresh_token} to the output file (0600):

    python3 brain/gmail-token.py client_secret.json mael.valais@gmail.com gmail-token.json
    scp gmail-token.json pi:vls.dev/foncia/ && rm gmail-token.json

The token can read the mailbox, nothing else: it can't send, delete or label.
Revoke it at https://myaccount.google.com/permissions.
"""
import http.server
import json
import os
import secrets
import sys
import urllib.parse
import urllib.request
import webbrowser

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    secret_path, account, out = sys.argv[1:]
    with open(secret_path) as f:
        c = json.load(f)
    c = c.get("installed") or c.get("web") or c
    state = secrets.token_urlsafe(16)
    got = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("state", [""])[0] != state:
                self.send_response(400)
                self.end_headers()
                return
            got.update({k: v[0] for k, v in q.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write("C'est bon, vous pouvez fermer cet onglet.".encode())

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    redirect = "http://127.0.0.1:%d/" % srv.server_port
    url = c.get("auth_uri", "https://accounts.google.com/o/oauth2/auth") + "?" + urllib.parse.urlencode({
        "client_id": c["client_id"], "redirect_uri": redirect, "response_type": "code", "scope": SCOPE,
        "access_type": "offline", "prompt": "consent", "login_hint": account, "state": state,
    })
    print("Si le navigateur ne s'ouvre pas :\n" + url, file=sys.stderr)
    webbrowser.open(url)
    while "code" not in got and "error" not in got:
        srv.handle_request()
    if "error" in got:
        sys.exit("refusé : " + got["error"])

    body = urllib.parse.urlencode({
        "code": got["code"], "client_id": c["client_id"], "client_secret": c["client_secret"],
        "redirect_uri": redirect, "grant_type": "authorization_code",
    }).encode()
    tok = json.load(urllib.request.urlopen(c.get("token_uri", "https://oauth2.googleapis.com/token"), body))
    if tok.get("scope", "").split() != [SCOPE]:
        print("attention : portées accordées : " + tok.get("scope", ""), file=sys.stderr)
    if "refresh_token" not in tok:
        sys.exit("pas de refresh_token dans la réponse")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"client_id": c["client_id"], "client_secret": c["client_secret"], "refresh_token": tok["refresh_token"]}, f)
    print("écrit : " + out, file=sys.stderr)


main()
