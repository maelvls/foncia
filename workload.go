package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/maelvls/foncia/logutil"
)

// The other services of the house call /api/v1 (api_v1.go) as themselves:
// each sends the short JWT that the house's issuer signs for it every 10
// minutes, its workload identity, made for this service alone (see
// vls.dev/oidc/README.md, "Between the services of the house"; the same check
// as vls.dev/whatsapp/workload.go). No token is shared, so there is none to
// keep or to change when it leaks.
//
// A call is let through when its token:
//
//   - is signed (ES256) by the issuer: the public key is the one the issuer
//     writes into a JWKS file (--workload-jwks), mounted read-only. No
//     network is needed to check a token;
//   - has the issuer's iss (--workload-issuer), and isn't expired;
//   - has this service as its aud (--workload-audience, by default
//     --baseurl), so that a token good elsewhere is refused here;
//   - has a sub, docker:<service>, among --api-callers;
//
// and when it didn't come through the reverse proxy: a request that carries
// X-Forwarded-For is refused even with a good token, so that a token alone is
// not enough from the Internet.

type workloads struct {
	jwks     string // The issuer's public keys, a JWKS file.
	issuer   string // https://vls.dev
	audience string // https://suivi-terra-nostra-2.vls.dev
	now      func() time.Time

	mu   sync.Mutex
	keys map[string]*ecdsa.PublicKey // By kid.
	read time.Time
}

func newWorkloads(jwks, issuer, audience string) *workloads {
	return &workloads{jwks: jwks, issuer: issuer, audience: audience, now: time.Now}
}

// maxWorkloadToken is more than any token of the issuer (about 350 bytes).
const maxWorkloadToken = 4096

// clockLeeway is how far in the future a token may start: the issuer is on
// the same machine, whose clock NTP may still step.
const clockLeeway = 30 * time.Second

// verify checks a token and gives who it names: its sub, docker:residence.
func (w *workloads) verify(token string) (string, error) {
	if len(token) > maxWorkloadToken {
		return "", errors.New("the token is too long")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("not a JWT")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	cb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if errors.Join(err1, err2, err3) != nil {
		return "", errors.New("not a JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hb, &header) != nil {
		return "", errors.New("not a JWT")
	}
	// The only algorithm of the issuer: "none" and the symmetric ones,
	// which would take the public key for a secret, never get further.
	if header.Alg != "ES256" {
		return "", fmt.Errorf("alg %q, not ES256", header.Alg)
	}
	key := w.key(header.Kid)
	if key == nil {
		return "", fmt.Errorf("signed with a key (kid %q) that isn't the issuer's", header.Kid)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return "", errors.New("bad signature")
	}

	var claims struct {
		Iss string      `json:"iss"`
		Sub string      `json:"sub"`
		Aud jwtAudience `json:"aud"`
		Exp float64     `json:"exp"`
		Nbf float64     `json:"nbf"`
	}
	if json.Unmarshal(cb, &claims) != nil {
		return "", errors.New("claims that can't be read")
	}
	now := w.now()
	switch {
	case claims.Iss != w.issuer:
		return "", fmt.Errorf("iss %q, not %s", claims.Iss, w.issuer)
	case !slices.Contains(claims.Aud, w.audience):
		return "", fmt.Errorf("made for %q, not for %s", strings.Join(claims.Aud, ", "), w.audience)
	case claims.Exp == 0:
		return "", errors.New("no exp")
	case !now.Before(time.Unix(int64(claims.Exp), 0)):
		return "", fmt.Errorf("expired %s ago", now.Sub(time.Unix(int64(claims.Exp), 0)).Round(time.Second))
	case now.Add(clockLeeway).Before(time.Unix(int64(claims.Nbf), 0)):
		return "", errors.New("not valid yet")
	case claims.Sub == "":
		return "", errors.New("no sub")
	}
	return claims.Sub, nil
}

// jwtAudience is a JWT's aud: a string, or a list of them.
type jwtAudience []string

func (a *jwtAudience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = jwtAudience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// key gives the issuer's key of that kid. The file is read at the first
// token, and again when a kid is new: the issuer got another key. Not more
// than every few seconds, so that tokens signed by anyone don't make the file
// read in a loop.
func (w *workloads) key(kid string) *ecdsa.PublicKey {
	w.mu.Lock()
	defer w.mu.Unlock()
	if k := w.keys[kid]; k != nil {
		return k
	}
	if now := w.now(); w.read.IsZero() || now.Sub(w.read) > 5*time.Second {
		w.read = now
		keys, err := readJWKS(w.jwks)
		if err != nil {
			logutil.Errorf("api: the issuer's public keys: %v", err)
			return nil
		}
		w.keys = keys
	}
	return w.keys[kid]
}

// readJWKS reads the P-256 keys of a JWKS file, by kid.
func readJWKS(path string) (map[string]*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		x, errx := base64.RawURLEncoding.DecodeString(k.X)
		y, erry := base64.RawURLEncoding.DecodeString(k.Y)
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" || errx != nil || erry != nil || len(x) != 32 || len(y) != 32 {
			continue
		}
		// Refuses a point that isn't on the curve.
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), slices.Concat([]byte{4}, x, y))
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no ES256 key in it", path)
	}
	return keys, nil
}

// calledBy lets through the calls of the services named in may (their sub,
// docker:residence), from the machine only.
func calledBy(w *workloads, may []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case w == nil || len(may) == 0:
			// Nobody may: there is no such endpoint.
			http.NotFound(rw, r)
			return
		case r.Header.Get("X-Forwarded-For") != "":
			http.Error(rw, "not from outside the machine", http.StatusForbidden)
			return
		case !ok:
			http.Error(rw, "unauthorized: Authorization: Bearer <the caller's workload token for "+w.audience+">", http.StatusUnauthorized)
			return
		}
		sub, err := w.verify(strings.TrimSpace(token))
		if err != nil {
			// Why, to the caller too: it is on the machine, and a refusal
			// with no reason is the hard one to fix.
			logutil.Errorf("api: %s %s refused: %v", r.Method, r.URL.Path, err)
			http.Error(rw, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if !slices.Contains(may, sub) {
			logutil.Errorf("api: %s %s refused: %s may not", r.Method, r.URL.Path, sub)
			http.Error(rw, sub+" may not do this", http.StatusForbidden)
			return
		}
		logutil.Infof("api: %s %s by %s", r.Method, r.URL.RequestURI(), sub)
		next.ServeHTTP(rw, r)
	})
}

// subjects reads a list of who may call, "docker:residence,docker:aspi".
func subjects(list string) []string {
	var out []string
	for _, s := range strings.Split(list, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
