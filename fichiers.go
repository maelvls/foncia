package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/maelvls/foncia/db"
)

// The files of the affaires (devis, factures, photos, attachments of the
// messages) are kept on the disk of the server, named by their SHA-256, like
// the PDFs of Foncia: no Google Drive to log into, and they are in the backup
// of the Pi with the rest.

var (
	filesDir   = flag.String("files-dir", "fichiers", "Directory where the files of the affaires (uploads, attachments of the collected e-mails and WhatsApp messages) are kept, by SHA-256.")
	adminUsers = flag.String("admin-users", "", "Comma-separated e-mails (from --auth-header) that see the collected messages still to sort and Claude's propositions. Everybody else only sees what is attached to an affaire. Empty means nobody, except when there is no authenticating proxy at all (local runs).")
)

// maxFichier is the size above which a file is refused: phone videos have no
// business in an affaire, and the Pi's disk is not infinite.
const maxFichier = 50 << 20

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// cheminFichier is where a file lives on disk.
func cheminFichier(sha string) string {
	return filepath.Join(*filesDir, sha[:2], sha)
}

// errTropGros is returned when a file is larger than maxFichier.
var errTropGros = fmt.Errorf("fichier de plus de %d Mo", maxFichier>>20)

// stockerFichier writes the content to the store (once per content) and
// records it. The MIME type is the one given, else guessed from the name, else
// from the content.
func stockerFichier(ctx context.Context, sqlDB *sql.DB, r io.Reader, nom, typ string, origine db.FichierOrigine, auteur string) (db.FichierDB, error) {
	if err := os.MkdirAll(*filesDir, 0o755); err != nil {
		return db.FichierDB{}, fmt.Errorf("while creating %s: %w", *filesDir, err)
	}
	tmp, err := os.CreateTemp(*filesDir, ".envoi-*")
	if err != nil {
		return db.FichierDB{}, fmt.Errorf("while creating a temporary file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer tmp.Close()

	h := sha256.New()
	var head [512]byte
	n, err := io.ReadFull(r, head[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return db.FichierDB{}, fmt.Errorf("while reading %s: %w", nom, err)
	}
	if _, err := io.MultiWriter(tmp, h).Write(head[:n]); err != nil {
		return db.FichierDB{}, err
	}
	rest, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, maxFichier-int64(n)+1))
	if err != nil {
		return db.FichierDB{}, fmt.Errorf("while writing %s: %w", nom, err)
	}
	taille := int64(n) + rest
	if taille > maxFichier {
		return db.FichierDB{}, errTropGros
	}
	if err := tmp.Close(); err != nil {
		return db.FichierDB{}, err
	}

	sha := hex.EncodeToString(h.Sum(nil))
	dest := cheminFichier(sha)
	if _, err := os.Stat(dest); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return db.FichierDB{}, err
		}
		if err := os.Rename(tmp.Name(), dest); err != nil {
			return db.FichierDB{}, fmt.Errorf("while moving %s into the store: %w", nom, err)
		}
	}

	f := db.FichierDB{
		SHA256:  sha,
		Nom:     nomPropre(nom),
		Mime:    devinerType(nom, typ, head[:n]),
		Taille:  taille,
		Origine: origine,
		Auteur:  auteur,
	}
	if err := db.InsertFichier(ctx, sqlDB, f); err != nil {
		return db.FichierDB{}, err
	}
	// The row may predate this upload: what counts is what is recorded.
	return db.GetFichier(ctx, sqlDB, sha)
}

func devinerType(nom, typ string, head []byte) string {
	typ, _, _ = mime.ParseMediaType(typ)
	if typ != "" && typ != "application/octet-stream" {
		return typ
	}
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(nom))); t != "" {
		t, _, _ = mime.ParseMediaType(t)
		return t
	}
	t, _, _ := mime.ParseMediaType(http.DetectContentType(head))
	return t
}

// nomPropre keeps what makes a file name readable and drops what could do
// harm in a header or a path.
func nomPropre(nom string) string {
	nom = filepath.Base(strings.ReplaceAll(nom, "\\", "/"))
	nom = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '/' {
			return -1
		}
		return r
	}, nom)
	nom = strings.TrimSpace(nom)
	if nom == "" || nom == "." || nom == ".." || !utf8.ValidString(nom) {
		return "fichier"
	}
	return nom
}

// servirFichier sends a file of the store, shown in the browser when it can
// be (PDF, image), downloaded otherwise.
func servirFichier(w http.ResponseWriter, r *http.Request, f db.FichierDB) {
	fh, err := os.Open(cheminFichier(f.SHA256))
	if err != nil {
		http.Error(w, "fichier absent du disque", http.StatusNotFound)
		return
	}
	defer fh.Close()
	disposition := "attachment"
	if f.IsPDF() || f.IsImage() || strings.HasPrefix(f.Mime, "text/plain") {
		disposition = "inline"
	}
	w.Header().Set("Content-Type", f.Mime)
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": f.Nom}))
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// A stored file is served from our origin: it must not be able to run
	// scripts there (an HTML or SVG attachment from an e-mail, say).
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; object-src 'self'; plugin-types application/pdf")
	http.ServeContent(w, r, f.Nom, f.CreatedAt, fh)
}

// -----------------------------------------------------------------------------
// Liens de partage
// -----------------------------------------------------------------------------

// A share link lets somebody without an account (the syndic, an artisan) open
// one file until a date: /f/<sha256>/<nom>?e=<unix>&s=<signature>. The
// signature is an HMAC of the file and the date, with a key kept in the
// database.

const dureePartage = 30 * 24 * time.Hour

type partage struct{ cle []byte }

func chargerPartage(ctx context.Context, sqlDB *sql.DB) (partage, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return partage{}, err
	}
	cle, err := db.InitReglage(ctx, sqlDB, "partage_cle", hex.EncodeToString(b[:]))
	if err != nil {
		return partage{}, err
	}
	raw, err := hex.DecodeString(cle)
	if err != nil || len(raw) < 16 {
		return partage{}, fmt.Errorf("the share-link key in reglages is invalid")
	}
	return partage{cle: raw}, nil
}

func (p partage) signature(sha string, exp int64) string {
	m := hmac.New(sha256.New, p.cle)
	_, _ = fmt.Fprintf(m, "%s|%d", sha, exp)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

// lien is the path (under the base path) of a share link valid until exp.
func (p partage) lien(f db.FichierDB, exp time.Time) string {
	e := exp.Unix()
	return "/f/" + f.SHA256 + "/" + url.PathEscape(f.Nom) + "?e=" + strconv.FormatInt(e, 10) + "&s=" + p.signature(f.SHA256, e)
}

// valide checks a share link. The date is checked after the signature so that
// an expired link is told apart from a forged one only for real links.
func (p partage) valide(sha, e, s string, now time.Time) (bool, string) {
	exp, err := strconv.ParseInt(e, 10, 64)
	if err != nil || !hmac.Equal([]byte(s), []byte(p.signature(sha, exp))) {
		return false, "Ce lien n'est pas valide."
	}
	if now.Unix() > exp {
		return false, "Ce lien a expiré le " + time.Unix(exp, 0).In(paris).Format("02/01/2006") + ". Demandez-en un nouveau."
	}
	return true, ""
}
