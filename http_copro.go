package main

import (
	"bytes"
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// What the pages of the conseil syndical (affaires, comptes, remboursements)
// share: one template set, one navigation bar, and who is looking.

//go:embed templates/copro/*.html
var coproFS embed.FS

var coproTmpl = template.Must(template.New("copro").Funcs(template.FuncMap{
	"quand":    func(t time.Time) string { return t.In(paris).Format("02/01/2006 à 15:04") },
	"jour":     func(t time.Time) string { return t.In(paris).Format("02/01/2006") },
	"exercice": nomExercice,
	"positif":  func(a db.Amount) db.Amount { return max(a, -a) },
	"taille":   taille,
	"brainCtx": func(basePath string, e brainEtat) any {
		return struct {
			brainEtat
			BasePath string
		}{e, basePath}
	},
	"chemin": url.PathEscape,
	// The "message" sub-template shows one collected message, in the lists
	// and in the dossier of an affaire (where it can be detached).
	"messageCtx": func(basePath, affaireID string, s db.SourceDB, lienID string) any {
		return struct {
			BasePath  string
			AffaireID string
			LienID    string
			S         db.SourceDB
		}{basePath, affaireID, lienID, s}
	},
	"tableRemboursements": func(basePath string, lignes []db.RemboursementDB) any {
		return struct {
			BasePath string
			Lignes   []db.RemboursementDB
		}{basePath, lignes}
	},
	// A sub-template only sees what it is given, and it needs the base path
	// along with the rows.
	"tableAffaires": func(basePath string, lignes []affaireLigne) any {
		return struct {
			BasePath string
			Lignes   []affaireLigne
		}{basePath, lignes}
	},
}).ParseFS(coproFS, "templates/copro/*.html"))

// taille is a file size for humans.
func taille(n int64) string {
	switch {
	case n >= 1<<20:
		return strings.Replace(fmt.Sprintf("%.1f Mo", float64(n)/(1<<20)), ".", ",", 1)
	case n >= 1<<10:
		return fmt.Sprintf("%d ko", n>>10)
	}
	return fmt.Sprintf("%d o", n)
}

// page is embedded in the data of every template.
type page struct {
	BasePath string
	User     string
	Section  string
	Flash    string

	// For the administrators (--admin-users) only: the collected messages
	// still to sort and Claude's propositions waiting for a decision.
	Admin         bool
	NATrier       int
	NPropositions int
}

const utilisateurInconnu = "inconnu"

// currentUser is the e-mail the reverse proxy authenticated. Without a proxy
// (local runs, tests) everybody is "inconnu".
func currentUser(r *http.Request) string {
	u := strings.TrimSpace(strings.ToLower(r.Header.Get(*authHeader)))
	if u == "" {
		return utilisateurInconnu
	}
	return u
}

type copro struct {
	sqlDB    *sql.DB
	basePath string
	baseURL  string  // With the base path; for the share links.
	partage  partage // The key of the share links; zero in the pages that make none.
	brain    brainTrigger
}

func (c copro) page(r *http.Request, section string) page {
	p := page{BasePath: c.basePath, User: currentUser(r), Section: section, Flash: r.URL.Query().Get("flash")}
	if isAdmin(r) {
		p.Admin = true
		if n, err := db.CountSources(r.Context(), c.sqlDB); err == nil {
			p.NATrier = n[db.SourceATrier]
		} else {
			logutil.Errorf("counting sources: %v", err)
		}
		if n, err := db.CountPropositionsEnAttente(r.Context(), c.sqlDB); err == nil {
			p.NPropositions = n
		} else {
			logutil.Errorf("counting propositions: %v", err)
		}
	}
	return p
}

// isAdmin tells whether the user sees the messages still to sort and the
// propositions (--admin-users). Without any authenticating proxy (local runs,
// tests), there is nobody to hide them from.
func isAdmin(r *http.Request) bool {
	u := currentUser(r)
	list := strings.TrimSpace(*adminUsers)
	if list == "" {
		return u == utilisateurInconnu
	}
	for _, a := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimSpace(a), u) {
			return true
		}
	}
	return false
}

// render executes into a buffer first so that a template that fails halfway
// isn't served as a truncated 200.
func (c copro) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := coproTmpl.ExecuteTemplate(&buf, name, data); err != nil {
		logutil.Errorf("executing template %s: %v", name, err)
		renderErr(w, http.StatusInternalServerError, "Erreur interne, voir les logs du serveur.")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// fail logs the real error and shows a generic one.
func (c copro) fail(w http.ResponseWriter, what string, err error) {
	logutil.Errorf("%s: %v", what, err)
	renderErr(w, http.StatusInternalServerError, "Erreur interne, voir les logs du serveur.")
}

// redirect sends the browser to a path of this app after a POST, with a
// message to show there. The path may carry a query string and a fragment.
func (c copro) redirect(w http.ResponseWriter, r *http.Request, path, flash string) {
	u, err := url.Parse(path)
	if err != nil || !cheminLocal(path) {
		u = &url.URL{Path: "/affaires"}
	}
	if flash != "" {
		q := u.Query()
		q.Set("flash", flash)
		u.RawQuery = q.Encode()
	}
	http.Redirect(w, r, c.basePath+u.String(), http.StatusSeeOther)
}

// cheminLocal tells whether a "retour" form field is a path of this app, so
// that it can't be used to bounce somebody to another site.
func cheminLocal(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.Contains(p, "\\")
}

// retour is where a form wants to go back to, or the fallback.
func retour(r *http.Request, fallback string) string {
	if p := r.FormValue("retour"); cheminLocal(p) {
		return p
	}
	return fallback
}

// lienExterne accepts what can go in an href: an http(s) URL, or nothing.
func lienExterne(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", true
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return s, true
}
