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

// What the pages of the site share: one template set, one navigation bar, and
// who is looking.

//go:embed templates/copro/*.html
var coproFS embed.FS

// coproFuncs is what every template of the site can call, the older pages
// (index, co-owners) included.
var coproFuncs = template.FuncMap{
	"quand":    func(t time.Time) string { return t.In(paris).Format("02/01/2006 à 15:04") },
	"jour":     func(t time.Time) string { return t.In(paris).Format("02/01/2006") },
	"exercice": nomExercice,
	"positif":  func(a db.Amount) db.Amount { return max(a, -a) },
	"taille":   taille,
	"chemin": url.PathEscape,
}

var coproTmpl = template.Must(template.New("copro").Funcs(coproFuncs).ParseFS(coproFS, "templates/copro/*.html"))

// avecLayout parses a page that lives outside templates/copro and gives it
// the "head" and "nav" templates of the layout, so that it looks like the
// rest of the site.
func avecLayout(name, html string) *template.Template {
	t := template.Must(template.New(name).Funcs(coproFuncs).Parse(html))
	return template.Must(t.ParseFS(coproFS, "templates/copro/layout.html"))
}

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
	coowners coownersFunc // The co-owners according to Foncia; nil without Foncia.
	push     *pusher      // The notifications of the site (push.go); nil in the pages that send none.
}

func (c copro) page(r *http.Request, section string) page {
	return page{BasePath: c.basePath, User: currentUser(r), Section: section, Flash: r.URL.Query().Get("flash")}
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
		u = &url.URL{Path: "/"}
	}
	if flash != "" {
		q := u.Query()
		q.Set("flash", flash)
		u.RawQuery = q.Encode()
	}
	http.Redirect(w, r, c.basePath+u.String(), http.StatusSeeOther)
}

// cheminLocal tells whether a path to redirect to is a path of this app, so
// that it can't be used to bounce somebody to another site.
func cheminLocal(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.Contains(p, "\\")
}
