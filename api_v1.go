package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// /api/v1 is for the other services of the house, the agent that files the
// pieces of the copropriété in a knowledge base first: what changed in the
// mirror of Foncia, and the PDFs. They call it as themselves (workload.go),
// from the machine, without the reverse proxy's login.
//
//	GET /api/v1/changements?depuis=<seq>&attendre=<s>&limite=<n>
//	GET /api/v1/fichiers/<typ>/<id>
//	GET /api/v1/etat
//
// The journal (db/migrations/0008_changements.sql) is read with a cursor:
// the reader keeps the "curseur" of the last answer and gives it back as
// "depuis". Nothing is lost while the reader is away, and a reader that
// starts from 0 gets the whole history first. "attendre" makes it a long
// poll: when there is nothing after the cursor, the answer waits up to that
// many seconds for something to come.

type apiV1 struct {
	sqlDB       *sql.DB
	client      *http.Client
	invoicesDir string
	basePath    string
	lastSync    func() (time.Time, error)
	poll        time.Duration // How often a long poll looks at the journal.
}

const (
	apiLimiteDefaut = 200
	apiLimiteMax    = 1000
	// apiAttenteMax stays under the server's WriteTimeout (60 s).
	apiAttenteMax = 50 * time.Second
)

func (a apiV1) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/changements", a.changements)
	mux.HandleFunc("GET /api/v1/fichiers/{typ}/{id}", a.fichier)
	mux.HandleFunc("GET /api/v1/etat", a.etat)
	return mux
}

type apiChangement struct {
	db.ChangementDB
	// Fichier is the URL of its PDF on this API, from the root of the
	// site; absent when it has none.
	Fichier string `json:"fichier,omitempty"`
}

type apiChangements struct {
	// Curseur is what to give as "depuis" next time.
	Curseur int64 `json:"curseur"`
	// Fin is the last seq of the journal: Curseur < Fin means there is
	// more to read right away.
	Fin         int64           `json:"fin"`
	Changements []apiChangement `json:"changements"`
}

func (a apiV1) changements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	fin, err := db.DernierChangement(ctx, a.sqlDB)
	if err != nil {
		a.fail(w, err)
		return
	}
	var depuis int64
	switch v := q.Get("depuis"); v {
	case "":
	case "fin":
		// Only what comes from now on.
		depuis = fin
	default:
		depuis, err = strconv.ParseInt(v, 10, 64)
		if err != nil || depuis < 0 {
			http.Error(w, `depuis: a seq ("curseur" of the last answer), 0 for everything, or "fin" for what comes next`, http.StatusBadRequest)
			return
		}
	}
	limite := apiLimiteDefaut
	if v := q.Get("limite"); v != "" {
		limite, err = strconv.Atoi(v)
		if err != nil || limite < 1 {
			http.Error(w, "limite: a number of changes, at least 1", http.StatusBadRequest)
			return
		}
		limite = min(limite, apiLimiteMax)
	}
	var attendre time.Duration
	if v := q.Get("attendre"); v != "" {
		s, err := strconv.Atoi(v)
		if err != nil || s < 0 {
			http.Error(w, "attendre: seconds", http.StatusBadRequest)
			return
		}
		attendre = min(time.Duration(s)*time.Second, apiAttenteMax)
	}

	// The long poll: the sync writes the journal every few minutes at best,
	// so looking at its end every second costs nothing.
	if fin <= depuis && attendre > 0 {
		poll := a.poll
		if poll == 0 {
			poll = time.Second
		}
		deadline := time.NewTimer(attendre)
		defer deadline.Stop()
		tick := time.NewTicker(poll)
		defer tick.Stop()
	attente:
		for fin <= depuis {
			select {
			case <-ctx.Done():
				return
			case <-deadline.C:
				break attente
			case <-tick.C:
				if fin, err = db.DernierChangement(ctx, a.sqlDB); err != nil {
					a.fail(w, err)
					return
				}
			}
		}
	}

	cs, err := db.GetChangements(ctx, a.sqlDB, depuis, limite)
	if err != nil {
		a.fail(w, err)
		return
	}
	out := apiChangements{Curseur: depuis, Fin: max(fin, depuis), Changements: []apiChangement{}}
	for _, c := range cs {
		ac := apiChangement{ChangementDB: c}
		if c.Fichier != "" {
			ac.Fichier = a.basePath + "/api/v1/fichiers/" + c.Fichier
		}
		out.Changements = append(out.Changements, ac)
		out.Curseur = c.Seq
		out.Fin = max(out.Fin, c.Seq)
	}
	a.json(w, out)
}

// fichier serves a PDF, as /dl does for the browser; a general assembly
// document that isn't on disk yet is downloaded from Foncia first.
func (a apiV1) fichier(w http.ResponseWriter, r *http.Request) {
	typ, id := r.PathValue("typ"), r.PathValue("id")
	if _, known := documentLookups[typ]; !known {
		http.Error(w, "not found: /api/v1/fichiers/(invoice|invoiceid|contract|doc)/<id>", http.StatusNotFound)
		return
	}
	p, err := resolveDocument(r.Context(), a.sqlDB, a.client, a.invoicesDir, typ, id)
	switch {
	case errors.Is(err, errNotDownloaded):
		http.Error(w, "not found: this file hasn't been downloaded yet; a change will say when it is", http.StatusNotFound)
		return
	case err != nil:
		logutil.Errorf("api: while looking up %s %q: %v", typ, id, err)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Disposition", `inline; filename="`+path.Base(p)+`"`)
	w.Header().Set("Cache-Control", "private, max-age=300")
	http.ServeFile(w, r, p)
}

type apiEtat struct {
	DerniereSynchro *time.Time `json:"derniere_synchro"` // null before the first one.
	Erreur          string     `json:"erreur,omitempty"` // Why the last one failed.
	Fin             int64      `json:"fin"`              // The last seq of the journal.
}

func (a apiV1) etat(w http.ResponseWriter, r *http.Request) {
	fin, err := db.DernierChangement(r.Context(), a.sqlDB)
	if err != nil {
		a.fail(w, err)
		return
	}
	out := apiEtat{Fin: fin}
	if a.lastSync != nil {
		when, err := a.lastSync()
		if !when.IsZero() {
			out.DerniereSynchro = &when
		}
		if err != nil {
			out.Erreur = err.Error()
		}
	}
	a.json(w, out)
}

func (a apiV1) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logutil.Errorf("api: writing the answer: %v", err)
	}
}

func (a apiV1) fail(w http.ResponseWriter, err error) {
	logutil.Errorf("api: %v", err)
	http.Error(w, "internal error, see the logs of the server", http.StatusInternalServerError)
}
