package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// The files of the affaires, the messages collected from Gmail, WhatsApp and
// Foncia (the "sources") and what Claude proposes to do with them.
//
// Who sees what: every co-owner sees what is attached to an affaire (the
// files, the messages). The messages still to sort, the ones set aside, and
// Claude's propositions are for the administrators (--admin-users): they are
// Maël's e-mails and WhatsApp conversations until somebody files them.

var claudeTriggerFile = flag.String("claude-trigger-file", "", "File to write to when Claude should look at the new sources: a systemd path unit on the host watches it and runs `claude -p` (see brain/). Next to it, dernier.json tells how the last run went. Empty disables the runs.")

type sourcesData struct {
	page
	Etat     db.SourceEtat
	Canal    db.SourceCanal
	Sources  []sourceLigne
	Affaires []db.AffaireDB
	Compte   map[string]int // By state; string keys for the template's index.
	Brain    brainEtat
}

type sourceLigne struct {
	db.SourceDB
	Affaires   []db.AffaireRef
	Proposee   bool
	Suggestion *suggestion
}

type sourceData struct {
	page
	S          db.SourceDB
	Affaires   []db.AffaireRef // Those it is attached to.
	Fil        []db.SourceDB   // The other messages of the same e-mail thread.
	Toutes     []db.AffaireDB  // To pick one to attach to.
	Suggestion *suggestion
}

// suggestion is what the page offers to do with a message still to sort, so
// that the administrator confirms rather than looks for the affaire: what
// Claude proposed for it, else the affaire of the rest of its e-mail thread.
type suggestion struct {
	Action        db.PropositionAction // Empty when it comes from the thread.
	PropositionID string
	Affaire       *db.AffaireDB // The affaire to preselect, when there is one.
	Titre         string        // creer_affaire: the title Claude gave.
	Pourquoi      string
}

// AffaireID is the affaire to preselect, or "". It is safe on a nil
// suggestion, which is what the templates have for most messages.
func (s *suggestion) AffaireID() string {
	if s == nil || s.Affaire == nil {
		return ""
	}
	return s.Affaire.ID
}

// Libelle says where the suggestion comes from and what it is.
func (s *suggestion) Libelle() string {
	num := ""
	if s.Affaire != nil {
		num = "n°" + strconv.Itoa(s.Affaire.Numero)
	}
	switch s.Action {
	case db.PropRattacher:
		return "Claude propose de rattacher à " + num
	case db.PropCommenter:
		return "Claude propose un commentaire sur " + num
	case db.PropRelancer:
		return "Claude propose une relance sur " + num
	case db.PropLever:
		return "Claude propose de lever " + num
	case db.PropCreerAffaire:
		return "Claude propose une nouvelle affaire"
	case db.PropIgnorer:
		return "Claude propose d'écarter"
	}
	return "Même fil que " + num
}

// Ecarter tells whether the suggestion is to set the message aside. Safe on
// a nil suggestion too.
func (s *suggestion) Ecarter() bool { return s != nil && s.Action == db.PropIgnorer }

// suggestions finds what to offer for each message to sort. Several waiting
// propositions may be about the same message: the one that names an affaire
// wins over a new affaire, which wins over setting it aside.
func suggestions(ctx context.Context, sqlDB *sql.DB, sources []db.SourceDB, affaires []db.AffaireDB) (map[string]*suggestion, error) {
	parID := make(map[string]*db.AffaireDB, len(affaires))
	for i := range affaires {
		parID[affaires[i].ID] = &affaires[i]
	}
	props, err := db.GetPropositions(ctx, sqlDB, 0, db.PropEnAttente)
	if err != nil {
		return nil, err
	}
	rang := func(s *suggestion) int {
		switch {
		case s == nil:
			return 0
		case s.Action == db.PropIgnorer:
			return 1
		case s.Action == db.PropCreerAffaire:
			return 2
		case s.Action == db.PropRattacher:
			return 4
		}
		return 3
	}
	out := make(map[string]*suggestion)
	for _, p := range props {
		sug := &suggestion{Action: p.Action, PropositionID: p.ID, Pourquoi: p.Justification}
		switch p.Action {
		case db.PropIgnorer:
		case db.PropCreerAffaire:
			sug.Titre = p.Donnees.Titre
		default:
			if sug.Affaire = parID[p.AffaireID]; sug.Affaire == nil {
				continue // The affaire is gone: nothing to preselect.
			}
		}
		for _, id := range p.SourceIDs {
			if rang(sug) > rang(out[id]) {
				out[id] = sug
			}
		}
	}
	for _, s := range sources {
		if out[s.ID] != nil || s.Etat != db.SourceATrier || s.Canal != db.CanalGmail {
			continue
		}
		fil, err := db.AffairesOfFil(ctx, sqlDB, s.Canal, s.Fil, s.ID)
		if err != nil {
			return nil, err
		}
		if len(fil) == 1 && parID[fil[0].ID] != nil {
			out[s.ID] = &suggestion{Affaire: parID[fil[0].ID], Pourquoi: "D'autres messages de ce fil y sont déjà rattachés."}
		}
	}
	return out, nil
}

type propositionsData struct {
	page
	EnAttente []propositionVue
	Decidees  []propositionVue
	Brain     brainEtat
}

type propositionVue struct {
	db.PropositionDB
	Affaire *db.AffaireDB
	Sources []db.SourceDB
}

func addSourcesHandlers(mux *http.ServeMux, c copro) {
	mux.HandleFunc("POST /affaires/{id}/fichiers", c.fichiersEnvoyer)
	mux.HandleFunc("GET /fichiers/{sha}", c.fichierServir)
	mux.HandleFunc("GET /fichiers/{sha}/{nom...}", c.fichierServir)
	mux.HandleFunc("POST /fichiers/{sha}/partager", c.fichierPartager)

	mux.HandleFunc("GET /sources", c.sourcesList)
	mux.HandleFunc("GET /sources/{id}", c.sourceVoir)
	mux.HandleFunc("POST /sources/{id}/rattacher", c.sourceRattacher)
	mux.HandleFunc("POST /sources/{id}/nouvelle-affaire", c.sourceNouvelleAffaire)
	mux.HandleFunc("POST /sources/{id}/etat", c.sourceEtat)

	mux.HandleFunc("GET /propositions", c.propositionsList)
	mux.HandleFunc("POST /propositions/{id}/accepter", c.propositionAccepter)
	mux.HandleFunc("POST /propositions/{id}/refuser", c.propositionRefuser)
	mux.HandleFunc("POST /claude/lancer", c.claudeLancer)
}

// addPublicHandlers serves what doesn't need a login: the share links. They
// are mounted next to (not under) the authenticated routes, and the reverse
// proxy must let /f/* through.
func addPublicHandlers(mux *http.ServeMux, c copro) {
	mux.HandleFunc("GET "+c.basePath+"/f/{sha}/{nom...}", c.fichierPartage)
}

func (c copro) adminOnly(w http.ResponseWriter, r *http.Request) bool {
	if !isAdmin(r) {
		renderErr(w, http.StatusForbidden, "Cette page est réservée aux administrateurs du suivi.")
		return false
	}
	return true
}

// -----------------------------------------------------------------------------
// Fichiers
// -----------------------------------------------------------------------------

func (c copro) fichiersEnvoyer(w http.ResponseWriter, r *http.Request) {
	a, ok := c.affaire(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*maxFichier)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		renderErr(w, http.StatusBadRequest, "Envoi impossible : "+err.Error())
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	note := strings.TrimSpace(r.FormValue("note"))
	user := currentUser(r)
	var noms []string
	for _, fh := range r.MultipartForm.File["fichiers"] {
		f, err := fh.Open()
		if err != nil {
			c.fail(w, "opening uploaded file", err)
			return
		}
		stocke, err := stockerFichier(r.Context(), c.sqlDB, f, fh.Filename, fh.Header.Get("Content-Type"), db.FichierEnvoi, user)
		_ = f.Close()
		if errors.Is(err, errTropGros) {
			renderErr(w, http.StatusRequestEntityTooLarge, fh.Filename+" : "+err.Error()+".")
			return
		}
		if err != nil {
			c.fail(w, "storing uploaded file", err)
			return
		}
		_, err = db.InsertLien(r.Context(), c.sqlDB, db.AffaireLienDB{
			AffaireID: a.ID, Kind: db.LienFichier, Ref: stocke.SHA256, Titre: nomPropre(fh.Filename), Note: note, Auteur: user,
		})
		if err != nil && !errors.Is(err, db.ErrLienExists) {
			c.fail(w, "attaching uploaded file", err)
			return
		}
		noms = append(noms, nomPropre(fh.Filename))
	}
	if len(noms) == 0 {
		renderErr(w, http.StatusBadRequest, "Aucun fichier choisi.")
		return
	}
	c.redirect(w, r, "/affaires/"+a.ID+"#pieces", strings.Join(noms, ", ")+" ajouté à l'affaire n°"+strconv.Itoa(a.Numero)+".")
}

// fichier loads the file of the request if the user may see it.
func (c copro) fichier(w http.ResponseWriter, r *http.Request) (db.FichierDB, bool) {
	sha := r.PathValue("sha")
	if !shaRe.MatchString(sha) {
		renderErr(w, http.StatusNotFound, "Fichier introuvable.")
		return db.FichierDB{}, false
	}
	f, err := db.GetFichier(r.Context(), c.sqlDB, sha)
	if errors.Is(err, sql.ErrNoRows) {
		renderErr(w, http.StatusNotFound, "Fichier introuvable.")
		return f, false
	}
	if err != nil {
		c.fail(w, "get fichier", err)
		return f, false
	}
	if !isAdmin(r) {
		visible, err := db.FichierVisible(r.Context(), c.sqlDB, sha)
		if err != nil {
			c.fail(w, "fichier visible", err)
			return f, false
		}
		if !visible {
			renderErr(w, http.StatusNotFound, "Fichier introuvable.")
			return f, false
		}
	}
	return f, true
}

func (c copro) fichierServir(w http.ResponseWriter, r *http.Request) {
	f, ok := c.fichier(w, r)
	if !ok {
		return
	}
	servirFichier(w, r, f)
}

// fichierPartager makes a share link and shows it on the page the button was
// on.
func (c copro) fichierPartager(w http.ResponseWriter, r *http.Request) {
	f, ok := c.fichier(w, r)
	if !ok {
		return
	}
	exp := time.Now().Add(dureePartage)
	lien := c.baseURL + c.partage.lien(f, exp)
	logutil.Infof("share link for %s (%s) made by %s, valid until %s", f.SHA256, f.Nom, currentUser(r), exp.Format(time.RFC3339))
	c.redirect(w, r, retour(r, "/affaires"), "Lien de partage de « "+f.Nom+" », valable jusqu'au "+exp.In(paris).Format("02/01/2006")+", sans connexion : "+lien)
}

// fichierPartage serves a share link, without a login.
func (c copro) fichierPartage(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	if !shaRe.MatchString(sha) || len(c.partage.cle) == 0 {
		renderErr(w, http.StatusNotFound, "Ce lien n'est pas valide.")
		return
	}
	if ok, msg := c.partage.valide(sha, r.URL.Query().Get("e"), r.URL.Query().Get("s"), time.Now()); !ok {
		renderErr(w, http.StatusForbidden, msg)
		return
	}
	f, err := db.GetFichier(r.Context(), c.sqlDB, sha)
	if err != nil {
		renderErr(w, http.StatusNotFound, "Ce fichier n'existe plus.")
		return
	}
	logutil.Infof("serving %s (%s) through a share link to %s", f.SHA256, f.Nom, r.RemoteAddr)
	servirFichier(w, r, f)
}

// -----------------------------------------------------------------------------
// Sources
// -----------------------------------------------------------------------------

func (c copro) sourcesList(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	ctx := r.Context()
	etat := db.SourceEtat(r.URL.Query().Get("etat"))
	if etat != db.SourceClassee && etat != db.SourceIgnoree {
		etat = db.SourceATrier
	}
	canal := db.SourceCanal(r.URL.Query().Get("canal"))
	sources, err := db.GetSources(ctx, c.sqlDB, db.SourcesFilter{Etats: []db.SourceEtat{etat}, Canal: canal, Limit: 300})
	if err != nil {
		c.fail(w, "listing sources", err)
		return
	}
	proposees, err := db.SourcesProposees(ctx, c.sqlDB)
	if err != nil {
		c.fail(w, "sources proposees", err)
		return
	}
	// Every affaire, those en cours first: the field filters them as one
	// types, and a late message may be about an affaire already levée.
	affaires, err := db.GetAffaires(ctx, c.sqlDB, "")
	if err != nil {
		c.fail(w, "listing affaires", err)
		return
	}
	var sugg map[string]*suggestion
	if etat == db.SourceATrier {
		if sugg, err = suggestions(ctx, c.sqlDB, sources, affaires); err != nil {
			c.fail(w, "suggestions", err)
			return
		}
	}
	compte, err := db.CountSources(ctx, c.sqlDB)
	if err != nil {
		c.fail(w, "counting sources", err)
		return
	}
	data := sourcesData{page: c.page(r, "sources"), Etat: etat, Canal: canal, Affaires: affaires, Compte: map[string]int{}, Brain: c.brain.etat()}
	for e, n := range compte {
		data.Compte[string(e)] = n
	}
	for _, s := range sources {
		l := sourceLigne{SourceDB: s, Proposee: proposees[s.ID], Suggestion: sugg[s.ID]}
		if etat == db.SourceClassee {
			if l.Affaires, err = db.AffairesOfSource(ctx, c.sqlDB, s.ID); err != nil {
				c.fail(w, "affaires of source", err)
				return
			}
		}
		data.Sources = append(data.Sources, l)
	}
	c.render(w, "sources", data)
}

// source loads the source of the request if the user may see it: the
// administrators see them all, the others only those attached to an affaire.
func (c copro) source(w http.ResponseWriter, r *http.Request) (db.SourceDB, []db.AffaireRef, bool) {
	s, err := db.GetSource(r.Context(), c.sqlDB, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		renderErr(w, http.StatusNotFound, "Message introuvable.")
		return s, nil, false
	}
	if err != nil {
		c.fail(w, "get source", err)
		return s, nil, false
	}
	affaires, err := db.AffairesOfSource(r.Context(), c.sqlDB, s.ID)
	if err != nil {
		c.fail(w, "affaires of source", err)
		return s, nil, false
	}
	if !isAdmin(r) && len(affaires) == 0 {
		renderErr(w, http.StatusNotFound, "Message introuvable.")
		return s, nil, false
	}
	return s, affaires, true
}

func (c copro) sourceVoir(w http.ResponseWriter, r *http.Request) {
	s, affaires, ok := c.source(w, r)
	if !ok {
		return
	}
	data := sourceData{page: c.page(r, "sources"), S: s, Affaires: affaires}
	if s.Canal == db.CanalGmail && s.Fil != "" {
		fil, err := db.GetSources(r.Context(), c.sqlDB, db.SourcesFilter{Canal: s.Canal, Fil: s.Fil})
		if err != nil {
			c.fail(w, "sources of thread", err)
			return
		}
		for _, f := range fil {
			if f.ID != s.ID {
				data.Fil = append(data.Fil, f)
			}
		}
	}
	if data.Admin {
		toutes, err := db.GetAffaires(r.Context(), c.sqlDB, "")
		if err != nil {
			c.fail(w, "listing affaires", err)
			return
		}
		data.Toutes = toutes
		if s.Etat == db.SourceATrier {
			sugg, err := suggestions(r.Context(), c.sqlDB, []db.SourceDB{s}, toutes)
			if err != nil {
				c.fail(w, "suggestions", err)
				return
			}
			data.Suggestion = sugg[s.ID]
		}
	}
	c.render(w, "source", data)
}

func (c copro) sourceRattacher(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	ctx := r.Context()
	s, _, ok := c.source(w, r)
	if !ok {
		return
	}
	a, err := db.GetAffaire(ctx, c.sqlDB, r.FormValue("affaire_id"))
	if errors.Is(err, sql.ErrNoRows) {
		renderErr(w, http.StatusBadRequest, "Choisissez une affaire.")
		return
	}
	if err != nil {
		c.fail(w, "get affaire", err)
		return
	}
	n, err := rattacherSource(ctx, c.sqlDB, s, a, currentUser(r))
	if err != nil {
		c.fail(w, "rattacher source", err)
		return
	}
	if err := fermerPropositionsCaduques(ctx, c.sqlDB, currentUser(r)); err != nil {
		c.fail(w, "closing propositions", err)
		return
	}
	flash := "Rattaché à l'affaire n°" + strconv.Itoa(a.Numero) + " (" + a.Titre + ")."
	if n > 0 {
		flash += fmt.Sprintf(" %d autre(s) message(s) du même fil aussi.", n)
	}
	c.redirect(w, r, retour(r, "/sources"), flash)
}

// sourceNouvelleAffaire opens an affaire from a message: the subject becomes
// the title, the message is attached, and the fiche opens to be completed.
func (c copro) sourceNouvelleAffaire(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	ctx := r.Context()
	s, _, ok := c.source(w, r)
	if !ok {
		return
	}
	num, err := db.NextAffaireNumero(ctx, c.sqlDB, db.AffaireStatutEnCours)
	if err != nil {
		c.fail(w, "next numero", err)
		return
	}
	titre := strings.TrimSpace(r.FormValue("titre"))
	if titre == "" {
		titre = s.Titre()
	}
	a := db.AffaireDB{Numero: num, Titre: titre, Statut: db.AffaireStatutEnCours, DateSignalement: s.Date.In(paris).Format("02/01/2006")}
	if a.ID, err = db.InsertAffaire(ctx, c.sqlDB, a); err != nil {
		c.fail(w, "insert affaire", err)
		return
	}
	if _, err := rattacherSource(ctx, c.sqlDB, s, a, currentUser(r)); err != nil {
		c.fail(w, "rattacher source", err)
		return
	}
	if err := fermerPropositionsCaduques(ctx, c.sqlDB, currentUser(r)); err != nil {
		c.fail(w, "closing propositions", err)
		return
	}
	c.redirect(w, r, "/affaires/"+a.ID+"/edit", "Affaire n°"+strconv.Itoa(num)+" créée depuis le message : complétez la fiche.")
}

func (c copro) sourceEtat(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	etat := db.SourceEtat(r.FormValue("etat"))
	if etat != db.SourceIgnoree && etat != db.SourceATrier {
		renderErr(w, http.StatusBadRequest, "État inconnu.")
		return
	}
	err := db.SetSourceEtat(r.Context(), c.sqlDB, r.PathValue("id"), etat, currentUser(r))
	if errors.Is(err, sql.ErrNoRows) {
		renderErr(w, http.StatusNotFound, "Message introuvable.")
		return
	}
	if err != nil {
		c.fail(w, "set source etat", err)
		return
	}
	if err := fermerPropositionsCaduques(r.Context(), c.sqlDB, currentUser(r)); err != nil {
		c.fail(w, "closing propositions", err)
		return
	}
	flash := "Message écarté."
	if etat == db.SourceATrier {
		flash = "Message remis à trier."
	}
	c.redirect(w, r, retour(r, "/sources"), flash)
}

// rattacherSource attaches a source to an affaire and marks it sorted. A
// Foncia novelty becomes a link to the mission or the invoice itself; a
// message becomes a "message" link, and its attachments are attached as files
// so that the devis show up among the pièces. The other messages of the same
// e-mail thread that are still to sort follow; how many is returned.
func rattacherSource(ctx context.Context, sqlDB *sql.DB, s db.SourceDB, a db.AffaireDB, par string) (int, error) {
	if err := lierSource(ctx, sqlDB, s, a, par); err != nil {
		return 0, err
	}
	if err := db.SetSourceEtat(ctx, sqlDB, s.ID, db.SourceClassee, par); err != nil {
		return 0, err
	}
	if s.Canal != db.CanalGmail || s.Fil == "" {
		return 0, nil
	}
	autres, err := db.GetSources(ctx, sqlDB, db.SourcesFilter{Canal: s.Canal, Fil: s.Fil, Etats: []db.SourceEtat{db.SourceATrier}})
	if err != nil {
		return 0, err
	}
	for _, o := range autres {
		if err := lierSource(ctx, sqlDB, o, a, "auto:fil"); err != nil {
			return 0, err
		}
		if err := db.SetSourceEtat(ctx, sqlDB, o.ID, db.SourceClassee, "auto:fil"); err != nil {
			return 0, err
		}
	}
	return len(autres), nil
}

// fermerPropositionsCaduques closes the waiting propositions that only sort
// messages (rattacher, creer_affaire, ignorer) once all their messages were
// sorted by hand: accepting one afterwards would file the messages a second
// time, open an affaire twice or set aside a filed message. It is recorded as
// accepted when what was done by hand is what it proposed, as refused
// otherwise. Those that do more than sorting (a comment, a relance, lever)
// stay: the administrator still has to decide on them.
func fermerPropositionsCaduques(ctx context.Context, sqlDB *sql.DB, par string) error {
	props, err := db.GetPropositions(ctx, sqlDB, 0, db.PropEnAttente)
	if err != nil {
		return err
	}
	for _, p := range props {
		if len(p.SourceIDs) == 0 || (p.Action != db.PropRattacher && p.Action != db.PropCreerAffaire && p.Action != db.PropIgnorer) {
			continue
		}
		sources, err := db.GetSources(ctx, sqlDB, db.SourcesFilter{IDs: p.SourceIDs})
		if err != nil {
			return err
		}
		reste, suivie := false, p.Action != db.PropCreerAffaire && len(sources) == len(p.SourceIDs)
		for _, s := range sources {
			switch {
			case s.Etat == db.SourceATrier:
				reste = true
			case p.Action == db.PropIgnorer:
				suivie = suivie && s.Etat == db.SourceIgnoree
			case p.Action == db.PropRattacher:
				refs, err := db.AffairesOfSource(ctx, sqlDB, s.ID)
				if err != nil {
					return err
				}
				suivie = suivie && slices.ContainsFunc(refs, func(a db.AffaireRef) bool { return a.ID == p.AffaireID })
			}
		}
		if reste {
			continue
		}
		etat, resultat := db.PropRefusee, "Sans objet : les messages ont été triés à la main autrement."
		if suivie {
			etat, resultat = db.PropAcceptee, "Fait à la main depuis les messages collectés."
		}
		if err := db.DecideProposition(ctx, sqlDB, p.ID, etat, par, resultat); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	return nil
}

func lierSource(ctx context.Context, sqlDB *sql.DB, s db.SourceDB, a db.AffaireDB, par string) error {
	ignoreExists := func(_ string, err error) error {
		if errors.Is(err, db.ErrLienExists) {
			return nil
		}
		return err
	}
	if s.Canal == db.CanalFoncia {
		kind, ref, _ := strings.Cut(s.Ref, ":")
		l := db.AffaireLienDB{AffaireID: a.ID, Kind: db.LienKind(kind), Ref: ref, Titre: s.Titre(), Auteur: par}
		if !l.Kind.Searchable() {
			return fmt.Errorf("source %s has an unknown ref %q", s.ID, s.Ref)
		}
		return ignoreExists(db.InsertLien(ctx, sqlDB, l))
	}
	err := ignoreExists(db.InsertLien(ctx, sqlDB, db.AffaireLienDB{
		AffaireID: a.ID, Kind: db.LienSource, Ref: s.ID, Titre: s.Titre(), URL: s.URL, Auteur: par,
	}))
	if err != nil {
		return err
	}
	for _, f := range s.Fichiers {
		err := ignoreExists(db.InsertLien(ctx, sqlDB, db.AffaireLienDB{
			AffaireID: a.ID, Kind: db.LienFichier, Ref: f.SHA256, Titre: f.NomDansMessage,
			Note: "Pièce jointe : " + s.Canal.French() + " de " + s.Auteur + " du " + s.Date.In(paris).Format("02/01/2006"), Auteur: par,
		}))
		if err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Propositions
// -----------------------------------------------------------------------------

func (c copro) propositionsList(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	ctx := r.Context()
	data := propositionsData{page: c.page(r, "propositions"), Brain: c.brain.etat()}
	var err error
	enAttente, err := db.GetPropositions(ctx, c.sqlDB, 0, db.PropEnAttente)
	if err != nil {
		c.fail(w, "listing propositions", err)
		return
	}
	decidees, err := db.GetPropositions(ctx, c.sqlDB, 30, db.PropAcceptee, db.PropRefusee)
	if err != nil {
		c.fail(w, "listing propositions", err)
		return
	}
	for _, lot := range []struct {
		in  []db.PropositionDB
		out *[]propositionVue
	}{{enAttente, &data.EnAttente}, {decidees, &data.Decidees}} {
		for _, p := range lot.in {
			v, err := c.vueProposition(ctx, p)
			if err != nil {
				c.fail(w, "proposition view", err)
				return
			}
			*lot.out = append(*lot.out, v)
		}
	}
	c.render(w, "propositions", data)
}

func (c copro) vueProposition(ctx context.Context, p db.PropositionDB) (propositionVue, error) {
	v := propositionVue{PropositionDB: p}
	if p.AffaireID != "" {
		a, err := db.GetAffaire(ctx, c.sqlDB, p.AffaireID)
		switch {
		case err == nil:
			v.Affaire = &a
		case !errors.Is(err, sql.ErrNoRows):
			return v, err
		}
	}
	if len(p.SourceIDs) > 0 {
		sources, err := db.GetSources(ctx, c.sqlDB, db.SourcesFilter{IDs: p.SourceIDs})
		if err != nil {
			return v, err
		}
		v.Sources = sources
	}
	return v, nil
}

func (c copro) propositionAccepter(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	ctx := r.Context()
	p, err := db.GetProposition(ctx, c.sqlDB, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		renderErr(w, http.StatusNotFound, "Proposition introuvable.")
		return
	}
	if err != nil {
		c.fail(w, "get proposition", err)
		return
	}
	if p.Etat != db.PropEnAttente {
		c.redirect(w, r, "/propositions", "Cette proposition a déjà été traitée.")
		return
	}
	// The administrator may have corrected the text before accepting.
	if t := strings.TrimSpace(r.FormValue("titre")); t != "" {
		p.Donnees.Titre = t
	}
	if t := strings.TrimSpace(r.FormValue("texte")); t != "" {
		p.Donnees.Texte = t
	}
	user := currentUser(r)
	resultat, dest, err := appliquerProposition(ctx, c.sqlDB, p, user)
	if err != nil {
		logutil.Errorf("applying proposition %s: %v", p.ID, err)
		renderErr(w, http.StatusBadRequest, "Impossible d'appliquer la proposition : "+err.Error())
		return
	}
	if err := db.DecideProposition(ctx, c.sqlDB, p.ID, db.PropAcceptee, user, resultat); err != nil {
		c.fail(w, "decide proposition", err)
		return
	}
	if r.FormValue("ensuite") == "affaire" && dest != "" {
		c.redirect(w, r, dest, resultat)
		return
	}
	c.redirect(w, r, "/propositions", resultat)
}

func (c copro) propositionRefuser(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	err := db.DecideProposition(r.Context(), c.sqlDB, r.PathValue("id"), db.PropRefusee, currentUser(r), strings.TrimSpace(r.FormValue("raison")))
	if errors.Is(err, sql.ErrNoRows) {
		c.redirect(w, r, "/propositions", "Cette proposition a déjà été traitée.")
		return
	}
	if err != nil {
		c.fail(w, "refuse proposition", err)
		return
	}
	c.redirect(w, r, "/propositions", "Proposition refusée.")
}

// appliquerProposition does what a proposition says. It returns a sentence
// for the administrator and the path of the affaire it touched.
func appliquerProposition(ctx context.Context, sqlDB *sql.DB, p db.PropositionDB, par string) (string, string, error) {
	var sources []db.SourceDB
	if len(p.SourceIDs) > 0 { // An empty filter would select every source.
		var err error
		if sources, err = db.GetSources(ctx, sqlDB, db.SourcesFilter{IDs: p.SourceIDs}); err != nil {
			return "", "", err
		}
		if len(sources) != len(p.SourceIDs) {
			return "", "", fmt.Errorf("un des messages n'existe plus")
		}
	}
	affaire := func() (db.AffaireDB, error) {
		a, err := db.GetAffaire(ctx, sqlDB, p.AffaireID)
		if errors.Is(err, sql.ErrNoRows) {
			return a, fmt.Errorf("l'affaire n'existe plus")
		}
		return a, err
	}
	rattacherTout := func(a db.AffaireDB) error {
		for _, s := range sources {
			if _, err := rattacherSource(ctx, sqlDB, s, a, par); err != nil {
				return err
			}
		}
		return nil
	}
	num := func(a db.AffaireDB) string { return "l'affaire n°" + strconv.Itoa(a.Numero) + " (" + a.Titre + ")" }

	switch p.Action {
	case db.PropRattacher:
		a, err := affaire()
		if err != nil {
			return "", "", err
		}
		if err := rattacherTout(a); err != nil {
			return "", "", err
		}
		return fmt.Sprintf("%d message(s) rattaché(s) à %s.", len(sources), num(a)), "/affaires/" + a.ID, nil

	case db.PropCreerAffaire:
		if strings.TrimSpace(p.Donnees.Titre) == "" {
			return "", "", fmt.Errorf("la proposition n'a pas de titre")
		}
		n, err := db.NextAffaireNumero(ctx, sqlDB, db.AffaireStatutEnCours)
		if err != nil {
			return "", "", err
		}
		a := db.AffaireDB{
			Numero: n, Titre: p.Donnees.Titre, Localisation: p.Donnees.Localisation, ActionFoncia: p.Donnees.ActionFoncia,
			Responsable: p.Donnees.Responsable, DateSignalement: p.Donnees.DateSignalement, Statut: db.AffaireStatutEnCours,
		}
		if a.ID, err = db.InsertAffaire(ctx, sqlDB, a); err != nil {
			return "", "", err
		}
		if err := rattacherTout(a); err != nil {
			return "", "", err
		}
		return "Affaire n°" + strconv.Itoa(n) + " créée : " + a.Titre + ".", "/affaires/" + a.ID, nil

	case db.PropCommenter:
		a, err := affaire()
		if err != nil {
			return "", "", err
		}
		if strings.TrimSpace(p.Donnees.Texte) == "" {
			return "", "", fmt.Errorf("le commentaire est vide")
		}
		texte := p.Donnees.Texte + "\n\n(proposé par Claude, accepté par " + par + ")"
		if _, err := db.InsertCommentaire(ctx, sqlDB, db.AffaireCommentaireDB{AffaireID: a.ID, Auteur: "claude", Texte: texte}); err != nil {
			return "", "", err
		}
		if err := rattacherTout(a); err != nil {
			return "", "", err
		}
		return "Commentaire ajouté à " + num(a) + ".", "/affaires/" + a.ID + "#commentaires", nil

	case db.PropRelancer:
		a, err := affaire()
		if err != nil {
			return "", "", err
		}
		date := strings.TrimSpace(p.Donnees.Date)
		if date == "" {
			date = time.Now().In(paris).Format("02/01/2006")
		}
		a.Relances = append(a.Relances, db.AffaireRelanceDB{Date: date, Note: p.Donnees.Note})
		if err := db.UpdateAffaire(ctx, sqlDB, a); err != nil {
			return "", "", err
		}
		if err := rattacherTout(a); err != nil {
			return "", "", err
		}
		return "Relance du " + date + " ajoutée à " + num(a) + ".", "/affaires/" + a.ID, nil

	case db.PropLever:
		a, err := affaire()
		if err != nil {
			return "", "", err
		}
		a.Statut = db.AffaireStatutLevee
		if a.DateLevee == "" {
			a.DateLevee = time.Now().In(paris).Format("02/01/2006")
		}
		if err := db.UpdateAffaire(ctx, sqlDB, a); err != nil {
			return "", "", err
		}
		if err := rattacherTout(a); err != nil {
			return "", "", err
		}
		return num(a) + " est levée.", "/affaires/" + a.ID, nil

	case db.PropIgnorer:
		for _, s := range sources {
			if err := db.SetSourceEtat(ctx, sqlDB, s.ID, db.SourceIgnoree, par); err != nil {
				return "", "", err
			}
		}
		return fmt.Sprintf("%d message(s) écarté(s).", len(sources)), "", nil
	}
	return "", "", fmt.Errorf("action inconnue %q", p.Action)
}

// -----------------------------------------------------------------------------
// Claude
// -----------------------------------------------------------------------------

// brainTrigger asks the Claude runner on the host (brain/ in the repository)
// to run, by writing to a file that a systemd path unit watches. The runner
// writes dernier.json next to it when it is done.
type brainTrigger struct{ path string }

type brainEtat struct {
	Actif     bool      // A trigger file is configured.
	Demande   time.Time // Last time a run was asked for.
	Debut     time.Time `json:"debut"`
	Fin       time.Time `json:"fin"`
	OK        bool      `json:"ok"`
	Resume    string    `json:"resume"`
	Erreur    string    `json:"erreur"`
	EnCours   bool      // Asked for and not finished yet.
	Illisible bool
}

func (b brainTrigger) demander(raison string) error {
	if b.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(b.path, []byte(time.Now().Format(time.RFC3339)+" "+raison+"\n"), 0o644)
}

func (b brainTrigger) etat() brainEtat {
	e := brainEtat{Actif: b.path != ""}
	if !e.Actif {
		return e
	}
	if st, err := os.Stat(b.path); err == nil {
		e.Demande = st.ModTime()
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(b.path), "dernier.json"))
	if err == nil {
		if json.Unmarshal(raw, &e) != nil {
			e.Illisible = true
		}
	}
	e.EnCours = e.Demande.After(e.Fin) || e.Debut.After(e.Fin)
	return e
}

func (c copro) claudeLancer(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	if c.brain.path == "" {
		renderErr(w, http.StatusBadRequest, "Claude n'est pas branché sur ce serveur (--claude-trigger-file).")
		return
	}
	if err := c.brain.demander("demandé par " + currentUser(r)); err != nil {
		c.fail(w, "trigger brain", err)
		return
	}
	c.redirect(w, r, retour(r, "/propositions"), "Claude va regarder les messages à trier. Les propositions arrivent ici d'ici une à deux minutes.")
}
