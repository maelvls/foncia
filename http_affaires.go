package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
)

// The "affaires du conseil syndical": the désordres, actions and decisions the
// conseil follows, which used to live in an Excel outside the Foncia API. Each
// affaire is a dossier: its fiche, a thread of comments, and the invoices,
// documents, work orders, e-mails and links attached to it.

type affaireLigne struct {
	db.AffaireDB
	Stats db.AffaireStats
}

type affairesListData struct {
	page
	EnCours []affaireLigne
	Leves   []affaireLigne
}

type affaireEditData struct {
	page
	IsNew bool
	A     db.AffaireDB
}

// pieceView is a link of an affaire, resolved against what it points to.
type pieceView struct {
	db.AffaireLienDB
	Href        string // Where the title leads: the PDF, the e-mail, the page.
	Fiche       string // The page of this app about the row, if any.
	Montant     db.Amount
	AMontant    bool
	Introuvable bool // The row it pointed to is gone.
}

type dossierData struct {
	page
	A            db.AffaireDB
	Pieces       []pieceView
	Engage       db.Amount
	NFactures    int
	Commentaires []db.AffaireCommentaireDB
}

type candidat struct {
	Ref     string
	Titre   string
	Detail  string
	Montant string
}

type lierData struct {
	page
	A         db.AffaireDB
	Kind      db.LienKind
	Q         string
	Candidats []candidat
	Tronque   bool
}

const maxCandidats = 60

func addAffairesHandlers(mux *http.ServeMux, sqlDB *sql.DB, basePath string) {
	c := copro{sqlDB: sqlDB, basePath: basePath}

	mux.HandleFunc("GET /affaires", c.affairesList)
	mux.HandleFunc("GET /affaires/new", c.affaireNew)
	mux.HandleFunc("POST /affaires/new", c.affaireCreate)
	mux.HandleFunc("GET /affaires/{id}", c.affaireDossier)
	mux.HandleFunc("GET /affaires/{id}/edit", c.affaireEdit)
	mux.HandleFunc("POST /affaires/{id}", c.affaireUpdate)
	mux.HandleFunc("POST /affaires/{id}/statut", c.affaireStatut)
	mux.HandleFunc("POST /affaires/{id}/delete", c.affaireDelete)
	mux.HandleFunc("POST /affaires/{id}/commentaires", c.commentaireCreate)
	mux.HandleFunc("POST /affaires/{id}/commentaires/{cid}/delete", c.commentaireDelete)
	mux.HandleFunc("GET /affaires/{id}/lier", c.lienChercher)
	mux.HandleFunc("POST /affaires/{id}/liens", c.lienCreate)
	mux.HandleFunc("POST /affaires/{id}/liens/{lid}/delete", c.lienDelete)
}

// affaire loads the affaire of the request, and answers 404 itself when there
// is none.
func (c copro) affaire(w http.ResponseWriter, r *http.Request) (db.AffaireDB, bool) {
	a, err := db.GetAffaire(r.Context(), c.sqlDB, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		renderErr(w, http.StatusNotFound, "Affaire introuvable.")
		return a, false
	}
	if err != nil {
		c.fail(w, "get affaire", err)
		return a, false
	}
	return a, true
}

func (c copro) affairesList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	toutes, err := db.GetAffaires(ctx, c.sqlDB, "")
	if err != nil {
		c.fail(w, "listing affaires", err)
		return
	}
	stats, err := db.GetAffairesStats(ctx, c.sqlDB)
	if err != nil {
		c.fail(w, "affaires stats", err)
		return
	}
	data := affairesListData{page: c.page(r, "affaires")}
	for _, a := range toutes {
		l := affaireLigne{AffaireDB: a, Stats: stats[a.ID]}
		if a.Statut == db.AffaireStatutLevee {
			data.Leves = append(data.Leves, l)
		} else {
			data.EnCours = append(data.EnCours, l)
		}
	}
	c.render(w, "affaires", data)
}

func (c copro) affaireNew(w http.ResponseWriter, r *http.Request) {
	next, err := db.NextAffaireNumero(r.Context(), c.sqlDB, db.AffaireStatutEnCours)
	if err != nil {
		c.fail(w, "next numero", err)
		return
	}
	c.render(w, "affaire_edit", affaireEditData{
		page:  c.page(r, "affaires"),
		IsNew: true,
		A:     db.AffaireDB{Numero: next, Statut: db.AffaireStatutEnCours},
	})
}

func (c copro) affaireCreate(w http.ResponseWriter, r *http.Request) {
	a, err := parseAffaireForm(r)
	if err != nil {
		renderErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := db.InsertAffaire(r.Context(), c.sqlDB, a)
	if err != nil {
		c.fail(w, "insert affaire", err)
		return
	}
	c.redirect(w, r, "/affaires/"+id, "Affaire n°"+strconv.Itoa(a.Numero)+" créée.")
}

func (c copro) affaireEdit(w http.ResponseWriter, r *http.Request) {
	a, ok := c.affaire(w, r)
	if !ok {
		return
	}
	c.render(w, "affaire_edit", affaireEditData{page: c.page(r, "affaires"), A: a})
}

func (c copro) affaireUpdate(w http.ResponseWriter, r *http.Request) {
	a, err := parseAffaireForm(r)
	if err != nil {
		renderErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.ID = r.PathValue("id")
	if err := db.UpdateAffaire(r.Context(), c.sqlDB, a); err != nil {
		c.fail(w, "update affaire", err)
		return
	}
	c.redirect(w, r, "/affaires/"+a.ID, "Affaire enregistrée.")
}

// affaireStatut is the one-click "lever" / "rouvrir" of the dossier page.
func (c copro) affaireStatut(w http.ResponseWriter, r *http.Request) {
	a, ok := c.affaire(w, r)
	if !ok {
		return
	}
	switch db.AffaireStatut(r.FormValue("statut")) {
	case db.AffaireStatutLevee:
		a.Statut = db.AffaireStatutLevee
		if a.DateLevee == "" {
			a.DateLevee = time.Now().In(paris).Format("02/01/2006")
		}
	case db.AffaireStatutEnCours:
		a.Statut = db.AffaireStatutEnCours
		a.DateLevee = ""
	default:
		renderErr(w, http.StatusBadRequest, "Statut inconnu.")
		return
	}
	if err := db.UpdateAffaire(r.Context(), c.sqlDB, a); err != nil {
		c.fail(w, "update statut", err)
		return
	}
	flash := "Affaire rouverte."
	if a.Statut == db.AffaireStatutLevee {
		flash = "Affaire levée le " + a.DateLevee + "."
	}
	c.redirect(w, r, "/affaires/"+a.ID, flash)
}

func (c copro) affaireDelete(w http.ResponseWriter, r *http.Request) {
	if err := db.DeleteAffaire(r.Context(), c.sqlDB, r.PathValue("id")); err != nil {
		c.fail(w, "delete affaire", err)
		return
	}
	c.redirect(w, r, "/affaires", "Affaire supprimée.")
}

func (c copro) affaireDossier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, ok := c.affaire(w, r)
	if !ok {
		return
	}
	liens, err := db.GetLiens(ctx, c.sqlDB, a.ID)
	if err != nil {
		c.fail(w, "get liens", err)
		return
	}
	commentaires, err := db.GetCommentaires(ctx, c.sqlDB, a.ID)
	if err != nil {
		c.fail(w, "get commentaires", err)
		return
	}

	data := dossierData{page: c.page(r, "affaires"), A: a, Commentaires: commentaires}
	for _, l := range liens {
		p, err := c.resoudre(ctx, l)
		if err != nil {
			c.fail(w, "resolving lien", err)
			return
		}
		if l.Kind == db.LienDepense && p.AMontant {
			data.Engage += p.Montant
			data.NFactures++
		}
		data.Pieces = append(data.Pieces, p)
	}
	c.render(w, "affaire", data)
}

// resoudre looks up what a link points to, for its current amount and URL. A
// row that is gone isn't an error: the link keeps the title it was given.
func (c copro) resoudre(ctx context.Context, l db.AffaireLienDB) (pieceView, error) {
	p := pieceView{AffaireLienDB: l}
	var err error
	switch l.Kind {
	case db.LienDepense:
		var e db.ExpenseRow
		if e, err = db.GetExpenseRow(ctx, c.sqlDB, l.Ref); err == nil {
			p.Href = hrefDepense(c.basePath, e.ExpenseDocumentDB)
			p.Fiche = c.basePath + "/comptes/depenses/" + e.ID
			p.Montant, p.AMontant = e.Amount, true
		}
	case db.LienDocument:
		var d db.AccountDocumentDB
		if d, err = db.GetAccountDocumentDB(ctx, c.sqlDB, l.Ref); err == nil {
			p.Href = c.basePath + "/dl/doc/" + string(d.HashFile)
		}
	case db.LienMission:
		if _, err = db.GetMissionDB(ctx, c.sqlDB, l.Ref); err == nil {
			p.Href = c.basePath + "/?filter=missions#" + l.Ref
		}
	case db.LienRemboursement:
		var rb db.RemboursementDB
		if rb, err = db.GetRemboursement(ctx, c.sqlDB, l.Ref); err == nil {
			p.Href = c.basePath + "/remboursements/" + rb.ID
			p.Montant, p.AMontant = rb.Montant, true
		}
	default:
		p.Href = l.URL
	}
	if errors.Is(err, sql.ErrNoRows) {
		p.Introuvable = true
		return p, nil
	}
	return p, err
}

// hrefDepense is the link to the invoice's PDF, or "" when there is none.
func hrefDepense(basePath string, e db.ExpenseDocumentDB) string {
	switch {
	case e.HashFile != "":
		return basePath + "/dl/invoice/" + string(e.HashFile)
	case e.InvoiceID != "":
		return basePath + "/dl/invoiceid/" + e.InvoiceID
	}
	return ""
}

func (c copro) commentaireCreate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	texte := strings.TrimSpace(r.FormValue("texte"))
	if texte == "" {
		renderErr(w, http.StatusBadRequest, "Le commentaire est vide.")
		return
	}
	if _, ok := c.affaire(w, r); !ok {
		return
	}
	_, err := db.InsertCommentaire(r.Context(), c.sqlDB, db.AffaireCommentaireDB{AffaireID: id, Auteur: currentUser(r), Texte: texte})
	if err != nil {
		c.fail(w, "insert commentaire", err)
		return
	}
	c.redirect(w, r, "/affaires/"+id+"#commentaires", "")
}

func (c copro) commentaireDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := db.DeleteCommentaire(r.Context(), c.sqlDB, id, r.PathValue("cid")); err != nil {
		c.fail(w, "delete commentaire", err)
		return
	}
	c.redirect(w, r, "/affaires/"+id+"#commentaires", "Commentaire supprimé.")
}

// lienChercher lists what can be attached to the affaire: the invoices,
// documents, work orders or remboursements matching the search.
func (c copro) lienChercher(w http.ResponseWriter, r *http.Request) {
	a, ok := c.affaire(w, r)
	if !ok {
		return
	}
	kind := db.LienKind(r.URL.Query().Get("kind"))
	if !kind.HasRef() {
		renderErr(w, http.StatusBadRequest, "On ne peut chercher que des factures, des documents, des ordres de service ou des remboursements.")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	candidats, err := c.candidats(r.Context(), kind, q)
	if err != nil {
		c.fail(w, "searching candidats", err)
		return
	}
	data := lierData{page: c.page(r, "affaires"), A: a, Kind: kind, Q: q, Candidats: candidats}
	if len(candidats) > maxCandidats {
		data.Candidats, data.Tronque = candidats[:maxCandidats], true
	}
	c.render(w, "affaire_lier", data)
}

func (c copro) candidats(ctx context.Context, kind db.LienKind, q string) ([]candidat, error) {
	var out []candidat
	switch kind {
	case db.LienDepense:
		rows, err := db.GetExpenseRows(ctx, c.sqlDB)
		if err != nil {
			return nil, err
		}
		for _, d := range filtrer(prepareDepenses(rows), filtreDepenses{Tout: true, Q: q}) {
			out = append(out, candidat{
				Ref:     d.ID,
				Titre:   d.Label,
				Detail:  d.Local.Format("02/01/2006") + " · " + d.Fournisseur + " · " + d.AccountingKey.Allocation + ", " + d.Nature,
				Montant: d.Amount.String(),
			})
		}
	case db.LienDocument:
		docs, err := db.GetAccountDocumentsDB(ctx, c.sqlDB)
		if err != nil {
			return nil, err
		}
		for _, d := range docs {
			titre := titreDocument(d)
			if contientMots(titre, q) {
				out = append(out, candidat{Ref: d.ID, Titre: titre, Detail: d.CreatedAt.In(paris).Format("02/01/2006")})
			}
		}
	case db.LienMission:
		missions, err := db.GetMissionsDB(ctx, c.sqlDB)
		if err != nil {
			return nil, err
		}
		for _, m := range missions {
			if contientMots(m.Label+" "+m.Number+" "+m.Description, q) {
				out = append(out, candidat{
					Ref:    m.ID,
					Titre:  titreMission(m),
					Detail: m.StartedAt.In(paris).Format("02/01/2006") + " · " + m.KindFrench() + " · " + m.StatusFrench(),
				})
			}
		}
	case db.LienRemboursement:
		rbs, err := db.GetRemboursements(ctx, c.sqlDB)
		if err != nil {
			return nil, err
		}
		for _, rb := range rbs {
			if contientMots(rb.Objet+" "+rb.Vendeur+" "+rb.Demandeur, q) {
				out = append(out, candidat{
					Ref:     rb.ID,
					Titre:   rb.Objet,
					Detail:  rb.DateAchatFrench() + " · " + rb.Vendeur + " · " + rb.Statut.French(),
					Montant: rb.Montant.String(),
				})
			}
		}
	}
	return out, nil
}

func titreDocument(d db.AccountDocumentDB) string {
	if d.FilePath == "" {
		return d.CategoryFrench()
	}
	return d.CategoryFrench() + " — " + d.Filename()
}

func titreMission(m db.MissionDB) string {
	if m.Number == "" {
		return m.Label
	}
	return m.Label + " (" + m.Number + ")"
}

// titreLien is the title a link keeps of the row it points to, so that it
// still reads well if the row ever disappears from Foncia.
func (c copro) titreLien(ctx context.Context, kind db.LienKind, ref string) (string, error) {
	switch kind {
	case db.LienDepense:
		e, err := db.GetExpenseRow(ctx, c.sqlDB, ref)
		return e.Label, err
	case db.LienDocument:
		d, err := db.GetAccountDocumentDB(ctx, c.sqlDB, ref)
		return titreDocument(d), err
	case db.LienMission:
		m, err := db.GetMissionDB(ctx, c.sqlDB, ref)
		return titreMission(m), err
	case db.LienRemboursement:
		rb, err := db.GetRemboursement(ctx, c.sqlDB, ref)
		return rb.Objet, err
	}
	return "", fmt.Errorf("kind %q has no ref", kind)
}

func (c copro) lienCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, ok := c.affaire(w, r)
	if !ok {
		return
	}
	l := db.AffaireLienDB{
		AffaireID: a.ID,
		Kind:      db.LienKind(r.FormValue("kind")),
		Note:      strings.TrimSpace(r.FormValue("note")),
		Auteur:    currentUser(r),
	}
	switch {
	case l.Kind.HasRef():
		l.Ref = r.FormValue("ref")
		titre, err := c.titreLien(ctx, l.Kind, l.Ref)
		if errors.Is(err, sql.ErrNoRows) {
			renderErr(w, http.StatusNotFound, "Élément à rattacher introuvable.")
			return
		}
		if err != nil {
			c.fail(w, "titre lien", err)
			return
		}
		l.Titre = titre
	case l.Kind == db.LienEmail || l.Kind == db.LienURL:
		l.Titre = strings.TrimSpace(r.FormValue("titre"))
		u, valide := lienExterne(r.FormValue("url"))
		if !valide {
			renderErr(w, http.StatusBadRequest, "Le lien doit commencer par http:// ou https://.")
			return
		}
		l.URL = u
		if l.Titre == "" {
			l.Titre = l.URL
		}
		if l.Titre == "" {
			renderErr(w, http.StatusBadRequest, "Il faut au moins un titre ou un lien.")
			return
		}
	default:
		renderErr(w, http.StatusBadRequest, "Type de pièce inconnu.")
		return
	}

	dest := retour(r, "/affaires/"+a.ID+"#pieces")
	_, err := db.InsertLien(ctx, c.sqlDB, l)
	if errors.Is(err, db.ErrLienExists) {
		c.redirect(w, r, dest, "Déjà rattaché à l'affaire n°"+strconv.Itoa(a.Numero)+".")
		return
	}
	if err != nil {
		c.fail(w, "insert lien", err)
		return
	}
	c.redirect(w, r, dest, l.Kind.French()+" rattaché à l'affaire n°"+strconv.Itoa(a.Numero)+".")
}

func (c copro) lienDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := db.DeleteLien(r.Context(), c.sqlDB, id, r.PathValue("lid")); err != nil {
		c.fail(w, "delete lien", err)
		return
	}
	c.redirect(w, r, retour(r, "/affaires/"+id+"#pieces"), "Pièce détachée.")
}

func parseAffaireForm(r *http.Request) (db.AffaireDB, error) {
	if err := r.ParseForm(); err != nil {
		return db.AffaireDB{}, fmt.Errorf("formulaire invalide : %w", err)
	}
	numStr := strings.TrimSpace(r.FormValue("numero"))
	num, err := strconv.Atoi(numStr)
	if err != nil || num < 1 {
		return db.AffaireDB{}, fmt.Errorf("numéro invalide : %q", numStr)
	}
	titre := strings.TrimSpace(r.FormValue("titre"))
	if titre == "" {
		return db.AffaireDB{}, fmt.Errorf("le titre est obligatoire")
	}
	statut := db.AffaireStatut(r.FormValue("statut"))
	if statut != db.AffaireStatutEnCours && statut != db.AffaireStatutLevee {
		statut = db.AffaireStatutEnCours
	}

	// relance_date and relance_note come in pairs; a pair with neither is the
	// blank line the form always shows.
	dates, notes := r.Form["relance_date"], r.Form["relance_note"]
	var relances []db.AffaireRelanceDB
	for i := 0; i < max(len(dates), len(notes)); i++ {
		var d, n string
		if i < len(dates) {
			d = strings.TrimSpace(dates[i])
		}
		if i < len(notes) {
			n = strings.TrimSpace(notes[i])
		}
		if d != "" || n != "" {
			relances = append(relances, db.AffaireRelanceDB{Date: d, Note: n})
		}
	}

	return db.AffaireDB{
		Numero:          num,
		Titre:           titre,
		Localisation:    strings.TrimSpace(r.FormValue("localisation")),
		ActionFoncia:    strings.TrimSpace(r.FormValue("action_foncia")),
		Responsable:     strings.TrimSpace(r.FormValue("responsable")),
		DateSignalement: strings.TrimSpace(r.FormValue("date_signalement")),
		LienDevis:       strings.TrimSpace(r.FormValue("lien_devis")),
		ObsCopro:        strings.TrimSpace(r.FormValue("obs_copro")),
		ObsSyndic:       strings.TrimSpace(r.FormValue("obs_syndic")),
		DateLevee:       strings.TrimSpace(r.FormValue("date_levee")),
		Statut:          statut,
		Relances:        relances,
	}, nil
}
