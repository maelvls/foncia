package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
)

// The accounts: what the copropriété spent, by category and by supplier,
// against the budget; the expenses behind each total; and the purchases the
// co-owners are waiting to be paid back for.

type comptesData struct {
	page
	C comptesExercice

	Budget        db.BudgetDB
	ABudget       bool
	BudgetPct     int
	BudgetDepasse bool
	BudgetReste   db.Amount // Negative once the budget is exceeded.

	AttenteN int
	Attente  db.Amount
}

type depenseLigne struct {
	depense
	Href     string
	Affaires []db.AffaireRef
}

type depensesData struct {
	page
	F         filtreDepenses
	Exercices []int
	Lignes    []depenseLigne
	N         int
	Debits    db.Amount
	Credits   db.Amount
	Tronque   bool
}

type depenseData struct {
	page
	D        depense
	Href     string
	Liees    []db.AffaireRef
	Affaires []db.AffaireDB
}

type remboursementsData struct {
	page
	EnAttente      []db.RemboursementDB
	Autres         []db.RemboursementDB
	TotalAttente   db.Amount
	TotalRembourse db.Amount
}

type remboursementEditData struct {
	page
	IsNew bool
	R     db.RemboursementDB
}

const maxDepensesAffichees = 800

func addComptesHandlers(mux *http.ServeMux, sqlDB *sql.DB, basePath string) {
	c := copro{sqlDB: sqlDB, basePath: basePath}

	mux.HandleFunc("GET /comptes", c.comptes)
	mux.HandleFunc("POST /comptes/budget", c.budgetSet)
	mux.HandleFunc("GET /comptes/depenses", c.depenses)
	mux.HandleFunc("GET /comptes/depenses/{id}", c.depense)
	mux.HandleFunc("POST /comptes/depenses/{id}/lier", c.depenseLier)

	mux.HandleFunc("GET /remboursements", c.remboursements)
	mux.HandleFunc("GET /remboursements/new", c.remboursementNew)
	mux.HandleFunc("POST /remboursements/new", c.remboursementCreate)
	mux.HandleFunc("GET /remboursements/{id}", c.remboursementEdit)
	mux.HandleFunc("POST /remboursements/{id}", c.remboursementUpdate)
	mux.HandleFunc("POST /remboursements/{id}/delete", c.remboursementDelete)
}

// exerciceDemande is the exercise of the query string. ok is false when there
// is none, or when it asks for all of them ("tous").
func exerciceDemande(r *http.Request) (exercice int, ok bool) {
	y, err := strconv.Atoi(r.URL.Query().Get("exercice"))
	if err != nil || y < 1990 || y > 2200 {
		return 0, false
	}
	return y, true
}

// depensesPreparees loads the expenses table and makes real expenses of it.
func (c copro) depensesPreparees(r *http.Request) ([]depense, error) {
	rows, err := db.GetExpenseRows(r.Context(), c.sqlDB)
	if err != nil {
		return nil, err
	}
	return prepareDepenses(rows), nil
}

// affairesDe lists the affaires an expense is attached to, through any of the
// rows it stands for.
func affairesDe(d depense, parRef map[string][]db.AffaireRef) []db.AffaireRef {
	var out []db.AffaireRef
	vues := make(map[string]bool)
	for _, id := range d.IDs {
		for _, a := range parRef[id] {
			if !vues[a.ID] {
				vues[a.ID] = true
				out = append(out, a)
			}
		}
	}
	return out
}

func (c copro) comptes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ds, err := c.depensesPreparees(r)
	if err != nil {
		c.fail(w, "listing expenses", err)
		return
	}
	exercice, ok := exerciceDemande(r)
	if !ok {
		exercice = exerciceDe(time.Now().In(paris))
	}
	data := comptesData{page: c.page(r, "comptes"), C: resumeComptes(ds, exercice)}

	data.Budget, data.ABudget, err = db.GetBudget(ctx, c.sqlDB, exercice)
	if err != nil {
		c.fail(w, "get budget", err)
		return
	}
	if data.ABudget {
		data.BudgetPct = pct(data.C.Courant, data.Budget.Montant)
		data.BudgetReste = data.Budget.Montant - data.C.Courant
		data.BudgetDepasse = data.BudgetReste < 0
	}

	rbs, err := db.GetRemboursements(ctx, c.sqlDB)
	if err != nil {
		c.fail(w, "listing remboursements", err)
		return
	}
	for _, rb := range rbs {
		if rb.Statut.EnAttente() {
			data.AttenteN++
			data.Attente += rb.Montant
		}
	}
	c.render(w, "comptes", data)
}

func (c copro) budgetSet(w http.ResponseWriter, r *http.Request) {
	exercice, err := strconv.Atoi(r.FormValue("exercice"))
	if err != nil {
		renderErr(w, http.StatusBadRequest, "Exercice invalide.")
		return
	}
	montant, err := db.ParseEuros(r.FormValue("montant"))
	if err != nil || montant < 0 {
		renderErr(w, http.StatusBadRequest, "Montant du budget invalide.")
		return
	}
	err = db.SetBudget(r.Context(), c.sqlDB, db.BudgetDB{
		Annee: exercice, Montant: montant, Note: strings.TrimSpace(r.FormValue("note")), UpdatedBy: currentUser(r),
	})
	if err != nil {
		c.fail(w, "set budget", err)
		return
	}
	c.redirect(w, r, "/comptes?exercice="+strconv.Itoa(exercice), "Budget "+nomExercice(exercice)+" enregistré.")
}

func (c copro) depenses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	toutes, err := c.depensesPreparees(r)
	if err != nil {
		c.fail(w, "listing expenses", err)
		return
	}
	liees, err := db.GetAffairesByRef(ctx, c.sqlDB, db.LienDepense)
	if err != nil {
		c.fail(w, "affaires by ref", err)
		return
	}

	q := r.URL.Query()
	f := filtreDepenses{
		Allocation:  q.Get("allocation"),
		Nature:      q.Get("nature"),
		Fournisseur: q.Get("fournisseur"),
		Source:      q.Get("source"),
		Q:           strings.TrimSpace(q.Get("q")),
	}
	var ok bool
	f.Exercice, ok = exerciceDemande(r)
	f.Tout = !ok
	data := depensesData{page: c.page(r, "comptes"), F: f, Exercices: exercices(toutes)}
	for _, d := range filtrer(toutes, f) {
		data.N++
		if d.Debit() {
			data.Debits += d.Amount
		} else {
			data.Credits -= d.Amount
		}
		if len(data.Lignes) < maxDepensesAffichees {
			data.Lignes = append(data.Lignes, depenseLigne{
				depense: d, Href: hrefDepense(c.basePath, d.ExpenseDocumentDB), Affaires: affairesDe(d, liees),
			})
		}
	}
	data.Tronque = data.N > len(data.Lignes)
	c.render(w, "depenses", data)
}

// uneDepense loads the expense of the request, and answers 404 itself. The id
// may be any of the rows the expense stands for.
func (c copro) uneDepense(w http.ResponseWriter, r *http.Request) (depense, bool) {
	ds, err := c.depensesPreparees(r)
	if err != nil {
		c.fail(w, "listing expenses", err)
		return depense{}, false
	}
	id := r.PathValue("id")
	for _, d := range ds {
		if slices.Contains(d.IDs, id) {
			return d, true
		}
	}
	renderErr(w, http.StatusNotFound, "Dépense introuvable.")
	return depense{}, false
}

func (c copro) depense(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d, ok := c.uneDepense(w, r)
	if !ok {
		return
	}
	liees, err := db.GetAffairesByRef(ctx, c.sqlDB, db.LienDepense)
	if err != nil {
		c.fail(w, "affaires by ref", err)
		return
	}
	affaires, err := db.GetAffaires(ctx, c.sqlDB, "")
	if err != nil {
		c.fail(w, "listing affaires", err)
		return
	}
	c.render(w, "depense", depenseData{
		page: c.page(r, "comptes"), D: d, Href: hrefDepense(c.basePath, d.ExpenseDocumentDB),
		Liees: affairesDe(d, liees), Affaires: affaires,
	})
}

// depenseLier attaches the expense to an affaire, from the expense's side.
func (c copro) depenseLier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d, ok := c.uneDepense(w, r)
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
	dest := "/comptes/depenses/" + d.ID
	liees, err := db.GetAffairesByRef(ctx, c.sqlDB, db.LienDepense)
	if err != nil {
		c.fail(w, "affaires by ref", err)
		return
	}
	// The expense may already be attached through one of its other rows.
	if slices.ContainsFunc(affairesDe(d, liees), func(l db.AffaireRef) bool { return l.ID == a.ID }) {
		c.redirect(w, r, dest, "Déjà rattachée à l'affaire n°"+strconv.Itoa(a.Numero)+".")
		return
	}
	_, err = db.InsertLien(ctx, c.sqlDB, db.AffaireLienDB{
		AffaireID: a.ID, Kind: db.LienDepense, Ref: d.ID, Titre: d.Label,
		Note: strings.TrimSpace(r.FormValue("note")), Auteur: currentUser(r),
	})
	if errors.Is(err, db.ErrLienExists) {
		c.redirect(w, r, dest, "Déjà rattachée à l'affaire n°"+strconv.Itoa(a.Numero)+".")
		return
	}
	if err != nil {
		c.fail(w, "insert lien", err)
		return
	}
	c.redirect(w, r, dest, "Facture rattachée à l'affaire n°"+strconv.Itoa(a.Numero)+".")
}

func (c copro) remboursements(w http.ResponseWriter, r *http.Request) {
	rbs, err := db.GetRemboursements(r.Context(), c.sqlDB)
	if err != nil {
		c.fail(w, "listing remboursements", err)
		return
	}
	data := remboursementsData{page: c.page(r, "remboursements")}
	for _, rb := range rbs {
		if rb.Statut.EnAttente() {
			data.EnAttente = append(data.EnAttente, rb)
			data.TotalAttente += rb.Montant
			continue
		}
		data.Autres = append(data.Autres, rb)
		if rb.Statut == db.RemboursementRembourse {
			data.TotalRembourse += rb.Montant
		}
	}
	c.render(w, "remboursements", data)
}

func (c copro) remboursementNew(w http.ResponseWriter, r *http.Request) {
	c.render(w, "remboursement_edit", remboursementEditData{
		page:  c.page(r, "remboursements"),
		IsNew: true,
		R: db.RemboursementDB{
			Demandeur: currentUser(r),
			Statut:    db.RemboursementADemander,
			DateAchat: time.Now().In(paris).Format("2006-01-02"),
		},
	})
}

func (c copro) remboursementCreate(w http.ResponseWriter, r *http.Request) {
	rb, err := parseRemboursementForm(r)
	if err != nil {
		renderErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rb.CreatedBy = currentUser(r)
	if _, err := db.InsertRemboursement(r.Context(), c.sqlDB, rb); err != nil {
		c.fail(w, "insert remboursement", err)
		return
	}
	c.redirect(w, r, "/remboursements", "Achat ajouté : "+rb.Objet+" ("+rb.Montant.String()+").")
}

func (c copro) remboursementEdit(w http.ResponseWriter, r *http.Request) {
	rb, err := db.GetRemboursement(r.Context(), c.sqlDB, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		renderErr(w, http.StatusNotFound, "Remboursement introuvable.")
		return
	}
	if err != nil {
		c.fail(w, "get remboursement", err)
		return
	}
	c.render(w, "remboursement_edit", remboursementEditData{page: c.page(r, "remboursements"), R: rb})
}

func (c copro) remboursementUpdate(w http.ResponseWriter, r *http.Request) {
	rb, err := parseRemboursementForm(r)
	if err != nil {
		renderErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rb.ID = r.PathValue("id")
	err = db.UpdateRemboursement(r.Context(), c.sqlDB, rb)
	if errors.Is(err, sql.ErrNoRows) {
		renderErr(w, http.StatusNotFound, "Remboursement introuvable.")
		return
	}
	if err != nil {
		c.fail(w, "update remboursement", err)
		return
	}
	c.redirect(w, r, "/remboursements", "Enregistré : "+rb.Objet+".")
}

func (c copro) remboursementDelete(w http.ResponseWriter, r *http.Request) {
	if err := db.DeleteRemboursement(r.Context(), c.sqlDB, r.PathValue("id")); err != nil {
		c.fail(w, "delete remboursement", err)
		return
	}
	c.redirect(w, r, "/remboursements", "Achat supprimé.")
}

func parseRemboursementForm(r *http.Request) (db.RemboursementDB, error) {
	if err := r.ParseForm(); err != nil {
		return db.RemboursementDB{}, fmt.Errorf("formulaire invalide : %w", err)
	}
	objet := strings.TrimSpace(r.FormValue("objet"))
	if objet == "" {
		return db.RemboursementDB{}, fmt.Errorf("l'objet est obligatoire")
	}
	montant, err := db.ParseEuros(r.FormValue("montant"))
	if err != nil {
		return db.RemboursementDB{}, err
	}
	if montant <= 0 {
		return db.RemboursementDB{}, fmt.Errorf("le montant doit être positif")
	}
	dateAchat := strings.TrimSpace(r.FormValue("date_achat"))
	if dateAchat != "" {
		if _, err := time.Parse("2006-01-02", dateAchat); err != nil {
			return db.RemboursementDB{}, fmt.Errorf("date d'achat invalide : %q", dateAchat)
		}
	}
	statut := db.RemboursementStatut(r.FormValue("statut"))
	if !statut.Valid() {
		return db.RemboursementDB{}, fmt.Errorf("statut inconnu : %q", statut)
	}
	return db.RemboursementDB{
		Objet:             objet,
		Vendeur:           strings.TrimSpace(r.FormValue("vendeur")),
		Montant:           montant,
		DateAchat:         dateAchat,
		Demandeur:         strings.TrimSpace(r.FormValue("demandeur")),
		DateDemande:       strings.TrimSpace(r.FormValue("date_demande")),
		Statut:            statut,
		DateRemboursement: strings.TrimSpace(r.FormValue("date_remboursement")),
		Preuve:            strings.TrimSpace(r.FormValue("preuve")),
		Detail:            strings.TrimSpace(r.FormValue("detail")),
	}, nil
}
