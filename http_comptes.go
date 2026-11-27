package main

import (
	"database/sql"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
)

// The accounts: what the copropriété spent, by category and by supplier,
// against the budget, and the expenses behind each total.

type comptesData struct {
	page
	C comptesExercice

	Budget        db.BudgetDB
	ABudget       bool
	BudgetPct     int
	BudgetDepasse bool
	BudgetReste   db.Amount // Negative once the budget is exceeded.
}

type depenseLigne struct {
	depense
	Href string
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
	D    depense
	Href string
}

const maxDepensesAffichees = 800

func addComptesHandlers(mux *http.ServeMux, sqlDB *sql.DB, basePath string) {
	c := copro{sqlDB: sqlDB, basePath: basePath}

	mux.HandleFunc("GET /comptes", c.comptes)
	mux.HandleFunc("POST /comptes/budget", c.budgetSet)
	mux.HandleFunc("GET /comptes/depenses", c.depenses)
	mux.HandleFunc("GET /comptes/depenses/{id}", c.depense)
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
	toutes, err := c.depensesPreparees(r)
	if err != nil {
		c.fail(w, "listing expenses", err)
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
				depense: d, Href: hrefDepense(c.basePath, d.ExpenseDocumentDB),
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
	d, ok := c.uneDepense(w, r)
	if !ok {
		return
	}
	c.render(w, "depense", depenseData{
		page: c.page(r, "comptes"), D: d, Href: hrefDepense(c.basePath, d.ExpenseDocumentDB),
	})
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
