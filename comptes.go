package main

import (
	"fmt"
	"html/template"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
)

// The accounts pages are computed in Go from the whole expenses table rather
// than in SQL: there are a couple of thousand rows, the exercise an expense
// belongs to depends on the Paris time zone (see `paris` in http_mcp.go), the
// supplier isn't a column, and the table holds every expense several times
// (see prepareDepenses).

// The exercise runs from the 1st of July to the 30th of June, and is named
// after the year it starts in: 2025 is "2025-2026".
var moisExercice = [12]string{"juil.", "août", "sept.", "oct.", "nov.", "déc.", "janv.", "févr.", "mars", "avr.", "mai", "juin"}

const (
	fournisseurFoncia  = "Foncia (honoraires et courriers)"
	fournisseurRemb    = "Remboursements à des copropriétaires"
	fournisseurInconnu = "Non identifié"
	fournisseurSansNom = ""
)

// exerciceDe is the exercise a date falls in. Foncia stamps the closing
// entries of an exercise anywhere between the 30th of June at midnight and the
// 1st of July at 23:59:59, so the boundary is the end of the 1st of July: a
// real invoice dated that one day lands in the exercise that just closed.
func exerciceDe(local time.Time) int {
	t := local.AddDate(0, 0, -1)
	if t.Month() >= time.July {
		return t.Year()
	}
	return t.Year() - 1
}

func nomExercice(debut int) string {
	return fmt.Sprintf("%d-%d", debut, debut+1)
}

// cloture tells whether the date is the stamp of the closing of an exercise
// rather than the day something was paid.
func cloture(local time.Time) bool {
	_, m, d := local.Date()
	if !(m == time.June && d == 30) && !(m == time.July && d == 1) {
		return false
	}
	rond := local.Minute() == 0 && local.Second() == 0
	finDeJournee := local.Hour() == 23 && local.Minute() == 59
	return rond || finDeJournee
}

// natureSansRecup removes the "R" (récupérable) and "NR" suffixes: Foncia
// publishes "ELECTRICITE" in the current accounts and the very same expense as
// "ELECTRICITE R" in the breakdown of the closed exercise.
func natureSansRecup(nature string) string {
	n := strings.Join(strings.Fields(nature), " ")
	n = strings.TrimSuffix(n, " NR")
	n = strings.TrimSuffix(n, " R")
	return n
}

// depense is one real expense: what the accounts pages show and add up. It
// stands for one or several rows of the expenses table.
type depense struct {
	db.ExpenseRow           // The row that represents the others.
	Local         time.Time // Date, in Paris.
	Exercice      int
	Nature        string // Expense type, without the R / NR suffix.
	Fournisseur   string
	IDs           []string // Every row this expense stands for, the representative included.
}

// Debit tells whether the copropriété paid this (as opposed to received it).
func (d depense) Debit() bool { return d.Amount > 0 }

// Abs is the amount without its sign, for the columns that already say which
// way the money went.
func (d depense) Abs() db.Amount { return max(d.Amount, -d.Amount) }

// Doublons is how many extra copies of this expense the table holds.
func (d depense) Doublons() int { return len(d.IDs) - 1 }

// fournisseurDuFichier reads the supplier out of the name Foncia gives to the
// invoice, "OU CHANNA - CT01037406 - 2024-10-01 - _27.pdf". That name is the
// most reliable: the label spells the same supplier in several ways.
func fournisseurDuFichier(e db.ExpenseDocumentDB) string {
	if e.FilePath == "" {
		return fournisseurSansNom
	}
	base := filepath.Base(e.FilePath)
	if i := strings.Index(base, " - CT"); i > 0 {
		return strings.ToUpper(strings.Join(strings.Fields(base[:i]), " "))
	}
	return fournisseurSansNom
}

// prefixeLibelle is the part of the label that usually names the supplier:
// "COGELEC - INTRATONE DU - 25/02/26" gives "COGELEC".
func prefixeLibelle(label string) string {
	i := strings.Index(label, " - ")
	if i <= 0 {
		return fournisseurSansNom
	}
	p := strings.ToUpper(strings.Join(strings.Fields(label[:i]), " "))
	p = strings.TrimPrefix(p, "MADAME ")
	p = strings.TrimPrefix(p, "MONSIEUR ")
	return p
}

func estFoncia(e db.ExpenseDocumentDB) bool {
	l := strings.ToUpper(e.Label)
	return strings.HasPrefix(l, "HONORAIRES") ||
		strings.Contains(l, "COURRIER DU") ||
		strings.HasPrefix(filepath.Base(e.FilePath), "Facture_Hono")
}

// ligne is a row of the expenses table with what is derived from it alone.
type ligne struct {
	db.ExpenseRow
	local       time.Time
	fournisseur string
	sur         int // How much to trust fournisseur: 2 from the file, 1 guessed, 0 unknown.
}

// fournisseurs derives the supplier of every row.
//
// The supplier comes from the invoice's file name when there is one. A quarter
// of the rows have no file, so the label prefix is used instead, translated
// through what the rows that have both taught us: "2NRT" is "2NRT-POMPES
// ENVIRONNEMENT", "ACO" is "A.C.O".
func fournisseurs(rows []db.ExpenseRow) []ligne {
	votes := make(map[string]map[string]int)
	for _, r := range rows {
		f, p := fournisseurDuFichier(r.ExpenseDocumentDB), prefixeLibelle(r.Label)
		if f == fournisseurSansNom || p == fournisseurSansNom {
			continue
		}
		if votes[p] == nil {
			votes[p] = make(map[string]int)
		}
		votes[p][f]++
	}
	appris := make(map[string]string, len(votes))
	for p, fs := range votes {
		best, bestN := "", 0
		for f, n := range fs {
			if n > bestN || (n == bestN && f < best) {
				best, bestN = f, n
			}
		}
		appris[p] = best
	}

	out := make([]ligne, 0, len(rows))
	for _, r := range rows {
		l := ligne{ExpenseRow: r, local: r.Date.In(paris), sur: 1}
		switch f, p := fournisseurDuFichier(r.ExpenseDocumentDB), prefixeLibelle(r.Label); {
		case strings.HasPrefix(strings.ToUpper(r.Label), "REMB"):
			l.fournisseur = fournisseurRemb
		case f != fournisseurSansNom:
			l.fournisseur, l.sur = f, 2
		case estFoncia(r.ExpenseDocumentDB):
			l.fournisseur = fournisseurFoncia
		case appris[p] != "":
			l.fournisseur = appris[p]
		case p != fournisseurSansNom:
			l.fournisseur = p
		default:
			l.fournisseur, l.sur = fournisseurInconnu, 0
		}
		out = append(out, l)
	}
	return out
}

// prepareDepenses turns the rows of the expenses table into real expenses,
// most recent first.
//
// The table holds most expenses several times, because the sync only ever
// adds: Foncia publishes an expense in the current accounts and again in the
// breakdown of the closed exercise (with an "R" or "NR" nature), and it
// rewrites labels after the fact, and each of those is a new row. Adding the
// rows up counts the electricity three times.
//
// Rows are the same expense when they have the same invoice file, amount and
// category. Without an invoice file, rows of the same exercise, amount and
// category are the same expense when they are dated the same day, or when one
// of them only carries the stamp of the closing of the exercise. The works
// accounts never have an invoice file and change nature between publications,
// so for them the nature is left out of the comparison; that makes their
// totals the least certain.
func prepareDepenses(rows []db.ExpenseRow) []depense {
	var ordre []string
	groupes := make(map[string][]ligne)
	for _, l := range fournisseurs(rows) {
		nature := natureSansRecup(l.AccountingKey.ExpenseType)
		var cle string
		switch {
		case l.HashFile != "":
			cle = strings.Join([]string{"piece", string(l.HashFile), strconv.Itoa(int(l.Amount)), l.AccountingKey.Allocation, nature}, "\x00")
		case l.Source == db.SourceRepairs:
			cle = strings.Join([]string{"travaux", strconv.Itoa(exerciceDe(l.local)), strconv.Itoa(int(l.Amount)), l.AccountingKey.Allocation}, "\x00")
		default:
			cle = strings.Join([]string{"courant", strconv.Itoa(exerciceDe(l.local)), strconv.Itoa(int(l.Amount)), l.AccountingKey.Allocation, nature}, "\x00")
		}
		if _, vu := groupes[cle]; !vu {
			ordre = append(ordre, cle)
		}
		groupes[cle] = append(groupes[cle], l)
	}

	var out []depense
	for _, cle := range ordre {
		g := groupes[cle]
		if g[0].HashFile != "" {
			out = append(out, fusionner(g))
			continue
		}
		// One expense per real day; the closing stamps join the first one.
		var jours []string
		parJour := make(map[string][]ligne)
		var clotures []ligne
		for _, l := range g {
			if cloture(l.local) {
				clotures = append(clotures, l)
				continue
			}
			j := l.local.Format("2006-01-02")
			if _, vu := parJour[j]; !vu {
				jours = append(jours, j)
			}
			parJour[j] = append(parJour[j], l)
		}
		if len(jours) == 0 {
			out = append(out, fusionner(clotures))
			continue
		}
		sort.Strings(jours)
		parJour[jours[0]] = append(parJour[jours[0]], clotures...)
		for _, j := range jours {
			out = append(out, fusionner(parJour[j]))
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Local.Equal(out[j].Local) {
			return out[i].Local.After(out[j].Local)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// fusionner makes one expense out of the rows that are copies of it. It keeps
// the real date over a closing stamp, the copy that has its PDF, the most
// trustworthy supplier, and the longest label, which is the latest rewrite
// more often than not.
func fusionner(g []ligne) depense {
	rep := g[0]
	date := g[0].local
	meilleur := g[0]
	ids := make([]string, 0, len(g))
	for _, l := range g {
		ids = append(ids, l.ID)
		if a, b := l.FilePath != "", rep.FilePath != ""; (a && !b) || (a == b && len(l.Label) > len(rep.Label)) {
			rep = l
		}
		if a, b := cloture(l.local), cloture(date); (!a && b) || (a == b && l.local.Before(date)) {
			date = l.local
		}
		if l.sur > meilleur.sur {
			meilleur = l
		}
	}
	sort.Strings(ids)
	return depense{
		ExpenseRow:  rep.ExpenseRow,
		Local:       date,
		Exercice:    exerciceDe(date),
		Nature:      natureSansRecup(rep.AccountingKey.ExpenseType),
		Fournisseur: meilleur.fournisseur,
		IDs:         ids,
	}
}

// filtreDepenses is the drill-down of the accounts page. Tout is there
// because exercise 0 can't mean "every exercise" and be a year too.
type filtreDepenses struct {
	Exercice    int
	Tout        bool // Every exercise.
	Allocation  string
	Nature      string
	Fournisseur string
	Source      string
	Q           string
}

func (f filtreDepenses) garde(d depense) bool {
	if !f.Tout && d.Exercice != f.Exercice {
		return false
	}
	if f.Allocation != "" && d.AccountingKey.Allocation != f.Allocation {
		return false
	}
	if f.Nature != "" && d.Nature != f.Nature {
		return false
	}
	if f.Fournisseur != "" && d.Fournisseur != f.Fournisseur {
		return false
	}
	if f.Source != "" && string(d.Source) != f.Source {
		return false
	}
	return contientMots(d.Label+" "+d.Fournisseur+" "+d.AccountingKey.Allocation+" "+d.Nature+" "+d.Amount.String(), f.Q)
}

// Query is the filter as a query string, for the links between the pages. It
// is a template.URL so that html/template leaves its "=" and "&" alone.
func (f filtreDepenses) Query() template.URL {
	v := url.Values{}
	if f.Tout {
		v.Set("exercice", "tous")
	} else {
		v.Set("exercice", strconv.Itoa(f.Exercice))
	}
	for k, s := range map[string]string{"allocation": f.Allocation, "nature": f.Nature, "fournisseur": f.Fournisseur, "source": f.Source, "q": f.Q} {
		if s != "" {
			v.Set(k, s)
		}
	}
	return template.URL(v.Encode())
}

// contientMots tells whether every word of q appears in s, ignoring case. An
// empty q matches everything.
func contientMots(s, q string) bool {
	s = strings.ToLower(s)
	for _, mot := range strings.Fields(strings.ToLower(q)) {
		if !strings.Contains(s, mot) {
			return false
		}
	}
	return true
}

func filtrer(ds []depense, f filtreDepenses) []depense {
	var out []depense
	for _, d := range ds {
		if f.garde(d) {
			out = append(out, d)
		}
	}
	return out
}

// exercices lists the exercises that have expenses, most recent first.
func exercices(ds []depense) []int {
	vus := make(map[int]bool)
	var out []int
	for _, d := range ds {
		if !vus[d.Exercice] {
			vus[d.Exercice] = true
			out = append(out, d.Exercice)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

// ligneTotal is one line of a breakdown: a category or a supplier.
type ligneTotal struct {
	Nom       string
	Debits    db.Amount    // What was paid.
	Credits   db.Amount    // What was received, as a positive amount.
	Precedent db.Amount    // Debits of the exercise before.
	N         int          // Expenses of this exercise.
	Pct       int          // Debits relative to the largest line, for the bar.
	Query     template.URL // Link to the expenses behind the line.
}

type categorieTotal struct {
	ligneTotal
	Natures []ligneTotal
}

type moisTotal struct {
	Nom    string
	Debits db.Amount
	Pct    int
}

// comptesExercice is the accounts page of one exercise. The day-to-day account
// and the works accounts are kept apart: adding them up means nothing.
type comptesExercice struct {
	Exercice  int
	Nom       string
	Precedent string // Name of the exercise before.
	Exercices []int

	Courant        db.Amount // Paid from the day-to-day account.
	CourantPrec    db.Amount
	CourantCredits db.Amount
	Travaux        db.Amount // Paid from the works accounts.
	TravauxCredits db.Amount
	N              int
	Doublons       int // Rows of the table left out because they are copies.

	Mois         [12]moisTotal    // Day-to-day account, July first.
	Categories   []categorieTotal // Day-to-day account.
	Fournisseurs []ligneTotal     // Both accounts.
	TravauxLots  []ligneTotal     // Works accounts, by allocation.
}

func pct(part, whole db.Amount) int {
	if whole <= 0 || part <= 0 {
		return 0
	}
	return min(max(int(part*100/whole), 1), 100)
}

// parDebits sorts the lines, largest first, and sizes their bars.
func parDebits(ls []ligneTotal) {
	sort.SliceStable(ls, func(i, j int) bool {
		if ls[i].Debits != ls[j].Debits {
			return ls[i].Debits > ls[j].Debits
		}
		return ls[i].Nom < ls[j].Nom
	})
	var top db.Amount
	for _, l := range ls {
		top = max(top, l.Debits)
	}
	for i := range ls {
		ls[i].Pct = pct(ls[i].Debits, top)
	}
}

// lignesDe turns the map into the lines of this exercise. The lines that only
// exist because of the exercise before are left out.
func lignesDe(m map[string]*ligneTotal, query func(cle string) template.URL) []ligneTotal {
	var out []ligneTotal
	for cle, l := range m {
		if l.N == 0 {
			continue
		}
		l.Query = query(cle)
		out = append(out, *l)
	}
	parDebits(out)
	return out
}

// resumeComptes computes the accounts page of one exercise.
func resumeComptes(ds []depense, exercice int) comptesExercice {
	c := comptesExercice{
		Exercice: exercice, Nom: nomExercice(exercice), Precedent: nomExercice(exercice - 1),
		Exercices: exercices(ds),
	}

	get := func(m map[string]*ligneTotal, k, nom string) *ligneTotal {
		if m[k] == nil {
			m[k] = &ligneTotal{Nom: nom}
		}
		return m[k]
	}
	compter := func(d depense, ls ...*ligneTotal) {
		for _, l := range ls {
			l.N++
			if d.Debit() {
				l.Debits += d.Amount
			} else {
				l.Credits -= d.Amount
			}
		}
	}
	cats := make(map[string]*ligneTotal)
	natures := make(map[string]*ligneTotal)
	fours := make(map[string]*ligneTotal)
	lots := make(map[string]*ligneTotal)
	const sep = "\x00"

	for _, d := range ds {
		travaux := d.Source == db.SourceRepairs
		allocation := d.AccountingKey.Allocation
		four := get(fours, d.Fournisseur, d.Fournisseur)

		switch d.Exercice {
		case exercice - 1:
			if !d.Debit() {
				continue
			}
			four.Precedent += d.Amount
			if !travaux {
				c.CourantPrec += d.Amount
				get(cats, allocation, allocation).Precedent += d.Amount
				get(natures, allocation+sep+d.Nature, d.Nature).Precedent += d.Amount
			}
		case exercice:
			c.N++
			c.Doublons += d.Doublons()
			if travaux {
				compter(d, four, get(lots, allocation, allocation))
				if d.Debit() {
					c.Travaux += d.Amount
				} else {
					c.TravauxCredits -= d.Amount
				}
				continue
			}
			compter(d, four, get(cats, allocation, allocation), get(natures, allocation+sep+d.Nature, d.Nature))
			if !d.Debit() {
				c.CourantCredits -= d.Amount
				continue
			}
			c.Courant += d.Amount
			// July is month 0 of the exercise, except the closing stamps of
			// the 1st of July, which belong to the June that just ended.
			m := (int(d.Local.Month()) + 5) % 12
			if d.Local.Month() == time.July && d.Local.Year() != exercice {
				m = 11
			}
			c.Mois[m].Debits += d.Amount
		}
	}

	var maxMois db.Amount
	for _, m := range c.Mois {
		maxMois = max(maxMois, m.Debits)
	}
	for i := range c.Mois {
		c.Mois[i].Nom = moisExercice[i]
		c.Mois[i].Pct = pct(c.Mois[i].Debits, maxMois)
	}

	c.Fournisseurs = lignesDe(fours, func(nom string) template.URL {
		return filtreDepenses{Exercice: exercice, Fournisseur: nom}.Query()
	})
	c.TravauxLots = lignesDe(lots, func(nom string) template.URL {
		return filtreDepenses{Exercice: exercice, Allocation: nom, Source: string(db.SourceRepairs)}.Query()
	})

	parCat := make(map[string][]ligneTotal)
	for cle, l := range natures {
		if l.N == 0 {
			continue
		}
		allocation, nature, _ := strings.Cut(cle, sep)
		l.Query = filtreDepenses{Exercice: exercice, Allocation: allocation, Nature: nature, Source: string(db.SourceAccounting)}.Query()
		parCat[allocation] = append(parCat[allocation], *l)
	}
	for _, l := range lignesDe(cats, func(nom string) template.URL {
		return filtreDepenses{Exercice: exercice, Allocation: nom, Source: string(db.SourceAccounting)}.Query()
	}) {
		ns := parCat[l.Nom]
		parDebits(ns)
		c.Categories = append(c.Categories, categorieTotal{ligneTotal: l, Natures: ns})
	}
	return c
}
