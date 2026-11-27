package main

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var rowSeq int

// row builds a row of the expenses table. The date is UTC, as Foncia gives it.
func row(label string, cents int, date, hash string, source db.Source, allocation, nature string) db.ExpenseRow {
	t, err := time.Parse(time.RFC3339, date)
	if err != nil {
		panic(err)
	}
	rowSeq++
	file := ""
	if hash != "" {
		file = "invoices/" + hash + ".pdf"
	}
	return db.ExpenseRow{ID: "id" + strconv.Itoa(rowSeq), ExpenseDocumentDB: db.ExpenseDocumentDB{
		Label: label, Amount: db.Amount(cents), Date: t, HashFile: db.HashFile(hash), FilePath: file, Source: source,
		AccountingKey: db.AccountingKey{Allocation: allocation, ExpenseType: nature},
	}}
}

func TestFournisseurs(t *testing.T) {
	const jour = "2026-03-02T10:00:00Z"
	withFile := row("ACME - CONTRAT POMPE - 23/02/26", 100, jour, "", db.SourceAccounting, "A", "N")
	withFile.FilePath = "invoices/ACME-POMPES  SERVICES - CT01031848 - 2026-02-24 - F26.pdf"
	remb := row("REMB MR MARTIN ETIQUETTES", 500, jour, "", db.SourceAccounting, "A", "N")
	remb.FilePath = "invoices/avis.pdf"

	got := make(map[string]string)
	for _, l := range fournisseurs([]db.ExpenseRow{
		withFile,
		row("ACME - DEPANNAGE", 200, jour, "", db.SourceAccounting, "A", "N"),
		row("MADAME DUPONT - MENAGE 03/2026", 300, jour, "", db.SourceAccounting, "A", "N"),
		row("Appels de fonds - Courrier du 15/06/2026", 400, jour, "", db.SourceAccounting, "A", "N"),
		remb,
		row("MOBILISATION FT TRAVAUX", 600, jour, "", db.SourceAccounting, "A", "N"),
	}) {
		got[l.Label] = l.fournisseur
	}

	assert.Equal(t, map[string]string{
		"ACME - CONTRAT POMPE - 23/02/26":          "ACME-POMPES SERVICES", // From the file name.
		"ACME - DEPANNAGE":                         "ACME-POMPES SERVICES", // No file: learnt from the row above, same label prefix.
		"MADAME DUPONT - MENAGE 03/2026":           "DUPONT",               // Nothing learnt: the label prefix, without the civilité.
		"Appels de fonds - Courrier du 15/06/2026": fournisseurFoncia,
		"REMB MR MARTIN ETIQUETTES":                fournisseurRemb,
		"MOBILISATION FT TRAVAUX":                  fournisseurInconnu,
	}, got)
}

func TestExerciceDe(t *testing.T) {
	for date, want := range map[string]int{
		"2025-06-29T22:00:00Z": 2024, // The 30th of June at midnight in Paris: a closing stamp.
		"2025-06-30T22:00:00Z": 2024, // The 1st of July at midnight: still a closing stamp.
		"2025-07-01T21:59:59Z": 2024, // And so is the 1st of July at 23:59:59.
		"2025-07-02T10:00:00Z": 2025,
		"2025-12-31T23:30:00Z": 2025,
		"2026-03-15T12:00:00Z": 2025,
		"2026-06-15T12:00:00Z": 2025,
	} {
		ts, err := time.Parse(time.RFC3339, date)
		require.NoError(t, err)
		assert.Equal(t, want, exerciceDe(ts.In(paris)), date)
	}
	assert.Equal(t, "2025-2026", nomExercice(2025))
}

// The expenses table holds most expenses several times. These are the shapes
// found in production, and how many real expenses each one is.
func TestPrepareDepensesMergesCopies(t *testing.T) {
	const ac, tr = db.SourceAccounting, db.SourceRepairs

	t.Run("an invoice republished with rewritten labels and an R nature is one expense", func(t *testing.T) {
		ds := prepareDepenses([]db.ExpenseRow{
			row("EDF (PARIS) - EDF - 10/07/24", 40586, "2024-07-15T11:39:45Z", "h1", ac, "GENERALES", "ELECTRICITE"),
			row("EDF - CONSO DU 09/05/2024 - 08/07/2024", 40586, "2024-07-15T11:39:45Z", "h1", ac, "GENERALES", "ELECTRICITE"),
			row("EDF - CONSO DU 09/05/2024 - 08/07/2024 PDL 880", 40586, "2024-07-15T11:39:45Z", "h1", ac, "GENERALES", "ELECTRICITE R"),
		})
		require.Len(t, ds, 1)
		assert.Len(t, ds[0].IDs, 3)
		assert.Equal(t, 2, ds[0].Doublons())
		assert.Equal(t, "ELECTRICITE", ds[0].Nature)
		assert.Equal(t, "EDF - CONSO DU 09/05/2024 - 08/07/2024 PDL 880", ds[0].Label, "the longest label is kept")
	})

	t.Run("one invoice file split in two amounts or two allocations stays two expenses", func(t *testing.T) {
		ds := prepareDepenses([]db.ExpenseRow{
			row("Honoraires du 01/01 au 09/01", 15618, "2024-01-22T13:13:21Z", "h2", ac, "GENERALES", "HONORAIRES"),
			row("Honoraires du 10/01 au 31/01", 39016, "2024-01-22T13:13:21Z", "h2", ac, "GENERALES", "HONORAIRES"),
			row("ENTRETIEN ASCENSEUR 2T2024", 41049, "2024-04-09T14:35:07Z", "h3", ac, "ASCENSEUR D", "CONTRAT"),
			row("ENTRETIEN ASCENSEUR 2T2024", 41049, "2024-04-09T14:35:07Z", "h3", ac, "ASCENSEUR C", "CONTRAT"),
		})
		assert.Len(t, ds, 4)
	})

	t.Run("two invoices that only differ by their file are two expenses", func(t *testing.T) {
		ds := prepareDepenses([]db.ExpenseRow{
			row("ACME", 79200, "2024-06-15T00:00:00Z", "h4", ac, "GENERALES", "ENTRETIEN"),
			row("ACME", 79200, "2024-06-15T00:00:00Z", "h5", ac, "GENERALES", "ENTRETIEN"),
		})
		assert.Len(t, ds, 2)
	})

	t.Run("without a file, a closing stamp is a copy of the dated row and takes its date", func(t *testing.T) {
		ds := prepareDepenses([]db.ExpenseRow{
			row("FRAIS DE TENUE DE COMPTE", 6400, "2025-06-29T22:00:00Z", "", ac, "GENERALES", "FRAIS BANCAIRES NR"),
			row("FRAIS BANCAIRES", 6400, "2025-02-05T09:00:00Z", "", ac, "GENERALES", "FRAIS BANCAIRES"),
		})
		require.Len(t, ds, 1)
		assert.Equal(t, "05/02/2025", ds[0].Local.Format("02/01/2006"))
		assert.Equal(t, 2024, ds[0].Exercice)
	})

	t.Run("without a file, the same amount on two days is two expenses, in two exercises too", func(t *testing.T) {
		ds := prepareDepenses([]db.ExpenseRow{
			row("FRAIS BANCAIRES", 530, "2025-02-05T09:00:00Z", "", ac, "GENERALES", "FRAIS BANCAIRES"),
			row("FRAIS BANCAIRES", 530, "2025-03-05T09:00:00Z", "", ac, "GENERALES", "FRAIS BANCAIRES"),
			row("FRAIS BANCAIRES", 530, "2025-08-05T09:00:00Z", "", ac, "GENERALES", "FRAIS BANCAIRES"),
		})
		assert.Len(t, ds, 3)
	})

	t.Run("works accounts: the same amount under three labels and natures is one expense", func(t *testing.T) {
		ds := prepareDepenses([]db.ExpenseRow{
			row("ASCENSEURS SA REPARATION ASC BAT C", 3066685, "2025-06-29T22:00:00Z", "", tr, "GENERALES", "HCC TRAVAUX DECIDES AG"),
			row("ASC - REPARATION ASC BAT C", 3066685, "2025-06-29T22:00:00Z", "", tr, "GENERALES", "HCC TRAVAUX DECIDES AG"),
			row("ASC - REPARATION ASCENSEUR BAT C", 3066685, "2025-06-29T22:00:00Z", "", tr, "GENERALES", "HCC HONORAIRES"),
		})
		require.Len(t, ds, 1)
		assert.Equal(t, 2024, ds[0].Exercice)
	})

	t.Run("most recent first", func(t *testing.T) {
		ds := prepareDepenses([]db.ExpenseRow{
			row("A", 1, "2025-02-05T09:00:00Z", "", ac, "G", "N"),
			row("B", 2, "2026-02-05T09:00:00Z", "", ac, "G", "N"),
		})
		require.Len(t, ds, 2)
		assert.Equal(t, "B", ds[0].Label)
	})
}

func TestResumeComptes(t *testing.T) {
	const ac, tr = db.SourceAccounting, db.SourceRepairs
	ds := prepareDepenses([]db.ExpenseRow{
		row("ACME - A", 30000, "2025-08-15T12:00:00Z", "", ac, "GENERALES", "ENTRETIEN"),
		row("ACME - B", 10000, "2025-10-15T12:00:00Z", "hb", ac, "GENERALES", "ELECTRICITE"),
		row("ACME - B republié", 10000, "2025-10-15T12:00:00Z", "hb", ac, "GENERALES", "ELECTRICITE R"),
		row("BETA - C", 50000, "2026-03-15T12:00:00Z", "", tr, "TRAVAUX", "TOITURE"),
		row("VIRT ASSURANCE", -20000, "2026-04-15T12:00:00Z", "", ac, "GENERALES", "ENTRETIEN"),
		row("ACME - D", 7000, "2025-01-15T12:00:00Z", "", ac, "GENERALES", "ENTRETIEN"),
		row("GAMMA - E", 9900, "2025-01-15T12:00:00Z", "", ac, "ASCENSEUR", "CONTRAT"),
		row("VIEUX - F", 1, "2021-06-15T12:00:00Z", "", ac, "GENERALES", "ENTRETIEN"),
	})

	c := resumeComptes(ds, 2025)

	assert.Equal(t, "2025-2026", c.Nom)
	assert.Equal(t, "2024-2025", c.Precedent)
	assert.Equal(t, []int{2025, 2024, 2020}, c.Exercices)
	assert.Equal(t, db.Amount(40000), c.Courant, "the republished invoice counts once")
	assert.Equal(t, db.Amount(20000), c.CourantCredits, "credits are shown positive and never netted against the debits")
	assert.Equal(t, db.Amount(50000), c.Travaux, "the works accounts are kept apart")
	assert.Equal(t, db.Amount(16900), c.CourantPrec)
	assert.Equal(t, 4, c.N)
	assert.Equal(t, 1, c.Doublons)

	assert.Equal(t, "juil.", c.Mois[0].Nom, "the exercise starts in July")
	assert.Equal(t, db.Amount(30000), c.Mois[1].Debits)
	assert.Equal(t, db.Amount(10000), c.Mois[3].Debits)
	assert.Equal(t, 100, c.Mois[1].Pct)
	assert.Equal(t, 33, c.Mois[3].Pct)

	require.Len(t, c.Categories, 1, "ASCENSEUR only has expenses in 2024-2025, TRAVAUX is a works account")
	generales := c.Categories[0]
	assert.Equal(t, "GENERALES", generales.Nom)
	assert.Equal(t, db.Amount(40000), generales.Debits)
	assert.Equal(t, db.Amount(20000), generales.Credits)
	assert.Equal(t, db.Amount(7000), generales.Precedent)
	require.Len(t, generales.Natures, 2)
	assert.Equal(t, "ENTRETIEN", generales.Natures[0].Nom, "largest first")
	assert.Equal(t, db.Amount(30000), generales.Natures[0].Debits)
	assert.Equal(t, "allocation=GENERALES&exercice=2025&nature=ENTRETIEN&source=accounting", string(generales.Natures[0].Query))
	assert.Equal(t, "ELECTRICITE", generales.Natures[1].Nom, "R and plain natures are one line")

	require.Len(t, c.TravauxLots, 1)
	assert.Equal(t, db.Amount(50000), c.TravauxLots[0].Debits)

	require.Len(t, c.Fournisseurs, 3)
	assert.Equal(t, "BETA", c.Fournisseurs[0].Nom)
	assert.Equal(t, "ACME", c.Fournisseurs[1].Nom)
	assert.Equal(t, db.Amount(40000), c.Fournisseurs[1].Debits)
	assert.Equal(t, db.Amount(7000), c.Fournisseurs[1].Precedent)
	assert.Equal(t, fournisseurInconnu, c.Fournisseurs[2].Nom)

	t.Run("the drill-down filter keeps what the totals counted", func(t *testing.T) {
		assert.Len(t, filtrer(ds, filtreDepenses{Exercice: 2025, Fournisseur: "ACME"}), 2)
		assert.Len(t, filtrer(ds, filtreDepenses{Exercice: 2025, Allocation: "GENERALES", Nature: "ELECTRICITE"}), 1)
		assert.Len(t, filtrer(ds, filtreDepenses{Tout: true, Source: "repairs"}), 1)
		assert.Len(t, filtrer(ds, filtreDepenses{Tout: true, Q: "acme 300,00"}), 1, "every word must match, the amount included")
		assert.Len(t, filtrer(ds, filtreDepenses{Tout: true}), 7)
	})

	t.Run("a closing stamp of the 1st of July counts in June", func(t *testing.T) {
		c := resumeComptes(prepareDepenses([]db.ExpenseRow{
			row("REGUL", 1200, "2026-07-01T21:59:59Z", "", ac, "GENERALES", "ENTRETIEN"),
		}), 2025)
		assert.Equal(t, db.Amount(1200), c.Mois[11].Debits)
		assert.Zero(t, c.Mois[0].Debits)
	})
}

// coproServer serves the comptes routes on an empty in-memory database,
// without the rest of the serve stack (which needs a Foncia token). The client
// doesn't follow redirects: the POST handlers answer 303 and the tests assert
// on the Location.
func coproServer(t *testing.T) (*httptest.Server, *sql.DB, *http.Client) {
	t.Helper()
	sqlDB, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	mux := http.NewServeMux()
	addComptesHandlers(mux, sqlDB, "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return srv, sqlDB, client
}

func get(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := client.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// post sends the form as the given user and returns the status and Location.
func post(t *testing.T, client *http.Client, user, url string, form url.Values) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.Header.Set(*authHeader, user)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func TestComptesHTTP(t *testing.T) {
	ctx := t.Context()
	srv, sqlDB, client := coproServer(t)

	entretien := db.AccountingKey{Allocation: "CHARGES GENERALES", ExpenseType: "ENTRETIEN"}
	require.NoError(t, db.UpsertExpensesWithDB(ctx, sqlDB,
		db.ExpenseDocumentDB{Label: "ACME - CONTRAT", Amount: 4000000, Date: time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC), HashFile: "h1", Source: db.SourceAccounting, AccountingKey: entretien},
		db.ExpenseDocumentDB{Label: "ACME - CONTRAT 2026", Amount: 4000000, Date: time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC), HashFile: "h1", Source: db.SourceAccounting, AccountingKey: entretien},
		db.ExpenseDocumentDB{Label: "BETA - TOITURE", Amount: 900000, Date: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC), Source: db.SourceRepairs, AccountingKey: db.AccountingKey{Allocation: "TRAVAUX", ExpenseType: "TOITURE"}},
	))

	t.Run("the exercise's page shows the totals and no budget", func(t *testing.T) {
		status, body := get(t, client, srv.URL+"/comptes?exercice=2025")
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "40000,00 €")
		assert.NotContains(t, body, "80000,00 €", "the invoice published twice counts once")
		assert.Contains(t, body, "Aucun budget saisi pour 2025-2026.")
		assert.Contains(t, body, "/comptes/depenses?exercice=2025&amp;fournisseur=ACME")
	})

	t.Run("the budget is compared to the day-to-day account only", func(t *testing.T) {
		status, loc := post(t, client, "alice@example.com", srv.URL+"/comptes/budget", url.Values{"exercice": {"2025"}, "montant": {"50 000"}, "note": {"Voté en AG"}})
		assert.Equal(t, http.StatusSeeOther, status)
		assert.Contains(t, loc, "/comptes?exercice=2025")

		_, body := get(t, client, srv.URL+"/comptes?exercice=2025")
		assert.Contains(t, body, "(80 %)")
		assert.Contains(t, body, "reste 10000,00 €")
		assert.Contains(t, body, "Saisi par alice@example.com")

		post(t, client, "", srv.URL+"/comptes/budget", url.Values{"exercice": {"2025"}, "montant": {"30000"}})
		_, body = get(t, client, srv.URL+"/comptes?exercice=2025")
		assert.Contains(t, body, "dépassement de 10000,00 €")

		status, _ = post(t, client, "", srv.URL+"/comptes/budget", url.Values{"exercice": {"2025"}, "montant": {"beaucoup"}})
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("the expenses list filters", func(t *testing.T) {
		_, body := get(t, client, srv.URL+"/comptes/depenses?exercice=2025&source=repairs")
		assert.Contains(t, body, "BETA - TOITURE")
		assert.NotContains(t, body, "ACME - CONTRAT")
		assert.Contains(t, body, "1 ligne · 9000,00 € dépensés")

		_, body = get(t, client, srv.URL+"/comptes/depenses?exercice=2019")
		assert.Contains(t, body, "Aucune dépense ne correspond.")
	})

	t.Run("an expense answers to the id of any of its copies", func(t *testing.T) {
		rows, err := db.GetExpenseRows(ctx, sqlDB)
		require.NoError(t, err)
		var copies []string
		for _, r := range rows {
			if r.HashFile == "h1" {
				copies = append(copies, r.ID)
			}
		}
		require.Len(t, copies, 2)
		for _, id := range copies {
			status, body := get(t, client, srv.URL+"/comptes/depenses/"+id)
			assert.Equal(t, http.StatusOK, status)
			assert.Contains(t, body, "publié cette dépense 2 fois")
		}
		status, _ := get(t, client, srv.URL+"/comptes/depenses/nope")
		assert.Equal(t, http.StatusNotFound, status)

	})
}

func TestParseEuros(t *testing.T) {
	for in, want := range map[string]db.Amount{
		"39,85": 3985, "245,3": 24530, "142": 14200, "5,90€": 590, "1 234,50 €": 123450,
		"55 000": 5500000, "0.5": 50, ",5": 50, "-12,00": -1200,
	} {
		got, err := db.ParseEuros(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "abc", "1,234", "1.2.3", "12 €uros"} {
		_, err := db.ParseEuros(in)
		assert.Error(t, err, in)
	}
	assert.Equal(t, "1234,50", db.Amount(123450).Input(), "what the form shows parses back")
}
