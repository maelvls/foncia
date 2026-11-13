package main

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// coproServer serves the affaires and comptes routes on an empty in-memory
// database, without the rest of the serve stack (which needs a Foncia token).
// The client doesn't follow redirects: the POST handlers answer 303 and the
// tests assert on the Location.
func coproServer(t *testing.T) (*httptest.Server, *sql.DB, *http.Client) {
	t.Helper()
	sqlDB, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	mux := http.NewServeMux()
	addAffairesHandlers(mux, sqlDB, "")
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

func TestAffairesHTTP(t *testing.T) {
	ctx := t.Context()
	srv, sqlDB, client := coproServer(t)

	t.Run("an empty list renders", func(t *testing.T) {
		status, body := get(t, client, srv.URL+"/affaires")
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "Aucune affaire.")
	})

	var id string
	t.Run("creating an affaire redirects to its dossier", func(t *testing.T) {
		status, loc := post(t, client, "", srv.URL+"/affaires/new", url.Values{
			"numero":           {"1"},
			"titre":            {"Ampoule du hall à changer"},
			"localisation":     {"Hall A"},
			"responsable":      {"Camille"},
			"date_signalement": {"18/06/2024"},
			"statut":           {"en_cours"},
			"relance_date":     {"13/08/2026", ""},
			"relance_note":     {"mail au syndic", ""},
		})
		assert.Equal(t, http.StatusSeeOther, status)

		affaires, err := db.GetAffaires(ctx, sqlDB, db.AffaireStatutEnCours)
		require.NoError(t, err)
		require.Len(t, affaires, 1)
		id = affaires[0].ID
		assert.True(t, strings.HasPrefix(loc, "/affaires/"+id+"?flash="), "got Location=%q", loc)
		assert.Equal(t, "Ampoule du hall à changer", affaires[0].Titre)
		require.Len(t, affaires[0].Relances, 1, "the blank relance line of the form must be dropped")
		assert.Equal(t, "mail au syndic", affaires[0].Relances[0].Note)
	})

	t.Run("the dossier and the edit form render", func(t *testing.T) {
		status, body := get(t, client, srv.URL+"/affaires/"+id)
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "Ampoule du hall à changer")
		assert.Contains(t, body, "Pas encore de commentaire.")

		status, body = get(t, client, srv.URL+"/affaires/"+id+"/edit")
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, `value="Camille"`)

		status, _ = get(t, client, srv.URL+"/affaires/nope")
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("a comment is signed with the proxy's user, who alone sees its delete button", func(t *testing.T) {
		status, _ := post(t, client, "Alice@Example.com", srv.URL+"/affaires/"+id+"/commentaires", url.Values{"texte": {"Le syndic a répondu."}})
		assert.Equal(t, http.StatusSeeOther, status)

		cs, err := db.GetCommentaires(ctx, sqlDB, id)
		require.NoError(t, err)
		require.Len(t, cs, 1)
		assert.Equal(t, "alice@example.com", cs[0].Auteur)

		_, body := get(t, client, srv.URL+"/affaires/"+id)
		assert.Contains(t, body, "Le syndic a répondu.")
		assert.NotContains(t, body, "/commentaires/"+cs[0].ID+"/delete", "an anonymous reader is not the author")

		status, _ = post(t, client, "", srv.URL+"/affaires/"+id+"/commentaires", url.Values{"texte": {"  "}})
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("an e-mail and a link can be attached, but not a javascript: URL", func(t *testing.T) {
		status, _ := post(t, client, "", srv.URL+"/affaires/"+id+"/liens", url.Values{
			"kind": {"email"}, "titre": {"Re: devis"}, "url": {"https://mail.example.com/x"}, "note": {"De l'électricien, le 2 mars"},
		})
		assert.Equal(t, http.StatusSeeOther, status)

		status, _ = post(t, client, "", srv.URL+"/affaires/"+id+"/liens", url.Values{"kind": {"lien"}, "url": {"javascript:alert(1)"}})
		assert.Equal(t, http.StatusBadRequest, status)

		liens, err := db.GetLiens(ctx, sqlDB, id)
		require.NoError(t, err)
		require.Len(t, liens, 1)
		assert.Equal(t, db.LienEmail, liens[0].Kind)

		_, body := get(t, client, srv.URL+"/affaires/"+id)
		assert.Contains(t, body, `href="https://mail.example.com/x"`)
	})

	t.Run("an invoice is found by the search, attached once, and counted", func(t *testing.T) {
		require.NoError(t, db.UpsertExpensesWithDB(ctx, sqlDB, db.ExpenseDocumentDB{
			Label: "LUMIERE SARL - REMPLACEMENT AMPOULES", Amount: 12345,
			Date: time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC), Source: db.SourceAccounting,
			AccountingKey: db.AccountingKey{Allocation: "CHARGES GENERALES", ExpenseType: "ENTRETIEN"},
		}))
		rows, err := db.GetExpenseRows(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, rows, 1)

		status, body := get(t, client, srv.URL+"/affaires/"+id+"/lier?kind=depense&q=ampoules+lumiere")
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, `value="`+rows[0].ID+`"`)
		_, body = get(t, client, srv.URL+"/affaires/"+id+"/lier?kind=depense&q=plomberie")
		assert.Contains(t, body, "Aucun résultat.")

		form := url.Values{"kind": {"depense"}, "ref": {rows[0].ID}}
		status, _ = post(t, client, "", srv.URL+"/affaires/"+id+"/liens", form)
		assert.Equal(t, http.StatusSeeOther, status)
		_, loc := post(t, client, "", srv.URL+"/affaires/"+id+"/liens", form)
		assert.Contains(t, loc, "D%C3%A9j%C3%A0", "attaching twice says so instead of duplicating")

		status, _ = post(t, client, "", srv.URL+"/affaires/"+id+"/liens", url.Values{"kind": {"depense"}, "ref": {"nope"}})
		assert.Equal(t, http.StatusNotFound, status)

		_, body = get(t, client, srv.URL+"/affaires/"+id)
		assert.Contains(t, body, "123,45 € facturés")
		_, body = get(t, client, srv.URL+"/affaires")
		assert.Contains(t, body, "2 pièces")
		assert.Contains(t, body, "123,45 € facturés")
		_, body = get(t, client, srv.URL+"/comptes/depenses/"+rows[0].ID)
		assert.Contains(t, body, "n°1 Ampoule du hall à changer")
	})

	t.Run("a link follows its expense when Foncia attaches a PDF to it", func(t *testing.T) {
		before, err := db.GetExpenseRows(ctx, sqlDB)
		require.NoError(t, err)
		withPDF := before[0].ExpenseDocumentDB
		withPDF.HashFile = "66dafe199f013b45ee991c96"
		require.NoError(t, db.UpsertExpensesWithDB(ctx, sqlDB, withPDF))

		after, err := db.GetExpenseRows(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, after, 1)
		require.NotEqual(t, before[0].ID, after[0].ID, "the id is derived from the hash file")

		byRef, err := db.GetAffairesByRef(ctx, sqlDB, db.LienDepense)
		require.NoError(t, err)
		require.Len(t, byRef[after[0].ID], 1)
		assert.Equal(t, id, byRef[after[0].ID][0].ID)
	})

	t.Run("lever stamps today's date, rouvrir clears it", func(t *testing.T) {
		status, _ := post(t, client, "", srv.URL+"/affaires/"+id+"/statut", url.Values{"statut": {"levee"}})
		assert.Equal(t, http.StatusSeeOther, status)
		a, err := db.GetAffaire(ctx, sqlDB, id)
		require.NoError(t, err)
		assert.Equal(t, db.AffaireStatutLevee, a.Statut)
		assert.Equal(t, time.Now().In(paris).Format("02/01/2006"), a.DateLevee)
		assert.Len(t, a.Relances, 1, "the relances survive a change of statut")

		post(t, client, "", srv.URL+"/affaires/"+id+"/statut", url.Values{"statut": {"en_cours"}})
		a, err = db.GetAffaire(ctx, sqlDB, id)
		require.NoError(t, err)
		assert.Equal(t, db.AffaireStatutEnCours, a.Statut)
		assert.Empty(t, a.DateLevee)
	})

	t.Run("updating replaces the fiche", func(t *testing.T) {
		status, _ := post(t, client, "", srv.URL+"/affaires/"+id, url.Values{"numero": {"1"}, "titre": {"Ampoule changée"}, "statut": {"levee"}, "date_levee": {"01/12/2026"}})
		assert.Equal(t, http.StatusSeeOther, status)
		a, err := db.GetAffaire(ctx, sqlDB, id)
		require.NoError(t, err)
		assert.Equal(t, "Ampoule changée", a.Titre)
		assert.Equal(t, "01/12/2026", a.DateLevee)

		status, _ = post(t, client, "", srv.URL+"/affaires/"+id, url.Values{"numero": {"1"}, "titre": {""}})
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("deleting removes the affaire with its comments and links", func(t *testing.T) {
		status, _ := post(t, client, "", srv.URL+"/affaires/"+id+"/delete", nil)
		assert.Equal(t, http.StatusSeeOther, status)

		for _, table := range []string{"affaires", "affaires_commentaires", "affaires_liens", "affaires_relances"} {
			var n int
			require.NoError(t, sqlDB.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
			assert.Zero(t, n, table)
		}
	})
}
