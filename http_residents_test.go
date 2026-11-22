package main

import (
	"bytes"
	"database/sql"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// residentsServer serves the directory on an empty in-memory database, with
// one administrator.
func residentsServer(t *testing.T) (*httptest.Server, *sql.DB, *http.Client) {
	t.Helper()
	sqlDB, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	oldAdmins := *adminUsers
	*adminUsers = admin
	t.Cleanup(func() { *adminUsers = oldAdmins })

	mux := http.NewServeMux()
	addAffairesHandlers(mux, sqlDB, "")
	addResidentsHandlers(mux, copro{sqlDB: sqlDB})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return srv, sqlDB, client
}

// envoyerContacts posts an export of the contacts, as the form of the page
// does, and returns the status and the page.
func envoyerContacts(t *testing.T, client *http.Client, user, u, vcard string) (int, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("contacts", "contacts.vcf")
	require.NoError(t, err)
	_, _ = fw.Write([]byte(vcard))
	require.NoError(t, mw.Close())
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, u, &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set(*authHeader, user)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	page, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(page)
}

func residentsParNom(t *testing.T, sqlDB *sql.DB) map[string]db.ResidentDB {
	t.Helper()
	rs, err := db.GetResidents(t.Context(), sqlDB)
	require.NoError(t, err)
	out := make(map[string]db.ResidentDB, len(rs))
	for _, r := range rs {
		out[r.Nom] = r
	}
	return out
}

func TestResidentsHTTP(t *testing.T) {
	srv, sqlDB, client := residentsServer(t)

	t.Run("the phone numbers are for the administrators only", func(t *testing.T) {
		id, err := db.InsertResident(t.Context(), sqlDB, db.ResidentDB{
			Appartement: "D13", Nom: "Charlie Secret", Qualite: db.ResidentHabite, Telephone: "06 00 00 00 13", Origine: db.ResidentDuSite,
		})
		require.NoError(t, err)
		// Not t.Cleanup: by then the context of the test is cancelled.
		defer func() { require.NoError(t, db.DeleteResident(t.Context(), sqlDB, id)) }()

		// The page itself is everybody's, for the co-owners it lists: without
		// the people, their numbers, or the tools to change them.
		status, body := getAs(t, client, membre, srv.URL+"/residents")
		assert.Equal(t, http.StatusOK, status)
		for _, interdit := range []string{"Charlie Secret", "06 00 00 00 13", "D13", "/residents/new", "/residents/export.csv", "/residents/import", "Aucun résident connu"} {
			assert.NotContains(t, body, interdit)
		}
		for _, chemin := range []string{"/residents/export.csv", "/residents/new", "/residents/" + id} {
			status, body := getAs(t, client, membre, srv.URL+chemin)
			assert.Equal(t, http.StatusForbidden, status, chemin)
			assert.NotContains(t, body, "Charlie Secret", chemin)
			assert.NotContains(t, body, "06 00 00 00 13", chemin)
		}
		for _, chemin := range []string{"/residents/new", "/residents/" + id, "/residents/" + id + "/delete", "/residents/supprimer"} {
			status, _ := post(t, client, membre, srv.URL+chemin, url.Values{
				"id": {id}, "appartement": {"C01"}, "nom": {"Intrus"}, "qualite": {"resident"},
			})
			assert.Equal(t, http.StatusForbidden, status, chemin)
		}
		status, _ = envoyerContacts(t, client, membre, srv.URL+"/residents/import", vcardExport)
		assert.Equal(t, http.StatusForbidden, status)

		// Nothing moved. The link is named after what each one finds there.
		assert.Len(t, residentsParNom(t, sqlDB), 1)
		_, body = getAs(t, client, membre, srv.URL+"/affaires")
		assert.Contains(t, body, `href="/residents" >Copropriétaires</a>`)
		_, body = getAs(t, client, admin, srv.URL+"/affaires")
		assert.Contains(t, body, `href="/residents" >Résidents</a>`)
	})

	t.Run("an empty directory lists every apartment", func(t *testing.T) {
		status, body := getAs(t, client, admin, srv.URL+"/residents")
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, 27, strings.Count(body, "Aucun résident connu</span>"))
		assert.Contains(t, body, `href="/residents/new?appartement=C14"`)
	})

	t.Run("importing the contacts", func(t *testing.T) {
		status, body := envoyerContacts(t, client, admin, srv.URL+"/residents/import", vcardExport)
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "dont 6 avec un appartement")
		assert.Contains(t, body, "Camille MARTIN")
		assert.NotContains(t, body, "Plombier", "a contact without an apartment is nobody's business")

		rs := residentsParNom(t, sqlDB)
		require.Len(t, rs, 6)
		assert.Equal(t, "06 12 34 56 78, 05 61 00 00 01", rs["Camille MARTIN"].Telephone)
		assert.Equal(t, admin, rs["Camille MARTIN"].CreatedBy)
		assert.Equal(t, db.ResidentDesContacts, rs["Camille MARTIN"].Origine)

		status, body = getAs(t, client, admin, srv.URL+"/residents")
		require.Equal(t, http.StatusOK, status)
		// html/template writes the "+" of an attribute as "&#43;".
		assert.Contains(t, body, `href="tel:&#43;33612345678"`)
		assert.Contains(t, body, `href="https://wa.me/33612345678"`)
		assert.Contains(t, body, `href="tel:&#43;33561000001"`)
		assert.NotContains(t, body, "wa.me/33561000001", "a landline has no WhatsApp")
		assert.Contains(t, body, `href="mailto:camille@example.com"`)
		assert.Contains(t, body, "compagnon</span>")
		// C01 has two residents and an owner; D02 only has a physiotherapist
		// and D12 somebody who left: nobody is known to live there.
		assert.Equal(t, 25, strings.Count(body, "Aucun résident connu</span>"))
		assert.NotContains(t, body, `new?appartement=C01"`)
		assert.Contains(t, body, `new?appartement=D02"`)
		assert.Contains(t, body, `new?appartement=D12"`)
	})

	t.Run("a note typed here survives the next import", func(t *testing.T) {
		camille := residentsParNom(t, sqlDB)["Camille MARTIN"]
		status, loc := post(t, client, admin, srv.URL+"/residents/"+camille.ID, url.Values{
			"appartement": {"C01"}, "nom": {"Camille MARTIN"}, "qualite": {"resident"}, "detail": {"locataire"},
			"telephone": {"+33 6 12 34 56 78, 0561000001"}, "email": {"camille@example.com"}, "note": {"a les clés du local vélo"},
		})
		require.Equal(t, http.StatusSeeOther, status)
		assert.Contains(t, loc, "/residents")
		assert.NotContains(t, loc, "Camille", "no name in a URL")

		status, body := envoyerContacts(t, client, admin, srv.URL+"/residents/import", vcardExport)
		require.Equal(t, http.StatusOK, status)
		assert.NotContains(t, body, "<h2>Ajoutés", "nobody is new the second time")
		assert.NotContains(t, body, "<h2>Mis à jour")

		rs := residentsParNom(t, sqlDB)
		require.Len(t, rs, 6)
		got := rs["Camille MARTIN"]
		assert.Equal(t, "a les clés du local vélo", got.Note)
		assert.Equal(t, "locataire", got.Detail)
		assert.Equal(t, "06 12 34 56 78, 05 61 00 00 01", got.Telephone)
		assert.Equal(t, db.ResidentDesContacts, got.Origine, "editing a row doesn't take it away from the contacts")
		assert.Equal(t, admin, got.CreatedBy)
	})

	t.Run("who left the contacts is reported, then removed on request", func(t *testing.T) {
		// Everybody but Camille is gone from the phone.
		seule := "BEGIN:VCARD\nVERSION:3.0\nN:MARTIN (C01);Camille;;;\nFN:Camille MARTIN (C01)\nEND:VCARD\n"
		status, body := envoyerContacts(t, client, admin, srv.URL+"/residents/import", seule)
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "Plus dans les contacts")
		rs := residentsParNom(t, sqlDB)
		require.Len(t, rs, 6, "reported, not removed")

		form := url.Values{}
		for nom, r := range rs {
			if nom != "Camille MARTIN" {
				assert.Contains(t, body, `name="id" value="`+r.ID+`"`)
				form.Add("id", r.ID)
			}
		}
		status, _ = post(t, client, admin, srv.URL+"/residents/supprimer", form)
		require.Equal(t, http.StatusSeeOther, status)
		rs = residentsParNom(t, sqlDB)
		require.Len(t, rs, 1)
		assert.Equal(t, "06 12 34 56 78, 05 61 00 00 01", rs["Camille MARTIN"].Telephone, "a contact without a number doesn't erase the number")
	})

	t.Run("adding, editing and removing somebody by hand", func(t *testing.T) {
		status, loc := post(t, client, admin, srv.URL+"/residents/new", url.Values{
			"appartement": {"d07"}, "nom": {"  Sacha   Petit "}, "qualite": {"proprietaire"},
			"telephone": {"06.00.00.00.07"}, "email": {"sacha@example.com; s.petit@example.com"},
		})
		require.Equal(t, http.StatusSeeOther, status)
		assert.Contains(t, loc, "/residents")

		sacha := residentsParNom(t, sqlDB)["Sacha Petit"]
		assert.Equal(t, "D07", sacha.Appartement)
		assert.Equal(t, "06 00 00 00 07", sacha.Telephone)
		assert.Equal(t, "sacha@example.com, s.petit@example.com", sacha.Email)
		assert.Equal(t, db.ResidentDuSite, sacha.Origine)
		assert.Equal(t, admin, sacha.CreatedBy)

		status, body := getAs(t, client, admin, srv.URL+"/residents/"+sacha.ID)
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, `value="Sacha Petit"`)
		assert.Contains(t, body, `<option value="D07" selected>`)
		assert.Contains(t, body, "Saisi ici par "+admin)

		_, body = getAs(t, client, admin, srv.URL+"/residents")
		assert.Contains(t, body, "Propriétaire</span>")
		assert.Contains(t, body, `new?appartement=D07"`, "an owner who doesn't live there isn't a resident")

		for nom, form := range map[string]url.Values{
			"no name":             {"appartement": {"D07"}, "nom": {" "}, "qualite": {"resident"}},
			"unknown apartment":   {"appartement": {"Z99"}, "nom": {"Sacha"}, "qualite": {"resident"}},
			"unknown qualité":     {"appartement": {"D07"}, "nom": {"Sacha"}, "qualite": {"voisin"}},
			"apartment is a path": {"appartement": {"../x"}, "nom": {"Sacha"}, "qualite": {"resident"}},
		} {
			status, _ := post(t, client, admin, srv.URL+"/residents/"+sacha.ID, form)
			assert.Equal(t, http.StatusBadRequest, status, nom)
		}

		status, _ = post(t, client, admin, srv.URL+"/residents/"+sacha.ID+"/delete", nil)
		require.Equal(t, http.StatusSeeOther, status)
		assert.NotContains(t, residentsParNom(t, sqlDB), "Sacha Petit")

		status, _ = getAs(t, client, admin, srv.URL+"/residents/"+sacha.ID)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = post(t, client, admin, srv.URL+"/residents/"+sacha.ID, url.Values{
			"appartement": {"D07"}, "nom": {"Sacha"}, "qualite": {"resident"},
		})
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("the export is a spreadsheet", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/residents/export.csv", nil)
		require.NoError(t, err)
		req.Header.Set(*authHeader, admin)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Disposition"), `attachment; filename="residents-`)
		assert.Equal(t, "\xEF\xBB\xBFAppartement;Nom;Qualité;Détail;Téléphone;E-mail;Note\n"+
			"C01;Camille MARTIN;Résident;locataire;06 12 34 56 78, 05 61 00 00 01;camille@example.com;a les clés du local vélo\n", string(body))
	})

	t.Run("a file that isn't an export of contacts changes nothing", func(t *testing.T) {
		status, body := envoyerContacts(t, client, admin, srv.URL+"/residents/import", "Appartement;Nom\nC01;Camille\n")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "vCard")
		assert.Len(t, residentsParNom(t, sqlDB), 1)
	})
}

func TestImporterResidentsPurge(t *testing.T) {
	sqlDB := openTestDB(t)
	ctx := t.Context()

	_, err := importerResidents(ctx, sqlDB, []byte(vcardExport), "import", false)
	require.NoError(t, err)
	_, err = db.InsertResident(ctx, sqlDB, db.ResidentDB{
		Appartement: "C05", Nom: "Sacha Petit", Qualite: db.ResidentHabite, Origine: db.ResidentDuSite,
	})
	require.NoError(t, err)
	require.Len(t, residentsParNom(t, sqlDB), 7)

	// The wrong file: contacts, but none of the building. Nothing goes.
	autres := "BEGIN:VCARD\nVERSION:3.0\nN:Plombier;Jean;;;\nFN:Jean Plombier\nEND:VCARD\n"
	_, err = importerResidents(ctx, sqlDB, []byte(autres), "import", true)
	require.Error(t, err)
	require.Len(t, residentsParNom(t, sqlDB), 7)

	seule := "BEGIN:VCARD\nVERSION:3.0\nN:MARTIN (C01);Camille;;;\nFN:Camille MARTIN (C01)\nEND:VCARD\n"
	plan, err := importerResidents(ctx, sqlDB, []byte(seule), "import", true)
	require.NoError(t, err)
	assert.Len(t, plan.Absents, 5)

	// Who was typed on the site was never in the contacts: they stay.
	rs := residentsParNom(t, sqlDB)
	assert.Len(t, rs, 2)
	assert.Contains(t, rs, "Camille MARTIN")
	assert.Contains(t, rs, "Sacha Petit")

	_, err = importerResidents(ctx, sqlDB, []byte("pas un vCard"), "import", true)
	assert.ErrorIs(t, err, errPasDeVCard)
}
