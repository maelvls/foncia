package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fauxWhatsApp is the whatsapp service as far as the residents go: its
// address book, behind the token, filtered by the regular expression asked
// for like the real one does. down makes it fail.
func fauxWhatsApp(t *testing.T, down *bool) *whatsappCollecteur {
	t.Helper()
	carnet := []map[string]string{
		{"jid": "33612345678@s.whatsapp.net", "full_name": "Camille MARTIN (C01)"},
		{"jid": "33712345678@s.whatsapp.net", "full_name": "Alex Durand (prop C01)"},
		{"jid": "33612000003@s.whatsapp.net", "full_name": "Sacha (ex loc D12)"},
		{"jid": "33561000099@s.whatsapp.net", "full_name": "Jean Plombier"},
		// Known by an identifier that hides the number: nobody to call.
		{"jid": "123456789012345@lid", "full_name": "Dominique (C02)"},
		{"jid": "33600000009:4@s.whatsapp.net", "full_name": "Claude Roux (kiné d02)"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("Authorization") != "Bearer tok":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case *down:
			http.Error(w, "the link is lost", http.StatusServiceUnavailable)
		case r.URL.Path != "/internal/contacts":
			http.NotFound(w, r)
		default:
			match, err := regexp.Compile(r.URL.Query().Get("match"))
			if !assert.NoError(t, err) || !assert.NotEmpty(t, r.URL.Query().Get("match"), "the whole address book must not be asked for") {
				http.Error(w, "bad match", http.StatusBadRequest)
				return
			}
			var out []map[string]string
			for _, c := range carnet {
				if match.MatchString(c["full_name"]) {
					out = append(out, c)
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		}
	}))
	t.Cleanup(srv.Close)
	return &whatsappCollecteur{client: srv.Client(), base: srv.URL, token: "tok"}
}

// postPage posts an empty form as the given user and returns the status and
// the page.
func postPage(t *testing.T, client *http.Client, user, u string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, u, nil)
	require.NoError(t, err)
	req.Header.Set(*authHeader, user)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	page, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(page)
}

func TestCarnetWhatsApp(t *testing.T) {
	down := false
	cartes, err := fauxWhatsApp(t, &down).carnet(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []contactVCard{
		{NomComplet: "Camille MARTIN (C01)", Telephones: []string{"+33612345678"}},
		{NomComplet: "Alex Durand (prop C01)", Telephones: []string{"+33712345678"}},
		{NomComplet: "Sacha (ex loc D12)", Telephones: []string{"+33612000003"}},
		{NomComplet: "Claude Roux (kiné d02)", Telephones: []string{"+33600000009"}},
	}, cartes)

	down = true
	_, err = fauxWhatsApp(t, &down).carnet(t.Context())
	assert.ErrorContains(t, err, "503")
}

func TestResidentsWhatsAppHTTP(t *testing.T) {
	sqlDB := openTestDB(t)
	oldAdmins := *adminUsers
	*adminUsers = admin
	t.Cleanup(func() { *adminUsers = oldAdmins })

	down := false
	mux := http.NewServeMux()
	addResidentsHandlers(mux, copro{sqlDB: sqlDB, carnet: fauxWhatsApp(t, &down).carnet})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := srv.Client()

	_, body := getAs(t, client, admin, srv.URL+"/residents")
	assert.Contains(t, body, "Relire maintenant")
	assert.Contains(t, body, "Pas encore lu.")

	status, _ := postPage(t, client, membre, srv.URL+"/residents/whatsapp")
	assert.Equal(t, http.StatusForbidden, status)
	assert.Empty(t, residentsParNom(t, sqlDB))

	status, body = postPage(t, client, admin, srv.URL+"/residents/whatsapp")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "Lecture des contacts de WhatsApp")
	assert.Contains(t, body, "Camille MARTIN")
	assert.NotContains(t, body, "Plombier")

	rs := residentsParNom(t, sqlDB)
	require.Len(t, rs, 4)
	assert.Equal(t, db.ResidentDB{
		ID: rs["Camille MARTIN"].ID, Appartement: "C01", Nom: "Camille MARTIN", Qualite: db.ResidentHabite,
		Telephone: "06 12 34 56 78", Origine: db.ResidentDeWhatsApp, CreatedBy: "whatsapp",
		CreatedAt: rs["Camille MARTIN"].CreatedAt, UpdatedAt: rs["Camille MARTIN"].UpdatedAt,
	}, rs["Camille MARTIN"])
	assert.Equal(t, db.ResidentAncien, rs["Sacha"].Qualite)
	assert.Equal(t, "D02", rs["Claude Roux"].Appartement)

	_, body = getAs(t, client, admin, srv.URL+"/residents")
	assert.Contains(t, body, "Dernière lecture le")
	assert.Contains(t, body, "4 personnes, 4 ajoutées.")
	assert.Contains(t, body, "Un export des contacts les ajoute", "the form says an export only adds to WhatsApp")
	_, body = getAs(t, client, admin, srv.URL+"/residents/"+rs["Camille MARTIN"].ID)
	assert.Contains(t, body, "lus par WhatsApp")

	t.Run("reading again changes nothing", func(t *testing.T) {
		status, body := postPage(t, client, admin, srv.URL+"/residents/whatsapp")
		require.Equal(t, http.StatusOK, status)
		assert.NotContains(t, body, "<h2>Ajoutés")
		assert.NotContains(t, body, "<h2>Mis à jour")
		assert.Len(t, residentsParNom(t, sqlDB), 4)
		_, body = getAs(t, client, admin, srv.URL+"/residents")
		assert.Contains(t, body, "4 personnes.")
	})

	t.Run("an export adds the e-mail and the other number, and nobody twice", func(t *testing.T) {
		status, _ := envoyerContacts(t, client, admin, srv.URL+"/residents/import", vcardExport)
		require.Equal(t, http.StatusOK, status)
		rs := residentsParNom(t, sqlDB)
		// Camille, Alex, Sacha and Claude are the same people in both. The
		// export is alone to know Dominique and Éloïse-Marie.
		require.Len(t, rs, 6)
		all, err := db.GetResidents(t.Context(), sqlDB)
		require.NoError(t, err)
		require.Len(t, all, 6, "nobody twice under the same name")
		camille := rs["Camille MARTIN"]
		assert.Equal(t, "06 12 34 56 78, 05 61 00 00 01", camille.Telephone)
		assert.Equal(t, "camille@example.com", camille.Email)
		assert.Equal(t, db.ResidentDeWhatsApp, camille.Origine)
		assert.Equal(t, db.ResidentDesContacts, rs["Dominique"].Origine)

		status, body := postPage(t, client, admin, srv.URL+"/residents/whatsapp")
		require.Equal(t, http.StatusOK, status)
		assert.NotContains(t, body, "<h2>Mis à jour", "WhatsApp's number is among Camille's: nothing to redo")
		assert.NotContains(t, body, "Plus dans les contacts", "who only the export knows isn't WhatsApp's to report")
		assert.Equal(t, camille, residentsParNom(t, sqlDB)["Camille MARTIN"])
	})

	t.Run("a whatsapp service that fails is said, and loses nobody", func(t *testing.T) {
		down = true
		status, _ := postPage(t, client, admin, srv.URL+"/residents/whatsapp")
		assert.Equal(t, http.StatusBadGateway, status)
		assert.Len(t, residentsParNom(t, sqlDB), 6)
		_, body := getAs(t, client, admin, srv.URL+"/residents")
		assert.Contains(t, body, "a échoué")
		assert.Contains(t, body, "503")
	})

	t.Run("without a whatsapp service there is nothing to read", func(t *testing.T) {
		mux := http.NewServeMux()
		addResidentsHandlers(mux, copro{sqlDB: sqlDB})
		seul := httptest.NewServer(mux)
		t.Cleanup(seul.Close)
		_, body := getAs(t, seul.Client(), admin, seul.URL+"/residents")
		assert.NotContains(t, body, "Relire maintenant")
		assert.Contains(t, body, "Importer depuis les contacts du téléphone")
		status, _ := postPage(t, seul.Client(), admin, seul.URL+"/residents/whatsapp")
		assert.Equal(t, http.StatusNotFound, status)
	})
}

func TestSynchroniserResidentsEnBoucle(t *testing.T) {
	sqlDB := openTestDB(t)
	old := *residentsPeriod
	*residentsPeriod = time.Hour
	t.Cleanup(func() { *residentsPeriod = old })

	down := false
	ctx, cancel := context.WithCancel(t.Context())
	fini := make(chan struct{})
	go func() {
		defer close(fini)
		synchroniserResidentsEnBoucle(ctx, sqlDB, fauxWhatsApp(t, &down).carnet)
	}()
	// The first reading doesn't wait for the period.
	require.Eventually(t, func() bool {
		_, lu := dernierCarnet(context.Background(), sqlDB)
		return lu
	}, 5*time.Second, 10*time.Millisecond)
	rs, err := db.GetResidents(t.Context(), sqlDB)
	require.NoError(t, err)
	assert.Len(t, rs, 4)
	etat, _ := dernierCarnet(t.Context(), sqlDB)
	assert.Equal(t, 4, etat.Retenus)
	assert.Equal(t, 4, etat.Ajouts)
	assert.Empty(t, etat.Erreur)

	cancel()
	select {
	case <-fini:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop didn't stop with its context")
	}

	// No whatsapp service, or the reading turned off: nothing runs.
	synchroniserResidentsEnBoucle(t.Context(), sqlDB, nil)
	*residentsPeriod = 0
	synchroniserResidentsEnBoucle(t.Context(), sqlDB, fauxWhatsApp(t, &down).carnet)
}
