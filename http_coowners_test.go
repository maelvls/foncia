package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The co-owners as Foncia gives them: a couple, an SCI, and somebody who only
// owns a parking space.
var coownersFoncia = []coownerRow{
	{Name: "M. OU MME MARTIN", Address: "3 RUE DE LA GARE 31000 TOULOUSE", Apartment: "C01", Parking: []string{"44", "45"}},
	{Name: "SCI DES LILAS", Address: "1 RUE DES ACACIAS 75011 PARIS", Apartment: "D08", Parking: []string{"49"}},
	{Name: "MME GARAGE", Address: "2 RUE AILLEURS 31000 TOULOUSE", Parking: []string{"74"}},
}

// coownersServer serves the page of the residents with the given co-owners
// behind it, with one administrator.
func coownersServer(t *testing.T, coowners coownersFunc) (*httptest.Server, *http.Client) {
	t.Helper()
	sqlDB := openTestDB(t)
	oldAdmins := *adminUsers
	*adminUsers = admin
	t.Cleanup(func() { *adminUsers = oldAdmins })

	for _, r := range []db.ResidentDB{
		{Appartement: "C01", Nom: "Camille MARTIN", Qualite: db.ResidentHabite, Telephone: "06 12 34 56 78"},
		{Appartement: "D08", Nom: "Sacha Petit", Qualite: db.ResidentHabite, Telephone: "07 00 00 00 08", Note: "la SCI est celle de son père"},
		{Appartement: "D08", Nom: "Alex Durand", Qualite: db.ResidentAncien, Telephone: "07 00 00 00 09"},
	} {
		r.Origine = db.ResidentDuSite
		_, err := db.InsertResident(t.Context(), sqlDB, r)
		require.NoError(t, err)
	}

	mux := http.NewServeMux()
	addResidentsHandlers(mux, copro{sqlDB: sqlDB, coowners: coowners})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return srv, client
}

// lot returns the part of the page about one apartment.
func lot(t *testing.T, body, code string) string {
	t.Helper()
	_, apres, ok := strings.Cut(body, `<tbody data-lot="`+code+`"`)
	require.True(t, ok, "no apartment %s on the page", code)
	bloc, _, _ := strings.Cut(apres, "</tbody>")
	return bloc
}

func TestResidentsEtCoowners(t *testing.T) {
	srv, client := coownersServer(t, func(context.Context) ([]coownerRow, error) { return coownersFoncia, nil })

	t.Run("an administrator sees who owns each apartment above who lives there", func(t *testing.T) {
		status, body := getAs(t, client, admin, srv.URL+"/residents")
		require.Equal(t, http.StatusOK, status)

		c01 := lot(t, body, "C01")
		assert.Contains(t, c01, "M. OU MME MARTIN")
		assert.Contains(t, c01, "3 RUE DE LA GARE 31000 TOULOUSE · parkings 44, 45")
		assert.Contains(t, c01, "Camille MARTIN")
		assert.NotContains(t, c01, "SCI DES LILAS")

		d08 := lot(t, body, "D08")
		assert.Contains(t, d08, "SCI DES LILAS")
		assert.Contains(t, d08, "· parking 49")
		assert.Contains(t, d08, "Sacha Petit")
		assert.Contains(t, d08, "la SCI est celle de son père")
		// The search finds the people of an apartment by its co-owner.
		assert.Contains(t, d08, `data-q="D08 T3 SCI DES LILAS 1 RUE DES ACACIAS 75011 PARIS"`)
		assert.NotContains(t, d08, "Alex Durand", "who left is listed apart")

		// Foncia knows nobody for the other apartments, and says so.
		assert.Contains(t, lot(t, body, "C02"), "Pas de copropriétaire connu de Foncia.")
		assert.Contains(t, lot(t, body, "C02"), "Aucun résident connu")

		// Who only owns a parking space has no apartment to be shown under.
		_, apres, ok := strings.Cut(body, "Copropriétaires sans appartement")
		require.True(t, ok)
		assert.Contains(t, apres, "MME GARAGE")
	})

	t.Run("the others see the co-owners, as they did, and nobody else", func(t *testing.T) {
		status, body := getAs(t, client, membre, srv.URL+"/residents")
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "<h1>Copropriétaires <small>3</small></h1>")
		for _, vu := range []string{"M. OU MME MARTIN", "3 RUE DE LA GARE 31000 TOULOUSE", "SCI DES LILAS", "MME GARAGE", "44, 45"} {
			assert.Contains(t, body, vu)
		}
		for _, cache := range []string{"Camille", "Sacha", "Alex Durand", "06 12 34 56 78", "07 00 00 00 08", "son père", "tel:", "wa.me", "Relire maintenant", `id="filtre"`} {
			assert.NotContains(t, body, cache)
		}
	})

	t.Run("the old address of the co-owners leads here", func(t *testing.T) {
		for _, qui := range []string{admin, membre} {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/coowners", nil)
			require.NoError(t, err)
			req.Header.Set(*authHeader, qui)
			resp, err := client.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.Equal(t, http.StatusFound, resp.StatusCode)
			assert.Equal(t, "/residents", resp.Header.Get("Location"))
		}
	})
}

func TestResidentsSansFoncia(t *testing.T) {
	srv, client := coownersServer(t, func(context.Context) ([]coownerRow, error) { return nil, errors.New("foncia: 403") })

	// The people and their numbers are worth showing without the co-owners.
	status, body := getAs(t, client, admin, srv.URL+"/residents")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "Foncia n'a pas donné la liste des copropriétaires")
	assert.Contains(t, lot(t, body, "C01"), "Camille MARTIN")
	assert.NotContains(t, body, "Pas de copropriétaire connu de Foncia.", "not knowing isn't knowing there is none")

	status, body = getAs(t, client, membre, srv.URL+"/residents")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "Foncia n'a pas donné la liste des copropriétaires")
	assert.NotContains(t, body, "Camille")
}

func TestCoownersEnCache(t *testing.T) {
	appels := 0
	var panne error
	fetch := func(context.Context) ([]coownerRow, error) {
		appels++
		if panne != nil {
			return nil, panne
		}
		return []coownerRow{{Name: "réponse " + string(rune('0'+appels))}}, nil
	}

	t.Run("Foncia is asked once per period", func(t *testing.T) {
		appels, panne = 0, nil
		c := coownersEnCache(fetch, time.Hour)
		for range 3 {
			rows, err := c(t.Context())
			require.NoError(t, err)
			assert.Equal(t, "réponse 1", rows[0].Name)
		}
		assert.Equal(t, 1, appels)
	})

	t.Run("and again once the period is over", func(t *testing.T) {
		appels, panne = 0, nil
		c := coownersEnCache(fetch, 0)
		_, _ = c(t.Context())
		rows, err := c(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "réponse 2", rows[0].Name)
	})

	t.Run("a Foncia that fails later leaves the last answer", func(t *testing.T) {
		appels, panne = 0, nil
		c := coownersEnCache(fetch, 0)
		_, err := c(t.Context())
		require.NoError(t, err)
		panne = errors.New("foncia: 403")
		rows, err := c(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "réponse 1", rows[0].Name)
		// And is asked again the next time, not given up on.
		panne = nil
		rows, err = c(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "réponse 3", rows[0].Name)
	})

	t.Run("a Foncia that never answered is an error, and is asked again", func(t *testing.T) {
		appels, panne = 0, errors.New("foncia: 403")
		c := coownersEnCache(fetch, time.Hour)
		_, err := c(t.Context())
		require.Error(t, err)
		panne = nil
		rows, err := c(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "réponse 2", rows[0].Name)
	})

	t.Run("a visitor who leaves doesn't cancel the question", func(t *testing.T) {
		appels, panne = 0, nil
		parti, cancel := context.WithCancel(t.Context())
		cancel()
		c := coownersEnCache(func(ctx context.Context) ([]coownerRow, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return fetch(ctx)
		}, time.Hour)
		_, err := c(parti)
		require.NoError(t, err)
	})
}
