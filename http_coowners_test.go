package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// coownersServer serves the page of the co-owners with the given co-owners
// behind it.
func coownersServer(t *testing.T, coowners coownersFunc) (*httptest.Server, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	addCoownersHandlers(mux, copro{sqlDB: openTestDB(t), coowners: coowners})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return srv, client
}

func TestCoproprietaires(t *testing.T) {
	srv, client := coownersServer(t, func(context.Context) ([]coownerRow, error) { return coownersFoncia, nil })

	t.Run("the co-owners of Foncia, apartment by apartment", func(t *testing.T) {
		status, body := get(t, client, srv.URL+"/coproprietaires")
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "M. OU MME MARTIN")
		assert.Contains(t, body, "3 RUE DE LA GARE 31000 TOULOUSE")
		assert.Contains(t, body, "44, 45")
		assert.Contains(t, body, "SCI DES LILAS")
		assert.Contains(t, body, "MME GARAGE")
	})

	for _, ancienne := range []string{"/coowners", "/residents"} {
		t.Run("the old address "+ancienne+" leads here", func(t *testing.T) {
			status, _ := get(t, client, srv.URL+ancienne)
			assert.Equal(t, http.StatusFound, status)
		})
	}
}

func TestCoproprietairesSansFoncia(t *testing.T) {
	srv, client := coownersServer(t, func(context.Context) ([]coownerRow, error) { return nil, errors.New("Foncia est en panne") })
	status, body := get(t, client, srv.URL+"/coproprietaires")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "Foncia ne répond pas")
	assert.Contains(t, body, "Aucun copropriétaire.")
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
