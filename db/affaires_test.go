package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAffairesCRUD(t *testing.T) {
	ctx := t.Context()
	sqlDB := openTest(t)

	t.Run("an empty database has no affaires", func(t *testing.T) {
		got, err := GetAffaires(ctx, sqlDB, "")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("InsertAffaire + GetAffaire round-trips every column", func(t *testing.T) {
		id, err := InsertAffaire(ctx, sqlDB, AffaireDB{
			Numero:          3,
			Titre:           "Ampoule du hall à changer",
			Localisation:    "Hall A",
			ActionFoncia:    "Devis demandé",
			Responsable:     "Camille",
			DateSignalement: "18/06/2024",
			LienDevis:       "Devis 42",
			ObsCopro:        "",
			ObsSyndic:       "Validé en réunion",
			DateLevee:       "",
			Statut:          AffaireStatutEnCours,
			Relances: []AffaireRelanceDB{
				{Date: "13/08/2026", Note: ""},
				{Date: "09/11/2026", Note: "réunion"},
			},
		})
		require.NoError(t, err)
		require.NotEmpty(t, id)

		got, err := GetAffaire(ctx, sqlDB, id)
		require.NoError(t, err)
		assert.Equal(t, 3, got.Numero)
		assert.Equal(t, "Ampoule du hall à changer", got.Titre)
		assert.Equal(t, "Hall A", got.Localisation)
		assert.Equal(t, "Camille", got.Responsable)
		assert.Equal(t, "18/06/2024", got.DateSignalement)
		assert.Equal(t, AffaireStatutEnCours, got.Statut)
		require.Len(t, got.Relances, 2)
		assert.Equal(t, "13/08/2026", got.Relances[0].Date)
		assert.Equal(t, "", got.Relances[0].Note)
		assert.Equal(t, "09/11/2026", got.Relances[1].Date)
		assert.Equal(t, "réunion", got.Relances[1].Note)
		assert.Equal(t, id, got.Relances[0].AffaireID)
	})

	t.Run("GetAffaires filters by statut and orders by numero", func(t *testing.T) {
		_, err := InsertAffaire(ctx, sqlDB, AffaireDB{Numero: 2, Titre: "B", Statut: AffaireStatutEnCours})
		require.NoError(t, err)
		_, err = InsertAffaire(ctx, sqlDB, AffaireDB{Numero: 1, Titre: "A levée", Statut: AffaireStatutLevee, DateLevee: "01/01/2025"})
		require.NoError(t, err)

		enCours, err := GetAffaires(ctx, sqlDB, AffaireStatutEnCours)
		require.NoError(t, err)
		require.Len(t, enCours, 2)
		assert.Equal(t, 2, enCours[0].Numero)
		assert.Equal(t, "B", enCours[0].Titre)
		assert.Equal(t, 3, enCours[1].Numero)

		levees, err := GetAffaires(ctx, sqlDB, AffaireStatutLevee)
		require.NoError(t, err)
		require.Len(t, levees, 1)
		assert.Equal(t, "A levée", levees[0].Titre)
	})

	t.Run("UpdateAffaire replaces every column and the relances", func(t *testing.T) {
		id, err := InsertAffaire(ctx, sqlDB, AffaireDB{
			Numero: 10, Titre: "To update",
			Relances: []AffaireRelanceDB{{Date: "01/01/2026"}},
		})
		require.NoError(t, err)

		err = UpdateAffaire(ctx, sqlDB, AffaireDB{
			ID: id, Numero: 10, Titre: "Updated", ObsSyndic: "new note",
			Statut:   AffaireStatutLevee,
			Relances: []AffaireRelanceDB{{Date: "02/02/2026", Note: "r1"}, {Date: "03/03/2026", Note: "r2"}},
		})
		require.NoError(t, err)

		got, err := GetAffaire(ctx, sqlDB, id)
		require.NoError(t, err)
		assert.Equal(t, "Updated", got.Titre)
		assert.Equal(t, "new note", got.ObsSyndic)
		assert.Equal(t, AffaireStatutLevee, got.Statut)
		require.Len(t, got.Relances, 2)
		assert.Equal(t, "02/02/2026", got.Relances[0].Date)
		assert.Equal(t, "r1", got.Relances[0].Note)
	})

	t.Run("DeleteAffaire cascades to relances", func(t *testing.T) {
		id, err := InsertAffaire(ctx, sqlDB, AffaireDB{
			Numero: 99, Titre: "To delete",
			Relances: []AffaireRelanceDB{{Date: "x"}, {Date: "y"}},
		})
		require.NoError(t, err)

		require.NoError(t, DeleteAffaire(ctx, sqlDB, id))

		var n int
		require.NoError(t, sqlDB.QueryRow("SELECT COUNT(*) FROM affaires_relances WHERE affaire_id = ?", id).Scan(&n))
		assert.Equal(t, 0, n, "the relances must be deleted with their affaire")
	})

	t.Run("NextAffaireNumero picks the next free numero for the given statut", func(t *testing.T) {
		fresh := openTest(t)
		got, err := NextAffaireNumero(ctx, fresh, AffaireStatutEnCours)
		require.NoError(t, err)
		assert.Equal(t, 1, got, "an empty table starts at 1")

		_, err = InsertAffaire(ctx, fresh, AffaireDB{Numero: 5, Titre: "x", Statut: AffaireStatutEnCours})
		require.NoError(t, err)
		_, err = InsertAffaire(ctx, fresh, AffaireDB{Numero: 7, Titre: "y", Statut: AffaireStatutEnCours})
		require.NoError(t, err)
		_, err = InsertAffaire(ctx, fresh, AffaireDB{Numero: 99, Titre: "z", Statut: AffaireStatutLevee})
		require.NoError(t, err)

		got, err = NextAffaireNumero(ctx, fresh, AffaireStatutEnCours)
		require.NoError(t, err)
		assert.Equal(t, 8, got)
	})
}
