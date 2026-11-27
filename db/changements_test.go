package db

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChangements(t *testing.T) {
	ctx := t.Context()
	sqlDB := openTest(t)

	fin, err := DernierChangement(ctx, sqlDB)
	require.NoError(t, err)
	assert.Zero(t, fin, "an empty database has an empty journal")

	m := MissionDB{ID: "m1", Number: "7000A", Kind: "Incident", Label: "Fuite", Status: "OPEN",
		StartedAt: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC), Description: "Fuite au C02"}
	require.NoError(t, SaveMissionsToDB(ctx, sqlDB, m))

	t.Run("a new thing is written once, with what it is now", func(t *testing.T) {
		cs, err := GetChangements(ctx, sqlDB, 0, 100)
		require.NoError(t, err)
		require.Len(t, cs, 1)
		assert.Equal(t, "mission", cs[0].Kind)
		assert.Equal(t, "m1", cs[0].Ref)
		assert.Equal(t, "nouveau", cs[0].Action)
		var objet map[string]any
		require.NoError(t, json.Unmarshal(cs[0].Objet, &objet))
		assert.Equal(t, "Fuite", objet["libelle"])
		assert.Equal(t, "Fuite au C02", objet["description"])
	})

	t.Run("the sync writing the same thing again writes nothing", func(t *testing.T) {
		require.NoError(t, SaveMissionsToDB(ctx, sqlDB, m))
		cs, err := GetChangements(ctx, sqlDB, 0, 100)
		require.NoError(t, err)
		assert.Len(t, cs, 1)
	})

	t.Run("a change is written, after the cursor", func(t *testing.T) {
		curseur, err := DernierChangement(ctx, sqlDB)
		require.NoError(t, err)
		m.Status = "CLOSED"
		require.NoError(t, SaveMissionsToDB(ctx, sqlDB, m))
		cs, err := GetChangements(ctx, sqlDB, curseur, 100)
		require.NoError(t, err)
		require.Len(t, cs, 1)
		assert.Equal(t, "modifie", cs[0].Action)
		assert.Contains(t, string(cs[0].Objet), `"statut":"CLOSED"`)
	})

	t.Run("an expense and a document, and the limit", func(t *testing.T) {
		require.NoError(t, UpsertExpensesWithDB(ctx, sqlDB, ExpenseDocumentDB{
			Label: "ACME - CONTRAT", Amount: 12345, Date: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
			HashFile: "h1", Source: SourceAccounting,
		}))
		require.NoError(t, UpsertAccountDocumentsWithDB(ctx, sqlDB, []AccountDocumentDB{{
			ID: "d1", HashFile: "d1", MimeType: "application/pdf", Category: DocumentCategoryReportVisit,
			CreatedAt: time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC),
		}}))
		cs, err := GetChangements(ctx, sqlDB, 0, 100)
		require.NoError(t, err)
		require.Len(t, cs, 4)
		assert.Equal(t, "expense", cs[2].Kind)
		assert.Contains(t, string(cs[2].Objet), `"montant_centimes":12345`)
		assert.Contains(t, string(cs[2].Objet), `"pdf_telecharge":0`)
		assert.Equal(t, "invoice/h1", cs[2].Fichier)
		assert.Equal(t, "doc/d1", cs[3].Fichier)
		assert.Empty(t, cs[0].Fichier, "a mission has no PDF")
		assert.Equal(t, "account_document", cs[3].Kind)
		assert.Contains(t, string(cs[3].Objet), `"categorie":"reportVisit"`)

		cs, err = GetChangements(ctx, sqlDB, 0, 2)
		require.NoError(t, err)
		assert.Len(t, cs, 2)
		assert.Less(t, cs[0].Seq, cs[1].Seq)
	})
}

func TestChangementsExistants(t *testing.T) {
	ctx := t.Context()

	// A database as it was before migration 8, with what it held.
	toutes := migrations
	migrations = toutes[:7]
	sqlDB, err := Open(filepath.Join(t.TempDir(), "foncia.sqlite"))
	migrations = toutes
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, SaveMissionsToDB(ctx, sqlDB,
		MissionDB{ID: "recente", StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		MissionDB{ID: "ancienne", StartedAt: time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)},
	))
	require.NoError(t, UpsertAccountDocumentsWithDB(ctx, sqlDB, []AccountDocumentDB{{
		ID: "pv", HashFile: "pv", Category: DocumentCategoryMinutesSigned, CreatedAt: time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC),
	}}))

	require.NoError(t, Migrate(ctx, sqlDB))

	t.Run("what was there goes in first, oldest first", func(t *testing.T) {
		cs, err := GetChangements(ctx, sqlDB, 0, 100)
		require.NoError(t, err)
		var refs []string
		for _, c := range cs {
			refs = append(refs, c.Ref)
			assert.Equal(t, "existant", c.Action)
		}
		assert.Equal(t, []string{"ancienne", "pv", "recente"}, refs)
	})

	t.Run("and what comes next is written after it", func(t *testing.T) {
		require.NoError(t, SaveMissionsToDB(ctx, sqlDB, MissionDB{ID: "nouvelle", StartedAt: time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)}))
		cs, err := GetChangements(ctx, sqlDB, 3, 100)
		require.NoError(t, err)
		require.Len(t, cs, 1)
		assert.Equal(t, "nouvelle", cs[0].Ref)
		assert.Equal(t, "nouveau", cs[0].Action)
	})
}
