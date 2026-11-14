package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// Affaire is one row from the "Suivi désordres" table that the conseil
// syndical keeps on its own, outside the Foncia API. See
// db/migrations/0004_affaires.sql for the schema and column semantics.
type AffaireDB struct {
	ID              string
	Numero          int
	Titre           string
	Localisation    string
	ActionFoncia    string
	Responsable     string
	DateSignalement string
	LienDevis       string
	ObsCopro        string
	ObsSyndic       string
	DateLevee       string
	Statut          AffaireStatut
	CreatedAt       time.Time
	UpdatedAt       time.Time

	Relances []AffaireRelanceDB
}

type AffaireRelanceDB struct {
	ID        string
	AffaireID string
	Date      string
	Note      string
}

type AffaireStatut string

const (
	AffaireStatutEnCours AffaireStatut = "en_cours"
	AffaireStatutLevee   AffaireStatut = "levee"
)

func newAffaireID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// InsertAffaire inserts a new affaire together with its relances. CreatedAt and
// UpdatedAt are set to now; the caller may leave them zero.
func InsertAffaire(ctx context.Context, db *sql.DB, a AffaireDB) (string, error) {
	if a.ID == "" {
		a.ID = newAffaireID()
	}
	now := time.Now()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = now
	}
	if a.Statut == "" {
		a.Statut = AffaireStatutEnCours
	}

	err := inTx(ctx, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
INSERT INTO affaires (id, numero, titre, localisation, action_foncia, responsable,
                      date_signalement, lien_devis, obs_copro, obs_syndic,
                      date_levee, statut, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			a.ID, a.Numero, a.Titre, a.Localisation, a.ActionFoncia, a.Responsable,
			a.DateSignalement, a.LienDevis, a.ObsCopro, a.ObsSyndic,
			a.DateLevee, string(a.Statut), formatTime(a.CreatedAt), formatTime(a.UpdatedAt))
		if err != nil {
			return fmt.Errorf("while inserting affaire: %w", err)
		}
		for _, r := range a.Relances {
			if r.ID == "" {
				r.ID = newAffaireID()
			}
			_, err := tx.ExecContext(ctx, `
INSERT INTO affaires_relances (id, affaire_id, date, note) VALUES (?,?,?,?)`,
				r.ID, a.ID, r.Date, r.Note)
			if err != nil {
				return fmt.Errorf("while inserting relance: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return a.ID, nil
}

// UpdateAffaire replaces every column except id and created_at. Relances are
// replaced wholesale (delete-then-insert) to keep the UI simple.
func UpdateAffaire(ctx context.Context, db *sql.DB, a AffaireDB) error {
	if a.ID == "" {
		return fmt.Errorf("UpdateAffaire: empty id")
	}
	a.UpdatedAt = time.Now()
	if a.Statut == "" {
		a.Statut = AffaireStatutEnCours
	}
	return inTx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
UPDATE affaires SET
    numero = ?, titre = ?, localisation = ?, action_foncia = ?, responsable = ?,
    date_signalement = ?, lien_devis = ?, obs_copro = ?, obs_syndic = ?,
    date_levee = ?, statut = ?, updated_at = ?
WHERE id = ?`,
			a.Numero, a.Titre, a.Localisation, a.ActionFoncia, a.Responsable,
			a.DateSignalement, a.LienDevis, a.ObsCopro, a.ObsSyndic,
			a.DateLevee, string(a.Statut), formatTime(a.UpdatedAt), a.ID)
		if err != nil {
			return fmt.Errorf("while updating affaire: %w", err)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return fmt.Errorf("no affaire with id %q", a.ID)
		}

		if _, err := tx.ExecContext(ctx, `DELETE FROM affaires_relances WHERE affaire_id = ?`, a.ID); err != nil {
			return fmt.Errorf("while clearing relances: %w", err)
		}
		for _, r := range a.Relances {
			if r.ID == "" {
				r.ID = newAffaireID()
			}
			_, err := tx.ExecContext(ctx, `
INSERT INTO affaires_relances (id, affaire_id, date, note) VALUES (?,?,?,?)`,
				r.ID, a.ID, r.Date, r.Note)
			if err != nil {
				return fmt.Errorf("while inserting relance: %w", err)
			}
		}
		return nil
	})
}

// DeleteAffaire removes an affaire; its relances go with it via the cascade.
func DeleteAffaire(ctx context.Context, db *sql.DB, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM affaires WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("while deleting affaire: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no affaire with id %q", id)
	}
	return nil
}

// GetAffaire returns one affaire with its relances, or sql.ErrNoRows if the id
// is unknown.
func GetAffaire(ctx context.Context, db *sql.DB, id string) (AffaireDB, error) {
	row := db.QueryRowContext(ctx, `
SELECT id, numero, titre, localisation, action_foncia, responsable,
       date_signalement, lien_devis, obs_copro, obs_syndic,
       date_levee, statut, created_at, updated_at
FROM affaires WHERE id = ?`, id)
	a, err := scanAffaire(row)
	if err != nil {
		return AffaireDB{}, err
	}
	a.Relances, err = getRelances(ctx, db, id)
	if err != nil {
		return AffaireDB{}, err
	}
	return a, nil
}

// GetAffaires returns every affaire whose statut matches; pass "" for all.
// Rows come back sorted by numero ascending, which matches the Excel layout.
func GetAffaires(ctx context.Context, db *sql.DB, statut AffaireStatut) ([]AffaireDB, error) {
	var query string
	var args []any
	if statut == "" {
		query = `SELECT id, numero, titre, localisation, action_foncia, responsable,
                       date_signalement, lien_devis, obs_copro, obs_syndic,
                       date_levee, statut, created_at, updated_at
                FROM affaires ORDER BY statut, numero`
	} else {
		query = `SELECT id, numero, titre, localisation, action_foncia, responsable,
                       date_signalement, lien_devis, obs_copro, obs_syndic,
                       date_levee, statut, created_at, updated_at
                FROM affaires WHERE statut = ? ORDER BY numero`
		args = []any{string(statut)}
	}
	affaires, err := queryAll(ctx, db, query, scanAffaireRow, args...)
	if err != nil {
		return nil, err
	}
	// Second query for relances. Small cardinality (dozens of affaires), so a
	// per-affaire query is clearer than a single join + merge.
	for i := range affaires {
		affaires[i].Relances, err = getRelances(ctx, db, affaires[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return affaires, nil
}

func getRelances(ctx context.Context, db *sql.DB, affaireID string) ([]AffaireRelanceDB, error) {
	// ORDER BY rowid keeps the insertion order the UI sent; the id is a UUID
	// and would shuffle the lines at random otherwise.
	return queryAll(ctx, db,
		`SELECT id, affaire_id, date, note FROM affaires_relances WHERE affaire_id = ? ORDER BY rowid`,
		func(rows *sql.Rows) (AffaireRelanceDB, error) {
			var r AffaireRelanceDB
			err := rows.Scan(&r.ID, &r.AffaireID, &r.Date, &r.Note)
			return r, err
		}, affaireID)
}

// NextAffaireNumero returns the next free number for a given statut, so the
// UI can suggest it when the user is adding a row.
func NextAffaireNumero(ctx context.Context, db *sql.DB, statut AffaireStatut) (int, error) {
	var n sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT MAX(numero) FROM affaires WHERE statut = ?`, string(statut)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("while reading max numero: %w", err)
	}
	if !n.Valid {
		return 1, nil
	}
	return int(n.Int64) + 1, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAffaire(s scanner) (AffaireDB, error) {
	var a AffaireDB
	var createdAt, updatedAt, statut string
	err := s.Scan(&a.ID, &a.Numero, &a.Titre, &a.Localisation, &a.ActionFoncia, &a.Responsable,
		&a.DateSignalement, &a.LienDevis, &a.ObsCopro, &a.ObsSyndic,
		&a.DateLevee, &statut, &createdAt, &updatedAt)
	if err != nil {
		return AffaireDB{}, err
	}
	a.Statut = AffaireStatut(statut)
	if a.CreatedAt, err = parseTime("created_at", createdAt); err != nil {
		return AffaireDB{}, err
	}
	if a.UpdatedAt, err = parseTime("updated_at", updatedAt); err != nil {
		return AffaireDB{}, err
	}
	return a, nil
}

func scanAffaireRow(rows *sql.Rows) (AffaireDB, error) { return scanAffaire(rows) }
