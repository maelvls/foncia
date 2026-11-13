package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// RemboursementDB is a purchase a co-owner paid out of pocket for the
// copropriété and wants back from the syndic.
type RemboursementDB struct {
	ID                string
	Objet             string
	Vendeur           string
	Montant           Amount
	DateAchat         string // "2006-01-02", or "".
	Demandeur         string
	DateDemande       string
	Statut            RemboursementStatut
	DateRemboursement string
	Preuve            string
	Detail            string
	CreatedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type RemboursementStatut string

const (
	RemboursementADemander RemboursementStatut = "a_demander"
	RemboursementDemande   RemboursementStatut = "demande"
	RemboursementRembourse RemboursementStatut = "rembourse"
	RemboursementAbandonne RemboursementStatut = "abandonne"
)

func (s RemboursementStatut) Valid() bool {
	switch s {
	case RemboursementADemander, RemboursementDemande, RemboursementRembourse, RemboursementAbandonne:
		return true
	}
	return false
}

func (s RemboursementStatut) French() string {
	switch s {
	case RemboursementADemander:
		return "À demander"
	case RemboursementDemande:
		return "Demandé"
	case RemboursementRembourse:
		return "Remboursé"
	case RemboursementAbandonne:
		return "Abandonné"
	}
	return string(s)
}

// EnAttente tells whether the copropriété still owes this money.
func (s RemboursementStatut) EnAttente() bool {
	return s == RemboursementADemander || s == RemboursementDemande
}

// DateAchatFrench shows the ISO purchase date as JJ/MM/AAAA.
func (r RemboursementDB) DateAchatFrench() string {
	t, err := time.Parse("2006-01-02", r.DateAchat)
	if err != nil {
		return r.DateAchat
	}
	return t.Format("02/01/2006")
}

const remboursementColumns = `id, objet, vendeur, montant, date_achat, demandeur, date_demande, statut,
	date_remboursement, preuve, detail, created_by, created_at, updated_at`

func scanRemboursement(rows *sql.Rows) (RemboursementDB, error) {
	var r RemboursementDB
	var statut, createdAt, updatedAt string
	err := rows.Scan(&r.ID, &r.Objet, &r.Vendeur, &r.Montant, &r.DateAchat, &r.Demandeur, &r.DateDemande, &statut,
		&r.DateRemboursement, &r.Preuve, &r.Detail, &r.CreatedBy, &createdAt, &updatedAt)
	if err != nil {
		return r, err
	}
	r.Statut = RemboursementStatut(statut)
	if r.CreatedAt, err = parseTime("created_at", createdAt); err != nil {
		return r, err
	}
	r.UpdatedAt, err = parseTime("updated_at", updatedAt)
	return r, err
}

// GetRemboursements returns every remboursement, most recent purchase first.
func GetRemboursements(ctx context.Context, db *sql.DB) ([]RemboursementDB, error) {
	return queryAll(ctx, db, `SELECT `+remboursementColumns+` FROM remboursements ORDER BY date_achat DESC, created_at DESC`, scanRemboursement)
}

// GetRemboursement returns sql.ErrNoRows when the id is unknown.
func GetRemboursement(ctx context.Context, db *sql.DB, id string) (RemboursementDB, error) {
	rs, err := queryAll(ctx, db, `SELECT `+remboursementColumns+` FROM remboursements WHERE id = ?`, scanRemboursement, id)
	if err != nil {
		return RemboursementDB{}, err
	}
	if len(rs) == 0 {
		return RemboursementDB{}, sql.ErrNoRows
	}
	return rs[0], nil
}

func InsertRemboursement(ctx context.Context, db *sql.DB, r RemboursementDB) (string, error) {
	if !r.Statut.Valid() {
		return "", fmt.Errorf("unknown statut %q", r.Statut)
	}
	if r.ID == "" {
		r.ID = newAffaireID()
	}
	now := formatTime(time.Now())
	_, err := db.ExecContext(ctx, `INSERT INTO remboursements (`+remboursementColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Objet, r.Vendeur, int(r.Montant), r.DateAchat, r.Demandeur, r.DateDemande, string(r.Statut),
		r.DateRemboursement, r.Preuve, r.Detail, r.CreatedBy, now, now)
	if err != nil {
		return "", fmt.Errorf("while inserting remboursement: %w", err)
	}
	return r.ID, nil
}

// UpdateRemboursement replaces every column except id, created_by and created_at.
func UpdateRemboursement(ctx context.Context, db *sql.DB, r RemboursementDB) error {
	if !r.Statut.Valid() {
		return fmt.Errorf("unknown statut %q", r.Statut)
	}
	res, err := db.ExecContext(ctx, `
UPDATE remboursements SET objet = ?, vendeur = ?, montant = ?, date_achat = ?, demandeur = ?, date_demande = ?,
    statut = ?, date_remboursement = ?, preuve = ?, detail = ?, updated_at = ?
WHERE id = ?`,
		r.Objet, r.Vendeur, int(r.Montant), r.DateAchat, r.Demandeur, r.DateDemande,
		string(r.Statut), r.DateRemboursement, r.Preuve, r.Detail, formatTime(time.Now()), r.ID)
	if err != nil {
		return fmt.Errorf("while updating remboursement: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func DeleteRemboursement(ctx context.Context, db *sql.DB, id string) error {
	return inTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM affaires_liens WHERE kind = 'remboursement' AND ref = ?`, id); err != nil {
			return fmt.Errorf("while detaching remboursement: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM remboursements WHERE id = ?`, id); err != nil {
			return fmt.Errorf("while deleting remboursement: %w", err)
		}
		return nil
	})
}
