package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ResidentDB is somebody of the building: who lives in an apartment, who owns
// it without living there, who left. See migrations/0006_residents.sql.
type ResidentDB struct {
	ID          string
	Appartement string // "C01".
	Nom         string
	Qualite     ResidentQualite
	Detail      string // "compagnon", "ancien locataire", "vendeur"...
	Telephone   string // "06 12 34 56 78"; several are separated by a comma.
	Email       string // Several are separated by a comma.
	Note        string
	Origine     ResidentOrigine
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ResidentQualite string

const (
	ResidentHabite       ResidentQualite = "resident"
	ResidentProprietaire ResidentQualite = "proprietaire"
	ResidentAncien       ResidentQualite = "ancien"
	ResidentAutre        ResidentQualite = "autre"
)

func (q ResidentQualite) Valid() bool {
	switch q {
	case ResidentHabite, ResidentProprietaire, ResidentAncien, ResidentAutre:
		return true
	}
	return false
}

func (q ResidentQualite) French() string {
	switch q {
	case ResidentHabite:
		return "Résident"
	case ResidentProprietaire:
		return "Propriétaire"
	case ResidentAncien:
		return "Ancien"
	case ResidentAutre:
		return "Autre"
	}
	return string(q)
}

// ResidentOrigine tells who keeps the row up to date: the address book as
// WhatsApp knows it (read again and again, on its own), an export of the
// contacts sent by hand, or the people typing on the site.
type ResidentOrigine string

const (
	ResidentDeWhatsApp  ResidentOrigine = "whatsapp"
	ResidentDesContacts ResidentOrigine = "contacts"
	ResidentDuSite      ResidentOrigine = "site"
)

func (o ResidentOrigine) Valid() bool {
	return o == ResidentDeWhatsApp || o == ResidentDesContacts || o == ResidentDuSite
}

// Rang orders the origins by how much they are trusted on who is where:
// WhatsApp is read live, an export is a picture of one day, and a row typed on
// the site is nobody's until a contact matches it.
func (o ResidentOrigine) Rang() int {
	switch o {
	case ResidentDeWhatsApp:
		return 2
	case ResidentDesContacts:
		return 1
	}
	return 0
}

// Telephones splits the phone numbers of the row.
func (r ResidentDB) Telephones() []string { return splitList(r.Telephone) }

// Emails splits the e-mail addresses of the row.
func (r ResidentDB) Emails() []string { return splitList(r.Email) }

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

const residentColumns = `id, appartement, nom, qualite, detail, telephone, email, note, origine,
	created_by, created_at, updated_at`

func scanResident(rows *sql.Rows) (ResidentDB, error) {
	var r ResidentDB
	var qualite, origine, createdAt, updatedAt string
	err := rows.Scan(&r.ID, &r.Appartement, &r.Nom, &qualite, &r.Detail, &r.Telephone, &r.Email, &r.Note, &origine,
		&r.CreatedBy, &createdAt, &updatedAt)
	if err != nil {
		return r, err
	}
	r.Qualite, r.Origine = ResidentQualite(qualite), ResidentOrigine(origine)
	if r.CreatedAt, err = parseTime("created_at", createdAt); err != nil {
		return r, err
	}
	r.UpdatedAt, err = parseTime("updated_at", updatedAt)
	return r, err
}

// GetResidents returns everybody, by apartment then by name.
func GetResidents(ctx context.Context, db *sql.DB) ([]ResidentDB, error) {
	return queryAll(ctx, db, `SELECT `+residentColumns+` FROM residents ORDER BY appartement, nom COLLATE NOCASE, id`, scanResident)
}

// GetResident returns sql.ErrNoRows when the id is unknown.
func GetResident(ctx context.Context, db *sql.DB, id string) (ResidentDB, error) {
	rs, err := queryAll(ctx, db, `SELECT `+residentColumns+` FROM residents WHERE id = ?`, scanResident, id)
	if err != nil {
		return ResidentDB{}, err
	}
	if len(rs) == 0 {
		return ResidentDB{}, sql.ErrNoRows
	}
	return rs[0], nil
}

func InsertResident(ctx context.Context, db *sql.DB, r ResidentDB) (string, error) {
	var id string
	err := inTx(ctx, db, func(tx *sql.Tx) (err error) {
		id, err = insertResident(ctx, tx, r)
		return err
	})
	return id, err
}

// UpdateResident replaces every column except id, created_by and created_at.
func UpdateResident(ctx context.Context, db *sql.DB, r ResidentDB) error {
	return inTx(ctx, db, func(tx *sql.Tx) error { return updateResident(ctx, tx, r) })
}

func DeleteResident(ctx context.Context, db *sql.DB, id string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM residents WHERE id = ?`, id); err != nil {
		return fmt.Errorf("while deleting resident: %w", err)
	}
	return nil
}

// ApplyResidents is what an import of the contacts does to the table, all or
// nothing: a file that fails halfway must not leave half of the building.
func ApplyResidents(ctx context.Context, db *sql.DB, ajouts, majs []ResidentDB, suppressions []string) error {
	return inTx(ctx, db, func(tx *sql.Tx) error {
		for _, r := range ajouts {
			if _, err := insertResident(ctx, tx, r); err != nil {
				return err
			}
		}
		for _, r := range majs {
			if err := updateResident(ctx, tx, r); err != nil {
				return err
			}
		}
		for _, id := range suppressions {
			if _, err := tx.ExecContext(ctx, `DELETE FROM residents WHERE id = ?`, id); err != nil {
				return fmt.Errorf("while deleting resident: %w", err)
			}
		}
		return nil
	})
}

func checkResident(r ResidentDB) error {
	if !r.Qualite.Valid() {
		return fmt.Errorf("unknown qualite %q", r.Qualite)
	}
	if !r.Origine.Valid() {
		return fmt.Errorf("unknown origine %q", r.Origine)
	}
	return nil
}

func insertResident(ctx context.Context, tx *sql.Tx, r ResidentDB) (string, error) {
	if err := checkResident(r); err != nil {
		return "", err
	}
	if r.ID == "" {
		r.ID = newAffaireID()
	}
	now := formatTime(time.Now())
	_, err := tx.ExecContext(ctx, `INSERT INTO residents (`+residentColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Appartement, r.Nom, string(r.Qualite), r.Detail, r.Telephone, r.Email, r.Note, string(r.Origine),
		r.CreatedBy, now, now)
	if err != nil {
		return "", fmt.Errorf("while inserting resident: %w", err)
	}
	return r.ID, nil
}

func updateResident(ctx context.Context, tx *sql.Tx, r ResidentDB) error {
	if err := checkResident(r); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
UPDATE residents SET appartement = ?, nom = ?, qualite = ?, detail = ?, telephone = ?, email = ?, note = ?,
    origine = ?, updated_at = ?
WHERE id = ?`,
		r.Appartement, r.Nom, string(r.Qualite), r.Detail, r.Telephone, r.Email, r.Note,
		string(r.Origine), formatTime(time.Now()), r.ID)
	if err != nil {
		return fmt.Errorf("while updating resident: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
