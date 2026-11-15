package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// What gets attached to an affaire: comments and links. See the comments in
// db/migrations/0004_affaires.sql for what each kind of link points to.

type AffaireCommentaireDB struct {
	ID        string
	AffaireID string
	Auteur    string
	Texte     string
	CreatedAt time.Time
}

type LienKind string

const (
	LienDepense       LienKind = "depense"
	LienDocument      LienKind = "document"
	LienMission       LienKind = "mission"
	LienRemboursement LienKind = "remboursement"
	LienEmail         LienKind = "email"
	LienURL           LienKind = "lien"
	LienFichier       LienKind = "fichier" // ref = fichiers.sha256
	LienSource        LienKind = "source"  // ref = sources.id
)

// Valid tells whether k is one of the kinds the schema accepts.
func (k LienKind) Valid() bool {
	switch k {
	case LienDepense, LienDocument, LienMission, LienRemboursement, LienEmail, LienURL, LienFichier, LienSource:
		return true
	}
	return false
}

// HasRef tells whether links of this kind point to a row of another table.
func (k LienKind) HasRef() bool {
	return k == LienDepense || k == LienDocument || k == LienMission || k == LienRemboursement || k == LienFichier || k == LienSource
}

// Searchable tells whether the "rattacher" page can look rows of this kind
// up. Files and sources are attached from their own pages.
func (k LienKind) Searchable() bool {
	return k == LienDepense || k == LienDocument || k == LienMission || k == LienRemboursement
}

func (k LienKind) French() string {
	switch k {
	case LienDepense:
		return "Facture"
	case LienDocument:
		return "Document"
	case LienMission:
		return "Ordre de service"
	case LienRemboursement:
		return "Remboursement"
	case LienEmail:
		return "E-mail"
	case LienURL:
		return "Lien"
	case LienFichier:
		return "Fichier"
	case LienSource:
		return "Message"
	}
	return string(k)
}

type AffaireLienDB struct {
	ID        string
	AffaireID string
	Kind      LienKind
	Ref       string
	Titre     string
	URL       string
	Note      string
	Auteur    string
	CreatedAt time.Time
}

// ErrLienExists is returned when the same row is attached twice to an affaire.
var ErrLienExists = errors.New("déjà rattaché à cette affaire")

func InsertCommentaire(ctx context.Context, db *sql.DB, c AffaireCommentaireDB) (string, error) {
	if c.ID == "" {
		c.ID = newAffaireID()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	_, err := db.ExecContext(ctx, `INSERT INTO affaires_commentaires (id, affaire_id, auteur, texte, created_at) VALUES (?,?,?,?,?)`,
		c.ID, c.AffaireID, c.Auteur, c.Texte, formatTime(c.CreatedAt))
	if err != nil {
		return "", fmt.Errorf("while inserting commentaire: %w", err)
	}
	return c.ID, nil
}

func DeleteCommentaire(ctx context.Context, db *sql.DB, affaireID, id string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM affaires_commentaires WHERE id = ? AND affaire_id = ?`, id, affaireID)
	if err != nil {
		return fmt.Errorf("while deleting commentaire: %w", err)
	}
	return nil
}

func GetCommentaires(ctx context.Context, db *sql.DB, affaireID string) ([]AffaireCommentaireDB, error) {
	return queryAll(ctx, db,
		`SELECT id, affaire_id, auteur, texte, created_at FROM affaires_commentaires WHERE affaire_id = ? ORDER BY created_at, rowid`,
		func(rows *sql.Rows) (AffaireCommentaireDB, error) {
			var c AffaireCommentaireDB
			var createdAt string
			if err := rows.Scan(&c.ID, &c.AffaireID, &c.Auteur, &c.Texte, &createdAt); err != nil {
				return c, err
			}
			var err error
			c.CreatedAt, err = parseTime("created_at", createdAt)
			return c, err
		}, affaireID)
}

func InsertLien(ctx context.Context, db *sql.DB, l AffaireLienDB) (string, error) {
	if !l.Kind.Valid() {
		return "", fmt.Errorf("unknown kind of lien %q", l.Kind)
	}
	if l.Kind.HasRef() && l.Ref == "" {
		return "", fmt.Errorf("a lien of kind %q needs a ref", l.Kind)
	}
	if l.ID == "" {
		l.ID = newAffaireID()
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	res, err := db.ExecContext(ctx, `
INSERT OR IGNORE INTO affaires_liens (id, affaire_id, kind, ref, titre, url, note, auteur, created_at)
VALUES (?,?,?,?,?,?,?,?,?)`,
		l.ID, l.AffaireID, string(l.Kind), l.Ref, l.Titre, l.URL, l.Note, l.Auteur, formatTime(l.CreatedAt))
	if err != nil {
		return "", fmt.Errorf("while inserting lien: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrLienExists
	}
	return l.ID, nil
}

func DeleteLien(ctx context.Context, db *sql.DB, affaireID, id string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM affaires_liens WHERE id = ? AND affaire_id = ?`, id, affaireID)
	if err != nil {
		return fmt.Errorf("while deleting lien: %w", err)
	}
	return nil
}

const lienColumns = `id, affaire_id, kind, ref, titre, url, note, auteur, created_at`

func scanLien(rows *sql.Rows) (AffaireLienDB, error) {
	var l AffaireLienDB
	var kind, createdAt string
	if err := rows.Scan(&l.ID, &l.AffaireID, &kind, &l.Ref, &l.Titre, &l.URL, &l.Note, &l.Auteur, &createdAt); err != nil {
		return l, err
	}
	l.Kind = LienKind(kind)
	var err error
	l.CreatedAt, err = parseTime("created_at", createdAt)
	return l, err
}

func GetLiens(ctx context.Context, db *sql.DB, affaireID string) ([]AffaireLienDB, error) {
	return queryAll(ctx, db,
		`SELECT `+lienColumns+` FROM affaires_liens WHERE affaire_id = ? ORDER BY created_at, rowid`, scanLien, affaireID)
}

// AffaireRef is the little that is needed to point back to an affaire.
type AffaireRef struct {
	ID     string
	Numero int
	Titre  string
	Statut AffaireStatut
}

// GetAffairesByRef returns, for every row of the given kind that is attached to
// at least one affaire, the affaires it is attached to. The key is the ref.
func GetAffairesByRef(ctx context.Context, db *sql.DB, kind LienKind) (map[string][]AffaireRef, error) {
	type row struct {
		ref string
		a   AffaireRef
	}
	rows, err := queryAll(ctx, db, `
SELECT l.ref, a.id, a.numero, a.titre, a.statut
FROM affaires_liens l JOIN affaires a ON a.id = l.affaire_id
WHERE l.kind = ? ORDER BY a.statut, a.numero`,
		func(rows *sql.Rows) (row, error) {
			var r row
			var statut string
			err := rows.Scan(&r.ref, &r.a.ID, &r.a.Numero, &r.a.Titre, &statut)
			r.a.Statut = AffaireStatut(statut)
			return r, err
		}, string(kind))
	if err != nil {
		return nil, err
	}
	out := make(map[string][]AffaireRef)
	for _, r := range rows {
		out[r.ref] = append(out[r.ref], r.a)
	}
	return out, nil
}

// AffaireStats is what the list of affaires shows about each dossier.
type AffaireStats struct {
	Commentaires int
	Liens        int
	Engage       Amount // Sum of the attached expenses.
}

func GetAffairesStats(ctx context.Context, db *sql.DB) (map[string]AffaireStats, error) {
	out := make(map[string]AffaireStats)

	rows, err := db.QueryContext(ctx, `SELECT affaire_id, COUNT(*) FROM affaires_commentaires GROUP BY affaire_id`)
	if err != nil {
		return nil, fmt.Errorf("while counting commentaires: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		s := out[id]
		s.Commentaires = n
		out[id] = s
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows2, err := db.QueryContext(ctx, `
SELECT l.affaire_id, COUNT(*), COALESCE(SUM(e.amount), 0)
FROM affaires_liens l LEFT JOIN expenses e ON l.kind = 'depense' AND e.id = l.ref
GROUP BY l.affaire_id`)
	if err != nil {
		return nil, fmt.Errorf("while counting liens: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var id string
		var n, engage int
		if err := rows2.Scan(&id, &n, &engage); err != nil {
			return nil, err
		}
		s := out[id]
		s.Liens = n
		s.Engage = Amount(engage)
		out[id] = s
	}
	return out, rows2.Err()
}
