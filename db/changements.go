package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// The journal of what changed in the mirror (migrations/0008_changements.sql),
// for the readers of GET /api/v1/changements.

// ChangementDB is one row of the journal, with the thing it is about as it is
// now (not as it was when the row was written): a reader wants what is true,
// and a thing changed twice is shown twice the same way.
type ChangementDB struct {
	Seq    int64           `json:"seq"`
	At     string          `json:"at"`
	Kind   string          `json:"type"`   // "mission" | "work_order" | "expense" | "account_document" | "contract_document"
	Ref    string          `json:"id"`     // The id of the thing.
	Action string          `json:"action"` // "existant" | "nouveau" | "modifie"
	Objet  json.RawMessage `json:"objet"`  // The thing as it is now; null when it is gone.

	// Fichier is its PDF, as "<typ>/<id>" of /dl/<typ>/<id> (http_dl.go),
	// "" when it has none. The API turns it into a URL.
	Fichier string `json:"-"`
}

// changementObjet is the thing of each kind, as JSON, built by SQLite.
const changementObjet = `CASE c.kind
	WHEN 'mission' THEN (SELECT json_object(
		'numero', m.number, 'genre', m.kind, 'libelle', m.label, 'statut', m.status,
		'debut', m.started_at, 'description', m.description) FROM missions m WHERE m.id = c.ref)
	WHEN 'work_order' THEN (SELECT json_object(
		'mission_id', w.mission_id, 'numero', w.number, 'libelle', w.label,
		'debut', w.repair_date_start, 'fin', w.repair_date_end,
		'fournisseur', w.supplier_name, 'activite', w.supplier_activity) FROM work_orders w WHERE w.id = c.ref)
	WHEN 'expense' THEN (SELECT json_object(
		'libelle', e.label, 'montant_centimes', e.amount, 'date', e.date,
		'compte', e.source, 'repartition', e.accounting_allocation, 'nature', e.accounting_expense_type,
		'facture_id', e.invoice_id, 'hash_file', e.hash_file, 'pdf_telecharge', e.file_path <> '') FROM expenses e WHERE e.id = c.ref)
	WHEN 'account_document' THEN (SELECT json_object(
		'categorie', d.category, 'type_mime', d.mime_type, 'date', d.created_at,
		'hash_file', d.hash_file, 'telecharge', d.file_path <> '') FROM account_documents d WHERE d.id = c.ref)
	WHEN 'contract_document' THEN (SELECT json_object(
		'fournisseur_id', k.supplier_id,
		'fournisseur', (SELECT s.name FROM suppliers s WHERE s.id = k.supplier_id),
		'hash_file', k.hash_file, 'telecharge', k.file_path <> '') FROM contract_documents k WHERE k.id = c.ref)
	END`

// changementFichier is the PDF of the thing, as "<typ>/<id>" of /dl.
const changementFichier = `CASE c.kind
	WHEN 'expense' THEN (SELECT CASE WHEN e.hash_file <> '' THEN 'invoice/' || e.hash_file
		WHEN e.invoice_id <> '' THEN 'invoiceid/' || e.invoice_id END FROM expenses e WHERE e.id = c.ref)
	WHEN 'account_document' THEN (SELECT 'doc/' || d.hash_file FROM account_documents d WHERE d.id = c.ref AND d.hash_file <> '')
	WHEN 'contract_document' THEN (SELECT 'contract/' || k.hash_file FROM contract_documents k WHERE k.id = c.ref AND k.hash_file <> '')
	END`

// GetChangements returns at most limit rows of the journal that come after
// seq depuis, oldest first.
func GetChangements(ctx context.Context, db *sql.DB, depuis int64, limit int) ([]ChangementDB, error) {
	rows, err := db.QueryContext(ctx, `SELECT c.seq, c.at, c.kind, c.ref, c.action, `+changementObjet+`, `+changementFichier+`
		FROM changements c WHERE c.seq > ? ORDER BY c.seq LIMIT ?`, depuis, limit)
	if err != nil {
		return nil, fmt.Errorf("while reading the journal: %w", err)
	}
	defer rows.Close()
	out := []ChangementDB{}
	for rows.Next() {
		var c ChangementDB
		var objet, fichier sql.NullString
		if err := rows.Scan(&c.Seq, &c.At, &c.Kind, &c.Ref, &c.Action, &objet, &fichier); err != nil {
			return nil, fmt.Errorf("while reading the journal: %w", err)
		}
		c.Objet = json.RawMessage("null")
		if objet.Valid {
			c.Objet = json.RawMessage(objet.String)
		}
		c.Fichier = fichier.String
		out = append(out, c)
	}
	return out, rows.Err()
}

// DernierChangement is the seq of the last row of the journal, 0 when empty:
// the cursor of a reader that only wants what comes next.
func DernierChangement(ctx context.Context, db *sql.DB) (int64, error) {
	var seq int64
	err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM changements`).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("while reading the end of the journal: %w", err)
	}
	return seq, nil
}
