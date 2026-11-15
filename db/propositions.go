package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// What Claude proposes to do with the sources. Nothing is applied until an
// administrator accepts it. See db/migrations/0005_sources.sql.

type PropositionAction string

const (
	PropRattacher    PropositionAction = "rattacher"
	PropCreerAffaire PropositionAction = "creer_affaire"
	PropCommenter    PropositionAction = "commenter"
	PropRelancer     PropositionAction = "relancer"
	PropLever        PropositionAction = "lever"
	PropIgnorer      PropositionAction = "ignorer"
)

func (a PropositionAction) Valid() bool {
	switch a {
	case PropRattacher, PropCreerAffaire, PropCommenter, PropRelancer, PropLever, PropIgnorer:
		return true
	}
	return false
}

func (a PropositionAction) French() string {
	switch a {
	case PropRattacher:
		return "Rattacher"
	case PropCreerAffaire:
		return "Nouvelle affaire"
	case PropCommenter:
		return "Commentaire"
	case PropRelancer:
		return "Relance"
	case PropLever:
		return "Lever l'affaire"
	case PropIgnorer:
		return "Écarter"
	}
	return string(a)
}

type PropositionEtat string

const (
	PropEnAttente PropositionEtat = "en_attente"
	PropAcceptee  PropositionEtat = "acceptee"
	PropRefusee   PropositionEtat = "refusee"
)

func (e PropositionEtat) French() string {
	switch e {
	case PropEnAttente:
		return "En attente"
	case PropAcceptee:
		return "Acceptée"
	case PropRefusee:
		return "Refusée"
	}
	return string(e)
}

// PropositionDonnees holds what an action needs beyond the affaire and the
// sources. Only the fields of the action are set.
type PropositionDonnees struct {
	// creer_affaire
	Titre           string `json:"titre,omitempty"`
	Localisation    string `json:"localisation,omitempty"`
	ActionFoncia    string `json:"action_foncia,omitempty"`
	Responsable     string `json:"responsable,omitempty"`
	DateSignalement string `json:"date_signalement,omitempty"`
	// commenter
	Texte string `json:"texte,omitempty"`
	// relancer
	Date string `json:"date,omitempty"`
	Note string `json:"note,omitempty"`
}

type PropositionDB struct {
	ID            string
	Action        PropositionAction
	AffaireID     string
	SourceIDs     []string
	Donnees       PropositionDonnees
	Justification string
	Citation      string
	Etat          PropositionEtat
	Auteur        string
	DecidePar     string
	DecideLe      time.Time
	Resultat      string
	CreatedAt     time.Time
}

func InsertProposition(ctx context.Context, db *sql.DB, p PropositionDB) (string, error) {
	if !p.Action.Valid() {
		return "", fmt.Errorf("unknown action %q", p.Action)
	}
	if p.ID == "" {
		p.ID = newAffaireID()
	}
	if p.Etat == "" {
		p.Etat = PropEnAttente
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	if p.SourceIDs == nil {
		p.SourceIDs = []string{}
	}
	ids, err := json.Marshal(p.SourceIDs)
	if err != nil {
		return "", err
	}
	donnees, err := json.Marshal(p.Donnees)
	if err != nil {
		return "", err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO propositions (id, action, affaire_id, source_ids, donnees, justification, citation,
                          etat, auteur, decide_par, decide_le, resultat, created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.ID, string(p.Action), p.AffaireID, string(ids), string(donnees), p.Justification, p.Citation,
		string(p.Etat), p.Auteur, p.DecidePar, formatOptionalTime(p.DecideLe), p.Resultat, formatTime(p.CreatedAt))
	if err != nil {
		return "", fmt.Errorf("while inserting proposition: %w", err)
	}
	return p.ID, nil
}

const propositionColumns = `id, action, affaire_id, source_ids, donnees, justification, citation, etat, auteur, decide_par, decide_le, resultat, created_at`

func scanProposition(rows *sql.Rows) (PropositionDB, error) {
	var p PropositionDB
	var action, ids, donnees, etat, decideLe, createdAt string
	if err := rows.Scan(&p.ID, &action, &p.AffaireID, &ids, &donnees, &p.Justification, &p.Citation,
		&etat, &p.Auteur, &p.DecidePar, &decideLe, &p.Resultat, &createdAt); err != nil {
		return p, err
	}
	p.Action, p.Etat = PropositionAction(action), PropositionEtat(etat)
	if err := json.Unmarshal([]byte(ids), &p.SourceIDs); err != nil {
		return p, fmt.Errorf("proposition %s: source_ids: %w", p.ID, err)
	}
	if err := json.Unmarshal([]byte(donnees), &p.Donnees); err != nil {
		return p, fmt.Errorf("proposition %s: donnees: %w", p.ID, err)
	}
	var err error
	if decideLe != "" {
		if p.DecideLe, err = parseTime("decide_le", decideLe); err != nil {
			return p, err
		}
	}
	p.CreatedAt, err = parseTime("created_at", createdAt)
	return p, err
}

// GetPropositions returns the propositions in the given states (all when
// none), oldest first for those waiting, so that they are read in the order
// the messages came.
func GetPropositions(ctx context.Context, db *sql.DB, limit int, etats ...PropositionEtat) ([]PropositionDB, error) {
	q := `SELECT ` + propositionColumns + ` FROM propositions`
	var args []any
	if len(etats) > 0 {
		q += ` WHERE etat IN (` + strings.TrimSuffix(strings.Repeat("?,", len(etats)), ",") + `)`
		for _, e := range etats {
			args = append(args, string(e))
		}
	}
	if len(etats) == 1 && etats[0] == PropEnAttente {
		q += ` ORDER BY created_at, rowid`
	} else {
		q += ` ORDER BY created_at DESC, rowid DESC`
	}
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	return queryAll(ctx, db, q, scanProposition, args...)
}

func GetProposition(ctx context.Context, db *sql.DB, id string) (PropositionDB, error) {
	got, err := queryAll(ctx, db, `SELECT `+propositionColumns+` FROM propositions WHERE id = ?`, scanProposition, id)
	if err != nil {
		return PropositionDB{}, err
	}
	if len(got) == 0 {
		return PropositionDB{}, sql.ErrNoRows
	}
	return got[0], nil
}

// DecideProposition records the decision on a proposition that is still
// waiting. It returns sql.ErrNoRows when it was already decided, so that two
// clicks don't apply it twice.
func DecideProposition(ctx context.Context, db *sql.DB, id string, etat PropositionEtat, par, resultat string) error {
	res, err := db.ExecContext(ctx, `UPDATE propositions SET etat = ?, decide_par = ?, decide_le = ?, resultat = ? WHERE id = ? AND etat = 'en_attente'`,
		string(etat), par, formatTime(time.Now()), resultat, id)
	if err != nil {
		return fmt.Errorf("while deciding proposition %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SourcesProposees returns the ids of the sources that a waiting proposition
// already covers, so that Claude doesn't look at them again.
func SourcesProposees(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	props, err := GetPropositions(ctx, db, 0, PropEnAttente)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	for _, p := range props {
		for _, id := range p.SourceIDs {
			out[id] = true
		}
	}
	return out, nil
}

// CountPropositionsEnAttente is for the navigation badge.
func CountPropositionsEnAttente(ctx context.Context, db *sql.DB) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM propositions WHERE etat = 'en_attente'`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("while counting propositions: %w", err)
	}
	return n, nil
}
