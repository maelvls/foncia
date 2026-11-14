package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// ImportAffairesCmd reads a JSON array of affaires and inserts them into the
// database. The expected shape matches db.AffaireDB with lowercase JSON field
// names, plus a relances array:
//
//	[
//	  {
//	    "numero": 1, "titre": "...", "localisation": "...",
//	    "action_foncia": "...", "responsable": "...", "date_signalement": "...",
//	    "lien_devis": "...", "obs_copro": "...", "obs_syndic": "...",
//	    "date_levee": "", "statut": "en_cours",
//	    "relances": [{"date": "13/08/2026", "note": "réunion"}, ...]
//	  },
//	  ...
//	]
//
// Used once to seed the database from the Excel the conseil kept before this
// service existed. It refuses to run when the table already has rows, so that
// running it twice can't double them.
func ImportAffairesCmd(ctx context.Context, sqlDB *sql.DB, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		logutil.Errorf("while reading %s: %v", path, err)
		os.Exit(1)
	}

	var in []importRow
	if err := json.Unmarshal(raw, &in); err != nil {
		logutil.Errorf("while parsing %s: %v", path, err)
		os.Exit(1)
	}

	var existing int
	if err := sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM affaires`).Scan(&existing); err != nil {
		logutil.Errorf("while counting existing affaires: %v", err)
		os.Exit(1)
	}
	if existing > 0 {
		logutil.Errorf("the affaires table already has %d rows — refusing to import; clear the table first (DELETE FROM affaires; DELETE FROM affaires_relances;) or import into a fresh database", existing)
		os.Exit(1)
	}

	for i, r := range in {
		relances := make([]db.AffaireRelanceDB, 0, len(r.Relances))
		for _, rl := range r.Relances {
			relances = append(relances, db.AffaireRelanceDB{Date: rl.Date, Note: rl.Note})
		}
		statut := db.AffaireStatut(r.Statut)
		if statut != db.AffaireStatutEnCours && statut != db.AffaireStatutLevee {
			logutil.Errorf("affaire %d: unknown statut %q (expected en_cours or levee)", i, r.Statut)
			os.Exit(1)
		}
		_, err := db.InsertAffaire(ctx, sqlDB, db.AffaireDB{
			Numero:          r.Numero,
			Titre:           r.Titre,
			Localisation:    r.Localisation,
			ActionFoncia:    r.ActionFoncia,
			Responsable:     r.Responsable,
			DateSignalement: r.DateSignalement,
			LienDevis:       r.LienDevis,
			ObsCopro:        r.ObsCopro,
			ObsSyndic:       r.ObsSyndic,
			DateLevee:       r.DateLevee,
			Statut:          statut,
			Relances:        relances,
		})
		if err != nil {
			logutil.Errorf("while inserting affaire %d (n°%d %q): %v", i, r.Numero, r.Titre, err)
			os.Exit(1)
		}
	}
	fmt.Printf("imported %d affaires\n", len(in))
}

type importRow struct {
	Numero          int                `json:"numero"`
	Titre           string             `json:"titre"`
	Localisation    string             `json:"localisation"`
	ActionFoncia    string             `json:"action_foncia"`
	Responsable     string             `json:"responsable"`
	DateSignalement string             `json:"date_signalement"`
	LienDevis       string             `json:"lien_devis"`
	ObsCopro        string             `json:"obs_copro"`
	ObsSyndic       string             `json:"obs_syndic"`
	DateLevee       string             `json:"date_levee"`
	Statut          string             `json:"statut"`
	Relances        []importRowRelance `json:"relances"`
}

type importRowRelance struct {
	Date string `json:"date"`
	Note string `json:"note"`
}

// ImportRemboursementsCmd reads a JSON array of remboursements and inserts
// them, once, like ImportAffairesCmd. The amounts are in euros as a person
// writes them ("39,85"); the purchase dates are AAAA-MM-JJ or empty:
//
//	[
//	  {
//	    "objet": "...", "vendeur": "...", "montant": "39,85", "date_achat": "2021-05-24",
//	    "demandeur": "...", "date_demande": "Email 23/07/2025", "statut": "rembourse",
//	    "date_remboursement": "18/08/2025", "preuve": "", "detail": ""
//	  },
//	  ...
//	]
func ImportRemboursementsCmd(ctx context.Context, sqlDB *sql.DB, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		logutil.Errorf("while reading %s: %v", path, err)
		os.Exit(1)
	}
	var in []importRemboursement
	if err := json.Unmarshal(raw, &in); err != nil {
		logutil.Errorf("while parsing %s: %v", path, err)
		os.Exit(1)
	}

	var existing int
	if err := sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM remboursements`).Scan(&existing); err != nil {
		logutil.Errorf("while counting existing remboursements: %v", err)
		os.Exit(1)
	}
	if existing > 0 {
		logutil.Errorf("the remboursements table already has %d rows, refusing to import", existing)
		os.Exit(1)
	}

	// Parse everything before inserting anything: a bad row must not leave
	// the table half filled, since the next run would then refuse to start.
	rows := make([]db.RemboursementDB, 0, len(in))
	for i, r := range in {
		montant, err := db.ParseEuros(r.Montant)
		if err != nil {
			logutil.Errorf("remboursement %d (%q): %v", i, r.Objet, err)
			os.Exit(1)
		}
		statut := db.RemboursementStatut(r.Statut)
		if !statut.Valid() {
			logutil.Errorf("remboursement %d (%q): unknown statut %q", i, r.Objet, r.Statut)
			os.Exit(1)
		}
		rows = append(rows, db.RemboursementDB{
			Objet: r.Objet, Vendeur: r.Vendeur, Montant: montant, DateAchat: r.DateAchat,
			Demandeur: r.Demandeur, DateDemande: r.DateDemande, Statut: statut,
			DateRemboursement: r.DateRemboursement, Preuve: r.Preuve, Detail: r.Detail,
			CreatedBy: "import",
		})
	}
	for _, r := range rows {
		if _, err := db.InsertRemboursement(ctx, sqlDB, r); err != nil {
			logutil.Errorf("while inserting remboursement %q: %v", r.Objet, err)
			os.Exit(1)
		}
	}
	fmt.Printf("imported %d remboursements\n", len(rows))
}

type importRemboursement struct {
	Objet             string `json:"objet"`
	Vendeur           string `json:"vendeur"`
	Montant           string `json:"montant"`
	DateAchat         string `json:"date_achat"`
	Demandeur         string `json:"demandeur"`
	DateDemande       string `json:"date_demande"`
	Statut            string `json:"statut"`
	DateRemboursement string `json:"date_remboursement"`
	Preuve            string `json:"preuve"`
	Detail            string `json:"detail"`
}
