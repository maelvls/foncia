package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// The residents follow the address book of the phone without anybody
// exporting anything: WhatsApp sends the contacts of the phone to its linked
// devices, the whatsapp service is one of them (see --whatsapp-url), and it
// hands over the contacts whose name carries an apartment.
//
// What WhatsApp doesn't know: who has no WhatsApp account, the other numbers
// of a person, the e-mails. An export of the contacts (the form of /residents)
// adds those.

var residentsPeriod = flag.Duration("residents-period", time.Hour, "Period at which the residents are read again from the address book of the whatsapp service (--whatsapp-url). 0 turns the periodic reading off; the button of /residents still reads it.")

// carnetFunc reads the neighbours of an address book. nil when there is no
// whatsapp service to ask.
type carnetFunc func(ctx context.Context) ([]contactVCard, error)

// carnetConfigure returns the address book the flags turn on, or nil.
func carnetConfigure(sqlDB *sql.DB) (carnetFunc, error) {
	if *whatsappURL == "" {
		return nil, nil
	}
	w, err := newWhatsappCollecteur(sqlDB)
	if err != nil {
		return nil, err
	}
	return w.carnet, nil
}

// etatCarnet is how the last reading of WhatsApp went, kept in the settings
// for /residents to show.
type etatCarnet struct {
	Quand    time.Time `json:"quand"`
	Retenus  int       `json:"retenus"`
	Ajouts   int       `json:"ajouts"`
	MisAJour int       `json:"mis_a_jour"`
	Absents  int       `json:"absents"`
	Erreur   string    `json:"erreur,omitempty"`
}

const reglageCarnet = "residents_whatsapp"

// dernierCarnet returns the last reading, or false when there was none.
func dernierCarnet(ctx context.Context, sqlDB *sql.DB) (etatCarnet, bool) {
	raw, err := db.GetReglage(ctx, sqlDB, reglageCarnet)
	if err != nil || raw == "" {
		return etatCarnet{}, false
	}
	var e etatCarnet
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return etatCarnet{}, false
	}
	return e, true
}

// synchroniserResidents reads the address book and brings the residents up to
// date with it. Nobody is ever removed here: who left the address book is
// only reported, and removed by hand from /residents.
func synchroniserResidents(ctx context.Context, sqlDB *sql.DB, carnet carnetFunc) (importResidents, error) {
	etat := etatCarnet{Quand: time.Now()}
	cartes, err := carnet(ctx)
	var plan importResidents
	if err == nil {
		plan, err = appliquerContacts(ctx, sqlDB, cartes, db.ResidentDeWhatsApp, "whatsapp", false)
	}
	if err != nil {
		etat.Erreur = err.Error()
	} else {
		etat.Retenus, etat.Ajouts, etat.MisAJour, etat.Absents = plan.Retenus, len(plan.Ajouts), len(plan.MisAJour), len(plan.Absents)
	}
	// The context of a request may be gone by now; the state is worth
	// keeping all the same.
	if raw, jerr := json.Marshal(etat); jerr == nil {
		if serr := db.SetReglage(context.WithoutCancel(ctx), sqlDB, reglageCarnet, string(raw)); serr != nil {
			logutil.Errorf("residents: keeping the state of the reading of WhatsApp: %v", serr)
		}
	}
	return plan, err
}

// synchroniserResidentsEnBoucle reads the address book at the start, then
// every --residents-period.
func synchroniserResidentsEnBoucle(ctx context.Context, sqlDB *sql.DB, carnet carnetFunc) {
	if carnet == nil || *residentsPeriod <= 0 {
		return
	}
	for {
		plan, err := synchroniserResidents(ctx, sqlDB, carnet)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			logutil.Errorf("residents: reading the address book of WhatsApp: %v", err)
		case len(plan.Ajouts)+len(plan.MisAJour) > 0:
			logutil.Infof("residents: %d neighbour(s) in the address book of WhatsApp: %d added, %d updated, %d no longer there",
				plan.Retenus, len(plan.Ajouts), len(plan.MisAJour), len(plan.Absents))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*residentsPeriod):
		}
	}
}
