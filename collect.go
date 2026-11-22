package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// The collectors bring the messages about the building into the sources
// table: the e-mails (collect_gmail.go), the WhatsApp messages
// (collect_whatsapp.go) and what is new at Foncia (below). They only add
// rows; sorting them is for the administrators and Claude.

var (
	sourcesPeriod = flag.Duration("sources-period", 10*time.Minute, "Period at which the e-mails and WhatsApp messages are collected.")
	sourcesSince  = flag.String("sources-since", "", "On the first collection, how far back to look, as a date (2026-10-01). Later collections start where the previous one stopped. Empty means 30 days back.")
)

// debutCollecte is when a collector that never ran starts from.
func debutCollecte(now time.Time) (time.Time, error) {
	if *sourcesSince == "" {
		return now.AddDate(0, 0, -30), nil
	}
	t, err := time.ParseInLocation("2006-01-02", *sourcesSince, paris)
	if err != nil {
		return time.Time{}, fmt.Errorf("--sources-since: %w", err)
	}
	return t, nil
}

// collecteursConfigures returns the collectors that the flags turn on.
func collecteursConfigures(ctx context.Context, sqlDB *sql.DB) ([]collecteur, error) {
	var out []collecteur
	if *gmailTokenFile != "" {
		g, err := newGmailCollecteur(sqlDB)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
		logutil.Infof("collecting the e-mails of %s matching %q", *gmailAccount, *gmailQuery)
	}
	if *whatsappURL != "" {
		w, err := newWhatsappCollecteur(sqlDB)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
		logutil.Infof("collecting the WhatsApp messages of %d conversation(s), %d filtered, and of the contacts matching %q", len(w.chats), len(w.filtered), *whatsappContacts)
	}
	return out, nil
}

// collecteur is one source of messages. collecter returns how many new
// sources it recorded.
type collecteur interface {
	nom() string
	collecter(ctx context.Context) (int, error)
}

// collecterEnBoucle runs the collectors every --sources-period, and asks
// Claude to look when something new came in.
func collecterEnBoucle(ctx context.Context, sqlDB *sql.DB, brain brainTrigger, collecteurs []collecteur) {
	if len(collecteurs) == 0 {
		return
	}
	for {
		total := 0
		for _, c := range collecteurs {
			n, err := c.collecter(ctx)
			// A mailbox that isn't connected is a state that /reglages
			// shows, not an error to log every ten minutes.
			if err != nil && !errors.Is(err, errGmailPasRelie) {
				logutil.Errorf("collecte %s: %v", c.nom(), err)
			}
			if n > 0 {
				logutil.Infof("collecte %s: %d nouveau(x) message(s)", c.nom(), n)
			}
			total += n
		}
		if total > 0 {
			if err := brain.demander(fmt.Sprintf("%d nouveau(x) message(s)", total)); err != nil {
				logutil.Errorf("asking Claude to run: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*sourcesPeriod):
		}
	}
}

// enregistrerSource records a collected message, then files it right away
// when it answers an e-mail thread that is already filed under a single
// affaire. It returns false when the message was already known.
func enregistrerSource(ctx context.Context, sqlDB *sql.DB, s db.SourceDB) (bool, error) {
	id, err := db.InsertSource(ctx, sqlDB, s)
	if errors.Is(err, db.ErrSourceExists) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if s.Canal != db.CanalGmail {
		return true, nil
	}
	affaires, err := db.AffairesOfFil(ctx, sqlDB, s.Canal, s.Fil, id)
	if err != nil || len(affaires) != 1 {
		return true, err
	}
	a, err := db.GetAffaire(ctx, sqlDB, affaires[0].ID)
	if err != nil {
		return true, err
	}
	s, err = db.GetSource(ctx, sqlDB, id)
	if err != nil {
		return true, err
	}
	if _, err := rattacherSource(ctx, sqlDB, s, a, "auto:fil"); err != nil {
		return true, fmt.Errorf("while filing source %s with its thread: %w", id, err)
	}
	logutil.Infof("source %s filed under affaire n°%d with the rest of its thread", id, a.Numero)
	return true, nil
}

// -----------------------------------------------------------------------------
// Foncia
// -----------------------------------------------------------------------------

// sourcesFoncia records the missions and invoices that the last sync found,
// so that they are sorted into the affaires like the messages are. Credits
// and the provisions called from the co-owners are left out: no affaire is
// about them.
func sourcesFoncia(ctx context.Context, sqlDB *sql.DB, baseURL string, missions []db.MissionDB, expenses []db.ExpenseDocumentDB) (int, error) {
	n := 0
	var errs []error
	for _, m := range missions {
		texte := strings.TrimSpace(m.Description)
		if len(m.WorkOrders) > 0 {
			var os []string
			for _, wo := range m.WorkOrders {
				os = append(os, strings.TrimSpace(wo.Number+" "+wo.Label+" — "+wo.Supplier.Name))
			}
			texte = strings.TrimSpace(texte + "\n\nOrdres de service :\n" + strings.Join(os, "\n"))
		}
		ok, err := enregistrerSource(ctx, sqlDB, db.SourceDB{
			Canal:  db.CanalFoncia,
			ExtID:  "mission:" + m.ID,
			Ref:    "mission:" + m.ID,
			Auteur: "Foncia",
			Sujet:  m.KindFrench() + " : " + titreMission(m),
			Texte:  texte,
			Date:   m.StartedAt,
			URL:    baseURL + "/?filter=missions#" + m.ID,
		})
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			n++
		}
	}
	for _, e := range expenses {
		if e.Amount <= 0 {
			continue
		}
		id := db.ExpenseIDOf(e)
		ok, err := enregistrerSource(ctx, sqlDB, db.SourceDB{
			Canal:  db.CanalFoncia,
			ExtID:  "depense:" + id,
			Ref:    "depense:" + id,
			Auteur: "Foncia",
			Sujet:  "Facture : " + e.Label + " (" + e.Amount.String() + ")",
			Texte:  e.Label,
			Date:   e.Date,
			URL:    baseURL + "/comptes/depenses/" + id,
		})
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			n++
		}
	}
	return n, errors.Join(errs...)
}
