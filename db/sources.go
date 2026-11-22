package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// What feeds the affaires without being copied by hand: files kept on disk,
// messages (e-mails, WhatsApp) and Foncia novelties. See
// db/migrations/0005_sources.sql.

// -----------------------------------------------------------------------------
// fichiers
// -----------------------------------------------------------------------------

type FichierOrigine string

const (
	FichierEnvoi    FichierOrigine = "envoi"
	FichierGmail    FichierOrigine = "gmail"
	FichierWhatsApp FichierOrigine = "whatsapp"
)

type FichierDB struct {
	SHA256    string
	Nom       string
	Mime      string
	Taille    int64
	Origine   FichierOrigine
	Auteur    string
	CreatedAt time.Time
}

// IsPDF and IsImage drive how the file is shown and whether its text can be
// read.
func (f FichierDB) IsPDF() bool   { return f.Mime == "application/pdf" }
func (f FichierDB) IsImage() bool { return strings.HasPrefix(f.Mime, "image/") }

// InsertFichier records a file. The same content arriving a second time keeps
// the first name and origin: the row is about the content.
func InsertFichier(ctx context.Context, db *sql.DB, f FichierDB) error {
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now()
	}
	_, err := db.ExecContext(ctx, `
INSERT OR IGNORE INTO fichiers (sha256, nom, mime, taille, origine, auteur, created_at)
VALUES (?,?,?,?,?,?,?)`,
		f.SHA256, f.Nom, f.Mime, f.Taille, string(f.Origine), f.Auteur, formatTime(f.CreatedAt))
	if err != nil {
		return fmt.Errorf("while inserting fichier: %w", err)
	}
	return nil
}

const fichierColumns = `sha256, nom, mime, taille, origine, auteur, created_at`

func scanFichier(rows *sql.Rows) (FichierDB, error) {
	var f FichierDB
	var origine, createdAt string
	if err := rows.Scan(&f.SHA256, &f.Nom, &f.Mime, &f.Taille, &origine, &f.Auteur, &createdAt); err != nil {
		return f, err
	}
	f.Origine = FichierOrigine(origine)
	var err error
	f.CreatedAt, err = parseTime("created_at", createdAt)
	return f, err
}

func GetFichier(ctx context.Context, db *sql.DB, sha string) (FichierDB, error) {
	got, err := queryAll(ctx, db, `SELECT `+fichierColumns+` FROM fichiers WHERE sha256 = ?`, scanFichier, sha)
	if err != nil {
		return FichierDB{}, err
	}
	if len(got) == 0 {
		return FichierDB{}, sql.ErrNoRows
	}
	return got[0], nil
}

// FichierVisible tells whether a file is attached to an affaire, directly or
// through a source that is. Those are the files every co-owner may open; the
// others (attachments of messages still to sort) are for the administrators.
func FichierVisible(ctx context.Context, db *sql.DB, sha string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM affaires_liens WHERE kind = 'fichier' AND ref = ?)
    OR EXISTS (SELECT 1 FROM sources_fichiers sf
               JOIN affaires_liens l ON l.kind = 'source' AND l.ref = sf.source_id
               WHERE sf.sha256 = ?)`, sha, sha).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("while checking whether fichier %s is attached: %w", sha, err)
	}
	return n == 1, nil
}

// -----------------------------------------------------------------------------
// sources
// -----------------------------------------------------------------------------

type SourceCanal string

const (
	CanalGmail    SourceCanal = "gmail"
	CanalWhatsApp SourceCanal = "whatsapp"
	CanalFoncia   SourceCanal = "foncia"
)

func (c SourceCanal) French() string {
	switch c {
	case CanalGmail:
		return "E-mail"
	case CanalWhatsApp:
		return "WhatsApp"
	case CanalFoncia:
		return "Foncia"
	}
	return string(c)
}

type SourceEtat string

const (
	SourceATrier  SourceEtat = "a_trier"
	SourceClassee SourceEtat = "classee"
	SourceIgnoree SourceEtat = "ignoree"
)

func (e SourceEtat) French() string {
	switch e {
	case SourceATrier:
		return "À trier"
	case SourceClassee:
		return "Classée"
	case SourceIgnoree:
		return "Écartée"
	}
	return string(e)
}

type SourceDB struct {
	ID            string
	Canal         SourceCanal
	ExtID         string
	Fil           string
	FilTitre      string
	Auteur        string
	Destinataires string
	Sujet         string
	Texte         string
	Date          time.Time
	URL           string
	Ref           string
	Etat          SourceEtat
	TraitePar     string
	TraiteLe      time.Time // Zero while à trier.
	CreatedAt     time.Time

	Fichiers []SourceFichier
}

// SourceFichier is an attachment of a source, with the name it had in the
// message (the same content may have been sent under several names).
type SourceFichier struct {
	FichierDB
	NomDansMessage string
}

// Titre is what a source is called in lists: the subject, else the start of
// the text.
func (s SourceDB) Titre() string {
	if s.Sujet != "" {
		return s.Sujet
	}
	t := strings.Join(strings.Fields(s.Texte), " ")
	if r := []rune(t); len(r) > 90 {
		return string(r[:90]) + "…"
	}
	if t == "" {
		return "(sans texte)"
	}
	return t
}

// Extrait is the beginning of the text, for the lists.
func (s SourceDB) Extrait(n int) string {
	t := strings.Join(strings.Fields(s.Texte), " ")
	if r := []rune(t); len(r) > n {
		return string(r[:n]) + "…"
	}
	return t
}

// ErrSourceExists is returned by InsertSource when the message was already
// collected.
var ErrSourceExists = errors.New("source déjà collectée")

// InsertSource records a collected message and its attachments (which must
// already be in fichiers). It returns ErrSourceExists when (canal, ext_id) is
// already known, which is how the collectors stay idempotent.
func InsertSource(ctx context.Context, db *sql.DB, s SourceDB) (string, error) {
	if s.ID == "" {
		s.ID = newAffaireID()
	}
	if s.Etat == "" {
		s.Etat = SourceATrier
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	inserted := false
	err := inTx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO sources (id, canal, ext_id, fil, fil_titre, auteur, destinataires, sujet, texte,
                               date, url, ref, etat, traite_par, traite_le, created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			s.ID, string(s.Canal), s.ExtID, s.Fil, s.FilTitre, s.Auteur, s.Destinataires, s.Sujet, s.Texte,
			formatTime(s.Date), s.URL, s.Ref, string(s.Etat), s.TraitePar, formatOptionalTime(s.TraiteLe), formatTime(s.CreatedAt))
		if err != nil {
			return fmt.Errorf("while inserting source: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		inserted = true
		for _, f := range s.Fichiers {
			nom := f.NomDansMessage
			if nom == "" {
				nom = f.Nom
			}
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO sources_fichiers (source_id, sha256, nom) VALUES (?,?,?)`, s.ID, f.SHA256, nom); err != nil {
				return fmt.Errorf("while attaching fichier %s to source: %w", f.SHA256, err)
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if !inserted {
		return "", ErrSourceExists
	}
	return s.ID, nil
}

// SourceExists tells whether a message was already collected, so that a
// collector can skip downloading it again.
func SourceExists(ctx context.Context, db *sql.DB, canal SourceCanal, extID string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM sources WHERE canal = ? AND ext_id = ?)`, string(canal), extID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("while checking for source %s/%s: %w", canal, extID, err)
	}
	return n == 1, nil
}

const sourceColumns = `id, canal, ext_id, fil, fil_titre, auteur, destinataires, sujet, texte, date, url, ref, etat, traite_par, traite_le, created_at`

func scanSource(rows *sql.Rows) (SourceDB, error) {
	var s SourceDB
	var canal, etat, date, traiteLe, createdAt string
	if err := rows.Scan(&s.ID, &canal, &s.ExtID, &s.Fil, &s.FilTitre, &s.Auteur, &s.Destinataires, &s.Sujet, &s.Texte,
		&date, &s.URL, &s.Ref, &etat, &s.TraitePar, &traiteLe, &createdAt); err != nil {
		return s, err
	}
	s.Canal, s.Etat = SourceCanal(canal), SourceEtat(etat)
	var err error
	if s.Date, err = parseTime("date", date); err != nil {
		return s, err
	}
	if traiteLe != "" {
		if s.TraiteLe, err = parseTime("traite_le", traiteLe); err != nil {
			return s, err
		}
	}
	s.CreatedAt, err = parseTime("created_at", createdAt)
	return s, err
}

// SourcesFilter selects sources. The zero value selects everything.
type SourcesFilter struct {
	Etats []SourceEtat
	Canal SourceCanal
	Fil   string // With Canal: one thread or conversation.
	IDs   []string
	Limit int
}

// GetSources returns the sources matching the filter, newest first, with
// their attachments.
func GetSources(ctx context.Context, db *sql.DB, f SourcesFilter) ([]SourceDB, error) {
	var where []string
	var args []any
	if len(f.Etats) > 0 {
		where = append(where, "etat IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.Etats)), ",")+")")
		for _, e := range f.Etats {
			args = append(args, string(e))
		}
	}
	if f.Canal != "" {
		where = append(where, "canal = ?")
		args = append(args, string(f.Canal))
	}
	if f.Fil != "" {
		where = append(where, "fil = ?")
		args = append(args, f.Fil)
	}
	if len(f.IDs) > 0 {
		where = append(where, "id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.IDs)), ",")+")")
		for _, id := range f.IDs {
			args = append(args, id)
		}
	}
	q := `SELECT ` + sourceColumns + ` FROM sources`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY date DESC, rowid DESC"
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	sources, err := queryAll(ctx, db, q, scanSource, args...)
	if err != nil {
		return nil, fmt.Errorf("while listing sources: %w", err)
	}
	if err := attachFichiers(ctx, db, sources); err != nil {
		return nil, err
	}
	return sources, nil
}

func GetSource(ctx context.Context, db *sql.DB, id string) (SourceDB, error) {
	got, err := GetSources(ctx, db, SourcesFilter{IDs: []string{id}})
	if err != nil {
		return SourceDB{}, err
	}
	if len(got) == 0 {
		return SourceDB{}, sql.ErrNoRows
	}
	return got[0], nil
}

func attachFichiers(ctx context.Context, db *sql.DB, sources []SourceDB) error {
	if len(sources) == 0 {
		return nil
	}
	byID := make(map[string]int, len(sources))
	ids := make([]any, 0, len(sources))
	for i, s := range sources {
		byID[s.ID] = i
		ids = append(ids, s.ID)
	}
	for chunk := range chunks(ids, 500) {
		rows, err := queryAll(ctx, db, `
SELECT sf.source_id, sf.nom, f.sha256, f.nom, f.mime, f.taille, f.origine, f.auteur, f.created_at
FROM sources_fichiers sf JOIN fichiers f ON f.sha256 = sf.sha256
WHERE sf.source_id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")+`)
ORDER BY sf.rowid`,
			func(rows *sql.Rows) (struct {
				sourceID string
				f        SourceFichier
			}, error) {
				var r struct {
					sourceID string
					f        SourceFichier
				}
				var origine, createdAt string
				if err := rows.Scan(&r.sourceID, &r.f.NomDansMessage, &r.f.SHA256, &r.f.Nom, &r.f.Mime, &r.f.Taille, &origine, &r.f.Auteur, &createdAt); err != nil {
					return r, err
				}
				r.f.Origine = FichierOrigine(origine)
				var err error
				r.f.CreatedAt, err = parseTime("created_at", createdAt)
				return r, err
			}, chunk...)
		if err != nil {
			return fmt.Errorf("while listing the attachments of sources: %w", err)
		}
		for _, r := range rows {
			i := byID[r.sourceID]
			sources[i].Fichiers = append(sources[i].Fichiers, r.f)
		}
	}
	return nil
}

// SetSourceEtat marks a source as sorted (classee), set aside (ignoree) or
// back to sort (a_trier), and by whom.
func SetSourceEtat(ctx context.Context, db *sql.DB, id string, etat SourceEtat, par string) error {
	traiteLe := ""
	if etat != SourceATrier {
		traiteLe = formatTime(time.Now())
	} else {
		par = ""
	}
	res, err := db.ExecContext(ctx, `UPDATE sources SET etat = ?, traite_par = ?, traite_le = ? WHERE id = ?`, string(etat), par, traiteLe, id)
	if err != nil {
		return fmt.Errorf("while updating source %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CountSources counts the sources per state, for the navigation badge.
func CountSources(ctx context.Context, db *sql.DB) (map[SourceEtat]int, error) {
	rows, err := queryAll(ctx, db, `SELECT etat, COUNT(*) FROM sources GROUP BY etat`,
		func(rows *sql.Rows) (struct {
			e string
			n int
		}, error) {
			var r struct {
				e string
				n int
			}
			return r, rows.Scan(&r.e, &r.n)
		})
	if err != nil {
		return nil, fmt.Errorf("while counting sources: %w", err)
	}
	out := make(map[SourceEtat]int)
	for _, r := range rows {
		out[SourceEtat(r.e)] = r.n
	}
	return out, nil
}

// CanalStats is what was collected from one channel so far.
type CanalStats struct {
	N       int
	Dernier time.Time // When the most recent message was sent.
}

// StatsSources tells, per channel, how many sources were collected and when
// the most recent one was sent. A channel without any source is absent.
func StatsSources(ctx context.Context, db *sql.DB) (map[SourceCanal]CanalStats, error) {
	type ligne struct {
		canal, dernier string
		n              int
	}
	rows, err := queryAll(ctx, db, `SELECT canal, COUNT(*), MAX(date) FROM sources GROUP BY canal`,
		func(rows *sql.Rows) (ligne, error) {
			var l ligne
			return l, rows.Scan(&l.canal, &l.n, &l.dernier)
		})
	if err != nil {
		return nil, fmt.Errorf("while counting sources per channel: %w", err)
	}
	out := make(map[SourceCanal]CanalStats)
	for _, l := range rows {
		s := CanalStats{N: l.n}
		// The dates are written by formatTime, in UTC: MAX on the text is
		// the most recent, to the second.
		if s.Dernier, err = parseTime("date", l.dernier); err != nil {
			return nil, fmt.Errorf("while counting sources per channel: %w", err)
		}
		out[SourceCanal(l.canal)] = s
	}
	return out, nil
}

// AffairesOfSource returns the affaires a source is attached to.
func AffairesOfSource(ctx context.Context, db *sql.DB, sourceID string) ([]AffaireRef, error) {
	return queryAll(ctx, db, `
SELECT a.id, a.numero, a.titre, a.statut FROM affaires_liens l JOIN affaires a ON a.id = l.affaire_id
WHERE l.kind = 'source' AND l.ref = ? ORDER BY a.numero`,
		func(rows *sql.Rows) (AffaireRef, error) {
			var r AffaireRef
			var statut string
			err := rows.Scan(&r.ID, &r.Numero, &r.Titre, &statut)
			r.Statut = AffaireStatut(statut)
			return r, err
		}, sourceID)
}

// AffairesOfFil returns the affaires that the other messages of the same
// thread or conversation are attached to. An e-mail that answers a thread
// already filed under an affaire belongs to it too.
func AffairesOfFil(ctx context.Context, db *sql.DB, canal SourceCanal, fil, exceptID string) ([]AffaireRef, error) {
	if fil == "" {
		return nil, nil
	}
	return queryAll(ctx, db, `
SELECT DISTINCT a.id, a.numero, a.titre, a.statut
FROM sources s
JOIN affaires_liens l ON l.kind = 'source' AND l.ref = s.id
JOIN affaires a ON a.id = l.affaire_id
WHERE s.canal = ? AND s.fil = ? AND s.id <> ?
ORDER BY a.numero`,
		func(rows *sql.Rows) (AffaireRef, error) {
			var r AffaireRef
			var statut string
			err := rows.Scan(&r.ID, &r.Numero, &r.Titre, &statut)
			r.Statut = AffaireStatut(statut)
			return r, err
		}, string(canal), fil, exceptID)
}

// ExpenseIDOf is the primary key that the expenses table gives to e, which
// is what a "depense" link points to.
func ExpenseIDOf(e ExpenseDocumentDB) string { return expenseID(e) }

func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return formatTime(t)
}

// -----------------------------------------------------------------------------
// reglages
// -----------------------------------------------------------------------------

// GetReglage returns the value of a setting, or "" when it was never set.
func GetReglage(ctx context.Context, db *sql.DB, cle string) (string, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT valeur FROM reglages WHERE cle = ?`, cle).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("while reading setting %s: %w", cle, err)
	}
	return v, nil
}

func SetReglage(ctx context.Context, db *sql.DB, cle, valeur string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO reglages (cle, valeur) VALUES (?, ?) ON CONFLICT (cle) DO UPDATE SET valeur = excluded.valeur`, cle, valeur)
	if err != nil {
		return fmt.Errorf("while writing setting %s: %w", cle, err)
	}
	return nil
}

// InitReglage sets a setting only if it has no value yet, and returns the
// value it ends up with. Two processes racing get the same value.
func InitReglage(ctx context.Context, db *sql.DB, cle, valeur string) (string, error) {
	if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO reglages (cle, valeur) VALUES (?, ?)`, cle, valeur); err != nil {
		return "", fmt.Errorf("while initialising setting %s: %w", cle, err)
	}
	return GetReglage(ctx, db, cle)
}
