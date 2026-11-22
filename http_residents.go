package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// The page of the building, apartment by apartment: who owns it according to
// Foncia (http_coowners.go), then who lives there, who owns it without living
// there, who left, and how to call them.
//
// Who sees what: everybody who has an account sees the co-owners. The people
// and their numbers are for the administrators (--admin-users) only: these
// are personal phone numbers, given to one person and not to the fifteen or
// so co-owners who have an account here.

// maxVCard bounds an export of the contacts. The one of an iPhone holds the
// photos, which makes it tens of megabytes for a thousand contacts.
const maxVCard = 96 << 20

var errPasDeVCard = errors.New("ce fichier ne contient aucune fiche de contact (vCard)")

type appartement struct {
	Code string // "C01".
	Type string // "T3".
}

// appartements lists the apartments of the building, from the lots.
func appartements() []appartement {
	var out []appartement
	for _, l := range lotMapping {
		if strings.HasPrefix(l.Type, "T") {
			out = append(out, appartement{Code: l.Description, Type: l.Type})
		}
	}
	return out
}

type appartementResidents struct {
	appartement
	// Who owns it according to Foncia: the name on the title deed, which
	// may be a couple or an SCI.
	Coowners []coownerRow
	// Those who live there first, then the owners, then the others.
	Personnes    []db.ResidentDB
	SansResident bool
}

// NomsCoowners is for the search: the names and addresses of the co-owners.
func (a appartementResidents) NomsCoowners() string {
	var out []string
	for _, c := range a.Coowners {
		out = append(out, c.Name, c.Address)
	}
	return strings.Join(out, " ")
}

type residentsData struct {
	page
	Appartements   []appartementResidents
	Anciens        []db.ResidentDB
	NResidents     int
	NProprietaires int
	SansResident   []string // The apartments where nobody is known to live.

	// The co-owners according to Foncia, by apartment, and whether Foncia
	// could be asked at all. Those who only own parking spaces have no
	// apartment to be shown under.
	Coowners        []coownerRow
	CoownersParking []coownerRow
	CoownersErreur  bool

	// The address book of WhatsApp, when there is a whatsapp service to ask:
	// how its last reading went, if there was one.
	WhatsApp bool
	Carnet   *etatCarnet
}

type residentEditData struct {
	page
	IsNew        bool
	R            db.ResidentDB
	Appartements []appartement
}

type residentsImportData struct {
	page
	Plan importResidents
}

func addResidentsHandlers(mux *http.ServeMux, c copro) {
	mux.HandleFunc("GET /residents", c.residents)
	// The co-owners had a page of their own; the links to it still work.
	mux.HandleFunc("GET /coowners", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, c.basePath+"/residents", http.StatusFound)
	})
	mux.HandleFunc("GET /residents/export.csv", c.residentsCSV)
	mux.HandleFunc("POST /residents/import", c.residentsImporter)
	mux.HandleFunc("POST /residents/whatsapp", c.residentsWhatsApp)
	mux.HandleFunc("POST /residents/supprimer", c.residentsSupprimer)
	mux.HandleFunc("GET /residents/new", c.residentNew)
	mux.HandleFunc("POST /residents/new", c.residentCreate)
	mux.HandleFunc("GET /residents/{id}", c.residentEdit)
	mux.HandleFunc("POST /residents/{id}", c.residentUpdate)
	mux.HandleFunc("POST /residents/{id}/delete", c.residentDelete)
}

// parAppartement sorts everybody into the apartments of the building. An
// apartment nobody knows of (a typo in a contact) comes after the others
// rather than being hidden.
func parAppartement(rs []db.ResidentDB) (apps []appartementResidents, anciens []db.ResidentDB) {
	index := make(map[string]int)
	for _, a := range appartements() {
		index[a.Code] = len(apps)
		apps = append(apps, appartementResidents{appartement: a})
	}
	connus := len(apps)
	for _, r := range rs {
		if r.Qualite == db.ResidentAncien {
			anciens = append(anciens, r)
			continue
		}
		i, ok := index[r.Appartement]
		if !ok {
			i = len(apps)
			index[r.Appartement] = i
			apps = append(apps, appartementResidents{appartement: appartement{Code: r.Appartement}})
		}
		apps[i].Personnes = append(apps[i].Personnes, r)
	}
	sort.SliceStable(apps[connus:], func(i, j int) bool { return apps[connus+i].Code < apps[connus+j].Code })
	for i := range apps {
		p := apps[i].Personnes
		sort.SliceStable(p, func(a, b int) bool { return rangQualite(p[a].Qualite) > rangQualite(p[b].Qualite) })
		apps[i].SansResident = len(p) == 0 || p[0].Qualite != db.ResidentHabite
	}
	return apps, anciens
}

// residents is the page of the building, apartment by apartment. Everybody
// who has an account sees who owns each apartment according to Foncia (what
// /coowners used to show). The administrators also see the people behind the
// doors and how to call them: those rows aren't even read for the others.
func (c copro) residents(w http.ResponseWriter, r *http.Request) {
	data := residentsData{page: c.page(r, "residents")}
	var rs []db.ResidentDB
	if data.Admin {
		var err error
		if rs, err = db.GetResidents(r.Context(), c.sqlDB); err != nil {
			c.fail(w, "listing residents", err)
			return
		}
		data.WhatsApp = c.carnet != nil
		if e, ok := dernierCarnet(r.Context(), c.sqlDB); ok && data.WhatsApp {
			data.Carnet = &e
		}
	}
	if c.coowners != nil {
		var err error
		if data.Coowners, err = c.coowners(r.Context()); err != nil {
			// The phone numbers are worth showing without the co-owners.
			logutil.Errorf("residents: asking Foncia for the co-owners: %v", err)
			data.CoownersErreur = true
		}
	}
	data.Appartements, data.Anciens = parAppartement(rs)
	parCode := make(map[string]int, len(data.Appartements))
	for i, a := range data.Appartements {
		parCode[a.Code] = i
	}
	for _, co := range data.Coowners {
		if i, ok := parCode[co.Apartment]; ok {
			data.Appartements[i].Coowners = append(data.Appartements[i].Coowners, co)
		} else {
			data.CoownersParking = append(data.CoownersParking, co)
		}
	}
	for _, a := range data.Appartements {
		if a.SansResident {
			data.SansResident = append(data.SansResident, a.Code)
		}
		for _, p := range a.Personnes {
			switch p.Qualite {
			case db.ResidentHabite:
				data.NResidents++
			case db.ResidentProprietaire:
				data.NProprietaires++
			}
		}
	}
	c.render(w, "residents", data)
}

// residentsCSV is the directory as a spreadsheet, for those who print it or
// paste it somewhere.
func (c copro) residentsCSV(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	rs, err := db.GetResidents(r.Context(), c.sqlDB)
	if err != nil {
		c.fail(w, "listing residents", err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="residents-`+time.Now().In(paris).Format(time.DateOnly)+`.csv"`)
	w.Header().Set("Cache-Control", "private, no-store")
	// The byte order mark is for Excel, which otherwise reads Latin-1; the
	// semicolon is what a French Excel expects.
	_, _ = io.WriteString(w, "\xEF\xBB\xBF")
	out := csv.NewWriter(w)
	out.Comma = ';'
	_ = out.Write([]string{"Appartement", "Nom", "Qualité", "Détail", "Téléphone", "E-mail", "Note"})
	for _, p := range rs {
		_ = out.Write([]string{p.Appartement, p.Nom, p.Qualite.French(), p.Detail, p.Telephone, p.Email, p.Note})
	}
	out.Flush()
	if err := out.Error(); err != nil {
		logutil.Errorf("writing the residents as CSV: %v", err)
	}
}

func (c copro) residentNew(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	c.render(w, "resident_edit", residentEditData{
		page:  c.page(r, "residents"),
		IsNew: true,
		R: db.ResidentDB{
			Appartement: strings.ToUpper(r.URL.Query().Get("appartement")),
			Qualite:     db.ResidentHabite,
			Origine:     db.ResidentDuSite,
		},
		Appartements: appartements(),
	})
}

func (c copro) residentCreate(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	p, err := parseResidentForm(r)
	if err != nil {
		renderErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p.Origine, p.CreatedBy = db.ResidentDuSite, currentUser(r)
	id, err := db.InsertResident(r.Context(), c.sqlDB, p)
	if err != nil {
		c.fail(w, "insert resident", err)
		return
	}
	// No name in the message: it travels in the URL, and so in the logs of
	// the proxy.
	c.redirect(w, r, "/residents#resident-"+id, "Ajouté en "+p.Appartement+".")
}

func (c copro) resident(w http.ResponseWriter, r *http.Request) (db.ResidentDB, bool) {
	p, err := db.GetResident(r.Context(), c.sqlDB, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		renderErr(w, http.StatusNotFound, "Personne introuvable.")
		return p, false
	}
	if err != nil {
		c.fail(w, "get resident", err)
		return p, false
	}
	return p, true
}

func (c copro) residentEdit(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	p, ok := c.resident(w, r)
	if !ok {
		return
	}
	c.render(w, "resident_edit", residentEditData{page: c.page(r, "residents"), R: p, Appartements: appartements()})
}

func (c copro) residentUpdate(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	avant, ok := c.resident(w, r)
	if !ok {
		return
	}
	p, err := parseResidentForm(r)
	if err != nil {
		renderErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p.ID, p.Origine = avant.ID, avant.Origine
	if err := db.UpdateResident(r.Context(), c.sqlDB, p); err != nil {
		c.fail(w, "update resident", err)
		return
	}
	c.redirect(w, r, "/residents#resident-"+p.ID, "Enregistré.")
}

func (c copro) residentDelete(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	if err := db.DeleteResident(r.Context(), c.sqlDB, r.PathValue("id")); err != nil {
		c.fail(w, "delete resident", err)
		return
	}
	c.redirect(w, r, "/residents", "Supprimé.")
}

// residentsSupprimer removes several people at once: those an import found
// are no longer in the contacts.
func (c copro) residentsSupprimer(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		renderErr(w, http.StatusBadRequest, "Formulaire invalide.")
		return
	}
	ids := r.PostForm["id"]
	if err := db.ApplyResidents(r.Context(), c.sqlDB, nil, nil, ids); err != nil {
		c.fail(w, "delete residents", err)
		return
	}
	c.redirect(w, r, "/residents", fmt.Sprintf("%d supprimé(s).", len(ids)))
}

func (c copro) residentsImporter(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxVCard)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		renderErr(w, http.StatusBadRequest, "Envoi impossible : "+err.Error())
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	f, _, err := r.FormFile("contacts")
	if err != nil {
		renderErr(w, http.StatusBadRequest, "Aucun fichier choisi.")
		return
	}
	raw, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		c.fail(w, "reading the uploaded contacts", err)
		return
	}
	plan, err := importerResidents(r.Context(), c.sqlDB, raw, currentUser(r), false)
	if errors.Is(err, errPasDeVCard) {
		renderErr(w, http.StatusBadRequest, "Ce fichier ne contient aucune fiche de contact : il faut un export vCard (.vcf).")
		return
	}
	if err != nil {
		c.fail(w, "importing the contacts", err)
		return
	}
	logutil.Infof("residents: %s imported %d contact(s): %d added, %d updated, %d unchanged, %d no longer there",
		currentUser(r), plan.Retenus, len(plan.Ajouts), len(plan.MisAJour), plan.Inchanges, len(plan.Absents))
	c.render(w, "residents_import", residentsImportData{page: c.page(r, "residents"), Plan: plan})
}

// residentsWhatsApp reads the address book of WhatsApp now, without waiting
// for the next periodic reading, and shows what it changed.
func (c copro) residentsWhatsApp(w http.ResponseWriter, r *http.Request) {
	if !c.adminOnly(w, r) {
		return
	}
	if c.carnet == nil {
		renderErr(w, http.StatusNotFound, "Aucun service WhatsApp n'est branché sur ce site (--whatsapp-url).")
		return
	}
	plan, err := synchroniserResidents(r.Context(), c.sqlDB, c.carnet)
	if err != nil {
		logutil.Errorf("residents: reading the address book of WhatsApp: %v", err)
		renderErr(w, http.StatusBadGateway, "Le service WhatsApp n'a pas donné ses contacts. Le détail est dans les logs du serveur, et sur la page des résidents.")
		return
	}
	logutil.Infof("residents: %s read the address book of WhatsApp: %d neighbour(s), %d added, %d updated, %d unchanged, %d no longer there",
		currentUser(r), plan.Retenus, len(plan.Ajouts), len(plan.MisAJour), plan.Inchanges, len(plan.Absents))
	c.render(w, "residents_import", residentsImportData{page: c.page(r, "residents"), Plan: plan})
}

// importerResidents reads an export of the contacts and brings the table up to
// date. With purger, the people of an earlier import who are no longer in the
// contacts are removed; otherwise they are only reported.
func importerResidents(ctx context.Context, sqlDB *sql.DB, raw []byte, auteur string, purger bool) (importResidents, error) {
	cartes := lireVCards(raw)
	if len(cartes) == 0 {
		return importResidents{}, errPasDeVCard
	}
	return appliquerContacts(ctx, sqlDB, cartes, db.ResidentDesContacts, auteur, purger)
}

// appliquerContacts brings the table up to date with the contacts read from a
// source: an export (importerResidents) or WhatsApp (synchroniserResidents).
func appliquerContacts(ctx context.Context, sqlDB *sql.DB, cartes []contactVCard, source db.ResidentOrigine, auteur string, purger bool) (importResidents, error) {
	existants, err := db.GetResidents(ctx, sqlDB)
	if err != nil {
		return importResidents{}, err
	}
	plan := planifierImport(existants, cartes, source)
	for i := range plan.Ajouts {
		plan.Ajouts[i].CreatedBy = auteur
	}
	var suppressions []string
	if purger {
		// A file where nobody follows the convention is the wrong file, not
		// a building that emptied overnight.
		if plan.Retenus == 0 {
			return plan, fmt.Errorf("aucun contact du fichier ne porte d'appartement dans son nom : rien n'est supprimé")
		}
		for _, a := range plan.Absents {
			suppressions = append(suppressions, a.ID)
		}
	}
	if err := db.ApplyResidents(ctx, sqlDB, plan.Ajouts, plan.MisAJour, suppressions); err != nil {
		return plan, err
	}
	return plan, nil
}

func parseResidentForm(r *http.Request) (db.ResidentDB, error) {
	if err := r.ParseForm(); err != nil {
		return db.ResidentDB{}, fmt.Errorf("formulaire invalide : %w", err)
	}
	p := db.ResidentDB{
		Appartement: strings.ToUpper(strings.TrimSpace(r.FormValue("appartement"))),
		Nom:         strings.Join(strings.Fields(r.FormValue("nom")), " "),
		Qualite:     db.ResidentQualite(r.FormValue("qualite")),
		Detail:      strings.TrimSpace(r.FormValue("detail")),
		Telephone:   normaliserTelephones(r.FormValue("telephone")),
		Email:       strings.Join(strings.FieldsFunc(r.FormValue("email"), func(c rune) bool { return c == ',' || c == ';' || c == ' ' }), ", "),
		Note:        strings.TrimSpace(r.FormValue("note")),
	}
	if !appartementRe.MatchString(p.Appartement) {
		return p, fmt.Errorf("appartement inconnu : %q (attendu : C01, D12…)", p.Appartement)
	}
	if p.Nom == "" {
		return p, fmt.Errorf("le nom est obligatoire")
	}
	if !p.Qualite.Valid() {
		return p, fmt.Errorf("qualité inconnue : %q", p.Qualite)
	}
	return p, nil
}
