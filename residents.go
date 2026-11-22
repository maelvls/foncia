package main

import (
	"html/template"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/maelvls/foncia/db"
)

// The people of the building come from the contacts of a phone. The convention
// is in the name of the contact: the apartment between parentheses, with a word
// in front when the person doesn't simply live there.
//
//	Camille MARTIN (C01)          lives in C01
//	Alex DURAND (prop C01)        owns C01 without living there
//	Sacha PETIT (ex loc C01)      used to rent C01
//	Dominique (compagnon C01)     lives in C01, "compagnon"
//	Claude ROUX (vendeur C01)     sold C01
//	Jo (plombier C01)             anything else: "autre", "plombier"
//
// An export of the contacts (a vCard file, from the iPhone or from Contacts.app)
// holds everybody the phone knows: only the contacts that follow the convention
// are kept, and nothing else of the file is stored.

// -----------------------------------------------------------------------------
// vCard
// -----------------------------------------------------------------------------

// contactVCard is what is read of one card.
type contactVCard struct {
	Prenom, Nom string // The two first parts of N.
	NomComplet  string // FN.
	Telephones  []string
	Emails      []string
}

var vcardRe = regexp.MustCompile(`(?s)BEGIN:VCARD.*?END:VCARD`)

// lireVCards reads the cards of a vCard 3.0 or 4.0 file, as the iPhone and
// Contacts.app write them. It never fails: what isn't a card is skipped.
func lireVCards(raw []byte) []contactVCard {
	text := strings.TrimPrefix(string(raw), "\xEF\xBB\xBF")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	var out []contactVCard
	for _, bloc := range vcardRe.FindAllString(text, -1) {
		var c contactVCard
		for _, ligne := range deplierVCard(strings.Split(bloc, "\n")) {
			cle, valeur, ok := strings.Cut(ligne, ":")
			if !ok {
				continue
			}
			switch proprieteVCard(cle) {
			case "N":
				// N:Family;Given;Additional;Prefix;Suffix
				parts := couperVCard(valeur)
				c.Nom = parts[0]
				if len(parts) > 1 {
					c.Prenom = parts[1]
				}
			case "FN":
				c.NomComplet = strings.Join(couperVCard(valeur), ";")
			case "TEL":
				// vCard 4.0 writes "TEL;VALUE=uri:tel:+33-6-12-34-56-78".
				if v := strings.TrimPrefix(strings.TrimSpace(valeur), "tel:"); v != "" {
					c.Telephones = append(c.Telephones, v)
				}
			case "EMAIL":
				if v := strings.Join(couperVCard(valeur), ";"); v != "" {
					c.Emails = append(c.Emails, v)
				}
			}
		}
		out = append(out, c)
	}
	return out
}

// deplierVCard joins the folded lines: a line that starts with a space or a tab
// continues the previous one.
func deplierVCard(lignes []string) []string {
	var out []string
	for _, l := range lignes {
		if len(out) > 0 && (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")) {
			out[len(out)-1] += l[1:]
			continue
		}
		out = append(out, l)
	}
	return out
}

// proprieteVCard is the name of a property without its group and parameters:
// "item1.TEL;type=CELL;type=pref" is "TEL".
func proprieteVCard(cle string) string {
	nom, _, _ := strings.Cut(cle, ";")
	if i := strings.LastIndexByte(nom, '.'); i >= 0 {
		nom = nom[i+1:]
	}
	return strings.ToUpper(strings.TrimSpace(nom))
}

// couperVCard splits a value on its semicolons and undoes the escaping: "\;"
// and "\," are a plain semicolon and comma, "\n" a line break (a space here).
// There is always at least one part.
func couperVCard(valeur string) []string {
	var parts []string
	var b strings.Builder
	for i := 0; i < len(valeur); i++ {
		switch ch := valeur[i]; {
		case ch == '\\' && i+1 < len(valeur):
			i++
			if valeur[i] == 'n' || valeur[i] == 'N' {
				b.WriteByte(' ')
			} else {
				b.WriteByte(valeur[i])
			}
		case ch == ';':
			parts = append(parts, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteByte(ch)
		}
	}
	return append(parts, strings.TrimSpace(b.String()))
}

// -----------------------------------------------------------------------------
// The convention
// -----------------------------------------------------------------------------

var (
	parenthesesRe = regexp.MustCompile(`\(([^()]*)\)`)
	// What is between the parentheses: maybe a few words, then the apartment.
	mentionRe     = regexp.MustCompile(`(?i)^(?:(.*\S)\s+)?([CD][0-9]{2})$`)
	appartementRe = regexp.MustCompile(`^[CD][0-9]{2}$`)
)

// mentionAppartement finds the "(C01)" or "(ex loc C01)" of a name and gives
// the apartment, the words in front of it, and the name without the mention.
// Other parentheses, "(Dudu)", are part of the name.
func mentionAppartement(champ string) (appartement, mot, reste string, ok bool) {
	for _, loc := range parenthesesRe.FindAllStringSubmatchIndex(champ, -1) {
		m := mentionRe.FindStringSubmatch(strings.TrimSpace(champ[loc[2]:loc[3]]))
		if m == nil {
			continue
		}
		reste = strings.Join(strings.Fields(champ[:loc[0]]+" "+champ[loc[1]:]), " ")
		return strings.ToUpper(m[2]), strings.Join(strings.Fields(m[1]), " "), reste, true
	}
	return "", "", strings.Join(strings.Fields(champ), " "), false
}

// qualiteDe reads the words in front of the apartment.
func qualiteDe(mot string) (db.ResidentQualite, string) {
	m := foldText(mot)
	switch {
	case m == "":
		return db.ResidentHabite, ""
	case m == "loc" || m == "locataire":
		return db.ResidentHabite, "locataire"
	case m == "prop" || m == "proprio" || m == "proprietaire":
		return db.ResidentProprietaire, ""
	case m == "ex loc" || m == "ex locataire" || m == "ancien loc" || m == "ancien locataire":
		return db.ResidentAncien, "ancien locataire"
	case m == "ex prop" || m == "ex proprio" || m == "ex proprietaire" || m == "ancien proprietaire":
		return db.ResidentAncien, "ancien propriétaire"
	case m == "ex" || strings.HasPrefix(m, "ex ") || strings.HasPrefix(m, "ancien") || m == "vendeur" || m == "vendeuse":
		return db.ResidentAncien, mot
	}
	switch m {
	case "compagnon", "compagne", "conjoint", "conjointe", "mari", "femme", "epoux", "epouse",
		"fils", "fille", "enfant", "pere", "mere", "parent", "coloc", "colocataire":
		return db.ResidentHabite, mot
	}
	return db.ResidentAutre, mot
}

// residentDeContact makes a resident of a contact that follows the convention.
// The mention is looked for in the family name first, then in the given name,
// then in the full name.
func residentDeContact(c contactVCard) (db.ResidentDB, bool) {
	var appartement, mot string
	var trouve bool
	// The first mention found is the one that counts; a mention repeated in
	// another field is taken out of the name all the same.
	nettoyer := func(champ string) string {
		a, m, reste, ok := mentionAppartement(champ)
		if ok && !trouve {
			appartement, mot, trouve = a, m, true
		}
		return reste
	}
	nom := nettoyer(c.Nom)
	prenom := nettoyer(c.Prenom)
	complet := nettoyer(c.NomComplet)
	if !trouve {
		return db.ResidentDB{}, false
	}

	r := db.ResidentDB{Appartement: appartement, Origine: db.ResidentDesContacts}
	r.Qualite, r.Detail = qualiteDe(mot)
	r.Nom = strings.TrimSpace(prenom + " " + nom)
	if r.Nom == "" {
		// A company, or a card that only has FN.
		r.Nom = complet
	}

	var tels []string
	for _, t := range c.Telephones {
		if t = normaliserTelephone(t); t != "" && !slices.Contains(tels, t) {
			tels = append(tels, t)
		}
	}
	r.Telephone = strings.Join(tels, ", ")
	var emails []string
	for _, e := range c.Emails {
		if e = strings.TrimSpace(e); e != "" && !slices.Contains(emails, e) {
			emails = append(emails, e)
		}
	}
	r.Email = strings.Join(emails, ", ")
	return r, true
}

// -----------------------------------------------------------------------------
// Phone numbers
// -----------------------------------------------------------------------------

var telephoneRe = regexp.MustCompile(`^[+0-9 .()\-\x{00A0}\x{202F}]+$`)

// normaliserTelephone writes a French number as "06 12 34 56 78", whichever
// way it was typed ("+33 6 12 34 56 78", "06.12.34.56.78"), and a foreign one
// as "+4479…". What doesn't look like a phone number is left as typed.
func normaliserTelephone(s string) string {
	s = strings.TrimSpace(s)
	if !telephoneRe.MatchString(s) {
		return s
	}
	var b strings.Builder
	for _, ch := range s {
		if (ch >= '0' && ch <= '9') || (ch == '+' && b.Len() == 0) {
			b.WriteRune(ch)
		}
	}
	d := b.String()
	// "+33 (0)6 12 34 56 78" is written with both prefixes.
	for _, indicatif := range []string{"+33", "0033"} {
		if rest, ok := strings.CutPrefix(d, indicatif); ok {
			d = "0" + strings.TrimPrefix(rest, "0")
			break
		}
	}
	if len(d) == 10 && d[0] == '0' {
		return d[0:2] + " " + d[2:4] + " " + d[4:6] + " " + d[6:8] + " " + d[8:10]
	}
	if d == "" || d == "+" {
		return s
	}
	return d
}

// normaliserTelephones does the same to a list typed in one field, separated
// by commas or slashes.
func normaliserTelephones(s string) string {
	var out []string
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '/' || r == ';' }) {
		if t = normaliserTelephone(t); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return strings.Join(out, ", ")
}

// telephoneInternational gives "+33612345678" for "06 12 34 56 78", and ""
// when the number has no such form (too short, with letters).
func telephoneInternational(t string) string {
	t = normaliserTelephone(t)
	var d strings.Builder
	for _, ch := range t {
		if ch >= '0' && ch <= '9' {
			d.WriteRune(ch)
		}
	}
	chiffres := d.String()
	switch {
	case strings.HasPrefix(t, "+") && len(chiffres) >= 8 && len(chiffres) == len(t)-1:
		return "+" + chiffres
	case strings.HasPrefix(t, "00") && len(chiffres) >= 10 && len(chiffres) == len(t):
		return "+" + chiffres[2:]
	case len(chiffres) == 10 && chiffres[0] == '0' && len(t) == 14:
		return "+33" + chiffres[1:]
	}
	return ""
}

// lienTelephone is the href that calls the number. html/template only lets
// http, https and mailto through, hence the template.URL: the value is made of
// digits only, or is empty.
func lienTelephone(t string) template.URL {
	if i := telephoneInternational(t); i != "" {
		return template.URL("tel:" + i)
	}
	return ""
}

// lienWhatsApp is the href that opens the WhatsApp conversation, for the
// numbers that can have one: French mobiles and foreign numbers.
func lienWhatsApp(t string) template.URL {
	i := telephoneInternational(t)
	if i == "" || (strings.HasPrefix(i, "+33") && !strings.HasPrefix(i, "+336") && !strings.HasPrefix(i, "+337")) {
		return ""
	}
	return template.URL("https://wa.me/" + i[1:])
}

// -----------------------------------------------------------------------------
// The import
// -----------------------------------------------------------------------------

// importResidents is what an import of the contacts changes, before it is
// applied (see db.ApplyResidents) and to tell the person what happened.
type importResidents struct {
	Lus       int // Cards in the file.
	Retenus   int // Those that follow the convention, without the duplicates.
	Ajouts    []db.ResidentDB
	MisAJour  []db.ResidentDB
	Inchanges int
	// In the table because of an earlier import, and no longer in the
	// contacts: removed from the phone, or the mention was taken out.
	Absents []db.ResidentDB
	// Contacts that say the same person twice in the same apartment.
	Doublons []db.ResidentDB
}

// cleResident tells two rows are the same person of the same apartment: the
// words of the name, without accents nor case, in any order.
func cleResident(r db.ResidentDB) string {
	mots := strings.Fields(foldText(r.Nom))
	sort.Strings(mots)
	return r.Appartement + "|" + strings.Join(mots, " ")
}

// rangQualite orders two contacts that say the same person twice: the one
// that says the person is there wins over the one that says they left.
func rangQualite(q db.ResidentQualite) int {
	switch q {
	case db.ResidentHabite:
		return 3
	case db.ResidentProprietaire:
		return 2
	case db.ResidentAutre:
		return 1
	}
	return 0
}

// residentsDesContacts keeps the cards that follow the convention.
func residentsDesContacts(cartes []contactVCard) (retenus, doublons []db.ResidentDB) {
	index := make(map[string]int)
	for _, c := range cartes {
		r, ok := residentDeContact(c)
		if !ok {
			continue
		}
		cle := cleResident(r)
		i, vu := index[cle]
		if !vu {
			index[cle] = len(retenus)
			retenus = append(retenus, r)
			continue
		}
		garde, autre := retenus[i], r
		if rangQualite(autre.Qualite) > rangQualite(garde.Qualite) {
			garde, autre = autre, garde
		}
		// The other card may know a number that this one doesn't.
		if garde.Telephone == "" {
			garde.Telephone = autre.Telephone
		}
		if garde.Email == "" {
			garde.Email = autre.Email
		}
		retenus[i] = garde
		doublons = append(doublons, autre)
	}
	return retenus, doublons
}

// planifierImport compares the contacts with the table.
//
// A contact is the row of the same apartment and name; failing that, the row
// of an earlier import with the same phone number (the contact was renamed, or
// moved to another apartment); failing that, somebody new.
//
// The contacts win where they say something: the apartment, the name, the
// qualité, and the phone and e-mail when they have one. What was typed on the
// site and the contacts don't know stays: the note always, the phone and
// e-mail of a contact that has none, the detail ("locataire") of somebody the
// contacts only say lives there.
func planifierImport(existants []db.ResidentDB, cartes []contactVCard) importResidents {
	contacts, doublons := residentsDesContacts(cartes)
	plan := importResidents{Lus: len(cartes), Retenus: len(contacts), Doublons: doublons}

	parCle := make(map[string]int, len(existants))
	for i, e := range existants {
		if _, vu := parCle[cleResident(e)]; !vu {
			parCle[cleResident(e)] = i
		}
	}
	pris := make([]bool, len(existants))
	paire := make([]int, len(contacts)) // The existing row of each contact, or -1.
	for i, c := range contacts {
		paire[i] = -1
		if j, ok := parCle[cleResident(c)]; ok && !pris[j] {
			paire[i], pris[j] = j, true
		}
	}
	for i, c := range contacts {
		if paire[i] >= 0 || c.Telephone == "" {
			continue
		}
		for j, e := range existants {
			if !pris[j] && e.Origine == db.ResidentDesContacts && memeTelephone(c, e) {
				paire[i], pris[j] = j, true
				break
			}
		}
	}

	for i, c := range contacts {
		if paire[i] < 0 {
			plan.Ajouts = append(plan.Ajouts, c)
			continue
		}
		e := existants[paire[i]]
		maj := e
		maj.Appartement, maj.Nom, maj.Origine = c.Appartement, c.Nom, db.ResidentDesContacts
		if c.Qualite != e.Qualite {
			maj.Qualite, maj.Detail = c.Qualite, c.Detail
		} else if c.Detail != "" {
			maj.Detail = c.Detail
		}
		if c.Telephone != "" {
			maj.Telephone = c.Telephone
		}
		if c.Email != "" {
			maj.Email = c.Email
		}
		if maj == e {
			plan.Inchanges++
		} else {
			plan.MisAJour = append(plan.MisAJour, maj)
		}
	}
	for j, e := range existants {
		if !pris[j] && e.Origine == db.ResidentDesContacts {
			plan.Absents = append(plan.Absents, e)
		}
	}
	return plan
}

// memeTelephone tells whether two rows share a phone number.
func memeTelephone(a, b db.ResidentDB) bool {
	for _, ta := range a.Telephones() {
		ia := telephoneInternational(ta)
		for _, tb := range b.Telephones() {
			if ta == tb || (ia != "" && ia == telephoneInternational(tb)) {
				return true
			}
		}
	}
	return false
}
