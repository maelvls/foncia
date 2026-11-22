package main

import (
	"strings"
	"testing"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An export of the contacts as Contacts.app writes it: CRLF, grouped
// properties, folded lines, escaped commas, and people who have nothing to do
// with the building. Every name and number is made up.
const vcardExport = "\xEF\xBB\xBFBEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"PRODID:-//Apple Inc.//macOS 15.0//EN\r\n" +
	"N:MARTIN (C01);Camille;;;\r\n" +
	"FN:Camille MARTIN (C01)\r\n" +
	"item1.EMAIL;type=INTERNET;type=pref:camille@example.com\r\n" +
	"TEL;type=CELL;type=VOICE;type=pref:+33 6 12 34 56 78\r\n" +
	"TEL;type=HOME;type=VOICE:05 61 00 00 01\r\n" +
	"END:VCARD\r\n" +
	"BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"N:Durand (prop C01);Alex;;;\r\n" +
	"FN:Alex Durand (prop C01)\r\n" +
	"TEL;type=CELL:+33712345678\r\n" +
	"END:VCARD\r\n" +
	"BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"N:(ex loc D12);Sacha;;;\r\n" +
	"FN:Sacha (ex loc D12)\r\n" +
	"TEL:0612000003\r\n" +
	"END:VCARD\r\n" +
	"BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"N:;Dominique (compagnon C01);;;\r\n" +
	"FN:Dominique (compagnon C01)\r\n" +
	"END:VCARD\r\n" +
	"BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"N:Lefèvre\\, fils (Dudu) (d03);Éloïse-Marie de la Très Longue Lignée qui Dépasse la Largeur\r\n" +
	"  d'une Ligne;;;\r\n" +
	"FN:Éloïse-Marie Lefèvre (d03)\r\n" +
	"TEL:+44 7911 123456\r\n" +
	"END:VCARD\r\n" +
	"BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"N:Roux (kiné D02);Claude;;;\r\n" +
	"FN:Claude Roux (kiné D02)\r\n" +
	"END:VCARD\r\n" +
	"BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"N:Plombier;Jean;;;\r\n" +
	"FN:Jean Plombier\r\n" +
	"ORG:Plomberie (Toulouse);\r\n" +
	"TEL:0561000099\r\n" +
	"END:VCARD\r\n"

func TestResidentsDesContacts(t *testing.T) {
	cartes := lireVCards([]byte(vcardExport))
	require.Len(t, cartes, 7)

	retenus, doublons := residentsDesContacts(cartes, db.ResidentDesContacts)
	assert.Empty(t, doublons)

	type ligne struct {
		Appartement, Nom string
		Qualite          db.ResidentQualite
		Detail           string
		Telephone, Email string
	}
	var got []ligne
	for _, r := range retenus {
		assert.Equal(t, db.ResidentDesContacts, r.Origine)
		got = append(got, ligne{r.Appartement, r.Nom, r.Qualite, r.Detail, r.Telephone, r.Email})
	}
	assert.Equal(t, []ligne{
		{"C01", "Camille MARTIN", db.ResidentHabite, "", "06 12 34 56 78, 05 61 00 00 01", "camille@example.com"},
		{"C01", "Alex Durand", db.ResidentProprietaire, "", "07 12 34 56 78", ""},
		{"D12", "Sacha", db.ResidentAncien, "ancien locataire", "06 12 00 00 03", ""},
		{"C01", "Dominique", db.ResidentHabite, "compagnon", "", ""},
		// A folded line, an escaped comma, parentheses that aren't an
		// apartment, and an apartment in lower case.
		{"D03", "Éloïse-Marie de la Très Longue Lignée qui Dépasse la Largeur d'une Ligne Lefèvre, fils (Dudu)", db.ResidentHabite, "", "+447911123456", ""},
		{"D02", "Claude Roux", db.ResidentAutre, "kiné", "", ""},
	}, got)
}

func TestMentionAppartement(t *testing.T) {
	for champ, want := range map[string][3]string{
		"MARTIN (C01)":          {"C01", "", "MARTIN"},
		"(C01)":                 {"C01", "", ""},
		"MARTIN ( ex  loc C01)": {"C01", "ex loc", "MARTIN"},
		"(prop D13) Durand":     {"D13", "prop", "Durand"},
		"Durand (Dudu) (c07)":   {"C07", "", "Durand (Dudu)"},
	} {
		appartement, mot, reste, ok := mentionAppartement(champ)
		assert.True(t, ok, champ)
		assert.Equal(t, want, [3]string{appartement, mot, reste}, champ)
	}
	// Not an apartment: another building, a word that only ends like one, no
	// parentheses at all.
	for _, champ := range []string{"MARTIN (A01)", "MARTIN (ABCD02)", "MARTIN C01", "MARTIN (C1)", "MARTIN (C011)", "MARTIN"} {
		_, _, reste, ok := mentionAppartement(champ)
		assert.False(t, ok, champ)
		assert.Equal(t, champ, reste)
	}
}

func TestQualiteDe(t *testing.T) {
	type q struct {
		Qualite db.ResidentQualite
		Detail  string
	}
	for mot, want := range map[string]q{
		"":              {db.ResidentHabite, ""},
		"loc":           {db.ResidentHabite, "locataire"},
		"compagnon":     {db.ResidentHabite, "compagnon"},
		"prop":          {db.ResidentProprietaire, ""},
		"Propriétaire":  {db.ResidentProprietaire, ""},
		"ex loc":        {db.ResidentAncien, "ancien locataire"},
		"Ex Loc":        {db.ResidentAncien, "ancien locataire"},
		"ex prop":       {db.ResidentAncien, "ancien propriétaire"},
		"ex compagnon":  {db.ResidentAncien, "ex compagnon"},
		"vendeur":       {db.ResidentAncien, "vendeur"},
		"kiné":          {db.ResidentAutre, "kiné"},
		"agence Dupont": {db.ResidentAutre, "agence Dupont"},
	} {
		qualite, detail := qualiteDe(mot)
		assert.Equal(t, want, q{qualite, detail}, mot)
	}
}

func TestTelephones(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"+33 6 12 34 56 78":      "06 12 34 56 78",
		"+33612345678":           "06 12 34 56 78",
		"0033612345678":          "06 12 34 56 78",
		"+33 (0)6 12 34 56 78":   "06 12 34 56 78",
		"06.12.34.56.78":         "06 12 34 56 78",
		"06-12-34-56-78":         "06 12 34 56 78",
		"0612345678":             "06 12 34 56 78",
		"+44 7911 123456":        "+447911123456",
		"06 12 34 56 78 le soir": "06 12 34 56 78 le soir", // Not only a number: as typed.
		"3631":                   "3631",
	} {
		assert.Equal(t, want, normaliserTelephone(in), in)
	}

	// Non-breaking spaces, as iOS writes them.
	assert.Equal(t, "06 12 34 56 78", normaliserTelephone(strings.ReplaceAll("06 12 34 56 78", " ", string(rune(0xA0)))))
	assert.Equal(t, "06 12 34 56 78", normaliserTelephone(strings.ReplaceAll("+33 6 12 34 56 78", " ", string(rune(0x202F)))))

	assert.Equal(t, "06 12 34 56 78, 05 61 00 00 01", normaliserTelephones("0612345678 / +33561000001, 06 12 34 56 78"))

	for in, want := range map[string]string{
		"06 12 34 56 78":         "+33612345678",
		"+447911123456":          "+447911123456",
		"3631":                   "",
		"06 12 34 56 78 le soir": "",
		"":                       "",
	} {
		assert.Equal(t, want, telephoneInternational(in), in)
	}

	assert.Equal(t, "tel:+33612345678", string(lienTelephone("06 12 34 56 78")))
	assert.Equal(t, "", string(lienTelephone("voir avec le gardien")))
	assert.Equal(t, "https://wa.me/33612345678", string(lienWhatsApp("06 12 34 56 78")))
	assert.Equal(t, "https://wa.me/447911123456", string(lienWhatsApp("+447911123456")))
	assert.Equal(t, "", string(lienWhatsApp("05 61 00 00 01")), "a landline has no WhatsApp")
}

// carte builds the card of a contact, the way the phone names it.
func carte(nom, prenom string, tels ...string) contactVCard {
	return contactVCard{Nom: nom, Prenom: prenom, Telephones: tels}
}

// planExport plans the import of an export of the contacts.
func planExport(existants []db.ResidentDB, cartes []contactVCard) importResidents {
	return planifierImport(existants, cartes, db.ResidentDesContacts)
}

// wa builds a contact as the whatsapp service gives it: the whole name of the
// address book, and the number of the WhatsApp account.
func wa(nomComplet, numero string) contactVCard {
	return contactVCard{NomComplet: nomComplet, Telephones: []string{"+" + numero}}
}

func TestPlanifierImportWhatsApp(t *testing.T) {
	t.Run("an empty table takes the neighbours of WhatsApp", func(t *testing.T) {
		plan := planifierImport(nil, []contactVCard{
			wa("Camille MARTIN (C01)", "33612345678"),
			wa("Alex Durand (prop C01)", "33712345678"),
		}, db.ResidentDeWhatsApp)
		require.Len(t, plan.Ajouts, 2)
		assert.Equal(t, db.ResidentDB{
			Appartement: "C01", Nom: "Camille MARTIN", Qualite: db.ResidentHabite,
			Telephone: "06 12 34 56 78", Origine: db.ResidentDeWhatsApp,
		}, plan.Ajouts[0])
		assert.Equal(t, db.ResidentProprietaire, plan.Ajouts[1].Qualite)
	})

	// The table after an export of the contacts and a row typed by hand.
	existants := []db.ResidentDB{
		{ID: "1", Appartement: "C01", Nom: "Camille MARTIN", Qualite: db.ResidentHabite, Detail: "locataire",
			Telephone: "05 61 00 00 01, 06 12 34 56 78", Email: "camille@example.com", Note: "a les clés du local", Origine: db.ResidentDesContacts},
		{ID: "2", Appartement: "C02", Nom: "Alex Durand", Qualite: db.ResidentHabite,
			Telephone: "05 61 00 00 02", Origine: db.ResidentDuSite},
		{ID: "3", Appartement: "D01", Nom: "Sacha Petit", Qualite: db.ResidentHabite, Origine: db.ResidentDesContacts},
	}

	t.Run("WhatsApp takes the rows over and keeps what it doesn't know", func(t *testing.T) {
		plan := planifierImport(existants, []contactVCard{
			wa("Camille MARTIN (C01)", "33612345678"),
			wa("Alex Durand (ex loc C02)", "33700000002"),
		}, db.ResidentDeWhatsApp)
		assert.Empty(t, plan.Ajouts)
		parID := make(map[string]db.ResidentDB)
		for _, m := range plan.MisAJour {
			parID[m.ID] = m
		}
		require.Len(t, parID, 2)

		// Its number was already there among the others: nothing but the
		// origin changes.
		camille := existants[0]
		camille.Origine = db.ResidentDeWhatsApp
		assert.Equal(t, camille, parID["1"])

		// A number WhatsApp is alone to know goes in front of the others.
		alex := existants[1]
		alex.Origine, alex.Qualite, alex.Detail = db.ResidentDeWhatsApp, db.ResidentAncien, "ancien locataire"
		alex.Telephone = "07 00 00 00 02, 05 61 00 00 02"
		assert.Equal(t, alex, parID["2"])

		// Sacha has no WhatsApp: the export keeps vouching for them.
		assert.Empty(t, plan.Absents)
	})

	t.Run("then reading WhatsApp again changes nothing", func(t *testing.T) {
		cartes := []contactVCard{wa("Camille MARTIN (C01)", "33612345678"), wa("Alex Durand (ex loc C02)", "33700000002")}
		premier := planifierImport(existants, cartes, db.ResidentDeWhatsApp)
		apres := append([]db.ResidentDB{existants[2]}, premier.MisAJour...)
		plan := planifierImport(apres, cartes, db.ResidentDeWhatsApp)
		assert.Equal(t, 2, plan.Inchanges)
		assert.Empty(t, plan.MisAJour)
		assert.Empty(t, plan.Ajouts)
	})

	suivis := []db.ResidentDB{
		{ID: "1", Appartement: "C01", Nom: "Camille MARTIN", Qualite: db.ResidentAncien, Detail: "ancien locataire",
			Telephone: "06 12 34 56 78", Origine: db.ResidentDeWhatsApp},
		{ID: "2", Appartement: "D01", Nom: "Sacha Petit", Qualite: db.ResidentHabite, Origine: db.ResidentDesContacts},
		{ID: "3", Appartement: "D02", Nom: "Claude Roux", Qualite: db.ResidentHabite,
			Telephone: "06 00 00 00 04", Origine: db.ResidentDeWhatsApp},
	}

	t.Run("an export adds to what WhatsApp follows, without contradicting it", func(t *testing.T) {
		// An export older than the last reading of WhatsApp: Camille still
		// lived there, under another spelling.
		avecEmail := carte("martin (C01)", "CAMILLE", "0561000001", "0612345678")
		avecEmail.Emails = []string{"camille@example.com"}
		plan := planExport(suivis, []contactVCard{avecEmail, carte("Petit (D01)", "Sacha")})
		assert.Equal(t, 1, plan.Inchanges)
		require.Len(t, plan.MisAJour, 1)

		camille := suivis[0]
		camille.Telephone, camille.Email = "05 61 00 00 01, 06 12 34 56 78", "camille@example.com"
		assert.Equal(t, camille, plan.MisAJour[0], "the numbers and the e-mail come, the name and the qualité stay WhatsApp's")

		// Claude isn't in the export, but isn't the export's to report.
		assert.Empty(t, plan.Absents)
	})

	t.Run("who left WhatsApp is reported, not who only an export knows", func(t *testing.T) {
		plan := planifierImport(suivis, []contactVCard{wa("Camille MARTIN (ex loc C01)", "33612345678")}, db.ResidentDeWhatsApp)
		assert.Equal(t, 1, plan.Inchanges)
		require.Len(t, plan.Absents, 1)
		assert.Equal(t, "3", plan.Absents[0].ID)
	})

	t.Run("a card with two numbers comes twice from WhatsApp, and is one person", func(t *testing.T) {
		plan := planifierImport(nil, []contactVCard{
			wa("Camille MARTIN (C01)", "33612345678"),
			wa("Camille MARTIN (C01)", "33700000001"),
		}, db.ResidentDeWhatsApp)
		require.Len(t, plan.Ajouts, 1)
		assert.Equal(t, "06 12 34 56 78, 07 00 00 00 01", plan.Ajouts[0].Telephone)
		assert.Empty(t, plan.Doublons, "nothing to clean up in the contacts")

		// Reading again finds both numbers there, whichever comes first.
		plan.Ajouts[0].ID = "1"
		encore := planifierImport(plan.Ajouts, []contactVCard{
			wa("Camille MARTIN (C01)", "33700000001"),
			wa("Camille MARTIN (C01)", "33612345678"),
		}, db.ResidentDeWhatsApp)
		assert.Equal(t, 1, encore.Inchanges)
		assert.Empty(t, encore.MisAJour)

		// A second account that appears later is added to the first.
		plan.Ajouts[0].Telephone = "06 12 34 56 78"
		plus := planifierImport(plan.Ajouts, []contactVCard{
			wa("Camille MARTIN (C01)", "33612345678"),
			wa("Camille MARTIN (C01)", "33700000001"),
		}, db.ResidentDeWhatsApp)
		require.Len(t, plus.MisAJour, 1)
		assert.Equal(t, "06 12 34 56 78, 07 00 00 00 01", plus.MisAJour[0].Telephone)
	})

	t.Run("a contact renamed on the phone is followed by its number", func(t *testing.T) {
		plan := planifierImport(suivis, []contactVCard{
			wa("Camille MARTIN (ex loc C01)", "33612345678"),
			wa("Claude ROUX-BLANC (D05)", "33600000004"),
		}, db.ResidentDeWhatsApp)
		assert.Empty(t, plan.Ajouts)
		assert.Empty(t, plan.Absents)
		require.Len(t, plan.MisAJour, 1)
		claude := suivis[2]
		claude.Appartement, claude.Nom = "D05", "Claude ROUX-BLANC"
		assert.Equal(t, claude, plan.MisAJour[0])
	})
}

func TestPlanifierImport(t *testing.T) {
	t.Run("an empty table takes everybody", func(t *testing.T) {
		plan := planExport(nil, []contactVCard{
			carte("MARTIN (C01)", "Camille", "0612345678"),
			carte("Plombier", "Jean", "0561000099"),
		})
		assert.Equal(t, 2, plan.Lus)
		assert.Equal(t, 1, plan.Retenus)
		require.Len(t, plan.Ajouts, 1)
		assert.Equal(t, "Camille MARTIN", plan.Ajouts[0].Nom)
		assert.Empty(t, plan.MisAJour)
		assert.Empty(t, plan.Absents)
	})

	existants := []db.ResidentDB{
		{ID: "1", Appartement: "C01", Nom: "Camille MARTIN", Qualite: db.ResidentHabite, Detail: "locataire",
			Telephone: "06 12 34 56 78", Email: "camille@example.com", Note: "a les clés du local", Origine: db.ResidentDesContacts},
		{ID: "2", Appartement: "C02", Nom: "Alex Durand", Qualite: db.ResidentHabite,
			Telephone: "07 00 00 00 02", Origine: db.ResidentDesContacts},
		{ID: "3", Appartement: "D01", Nom: "Sacha Petit", Qualite: db.ResidentHabite,
			Telephone: "06 00 00 00 03", Origine: db.ResidentDuSite},
		{ID: "4", Appartement: "D02", Nom: "Claude Roux", Qualite: db.ResidentHabite,
			Telephone: "06 00 00 00 04", Origine: db.ResidentDesContacts},
	}

	t.Run("the same contacts change nothing", func(t *testing.T) {
		plan := planExport(existants[:2], []contactVCard{
			carte("MARTIN (C01)", "Camille", "+33612345678"),
			carte("Durand (C02)", "Alex", "0700000002"),
		})
		assert.Equal(t, 2, plan.Inchanges)
		assert.Empty(t, plan.Ajouts)
		assert.Empty(t, plan.MisAJour)
		assert.Empty(t, plan.Absents)
	})

	t.Run("a name written another way is the same person", func(t *testing.T) {
		// Another case, no accent, the words the other way round.
		plan := planExport([]db.ResidentDB{
			{ID: "1", Appartement: "C01", Nom: "Éloïse Lefèvre", Qualite: db.ResidentHabite, Origine: db.ResidentDesContacts},
		}, []contactVCard{carte("eloise (C01)", "LEFEVRE")})
		assert.Empty(t, plan.Ajouts)
		// The name is taken as the contacts write it.
		require.Len(t, plan.MisAJour, 1)
		assert.Equal(t, "1", plan.MisAJour[0].ID)
		assert.Equal(t, "LEFEVRE eloise", plan.MisAJour[0].Nom)
	})

	t.Run("the contacts win where they say something, the site keeps the rest", func(t *testing.T) {
		plan := planExport(existants, []contactVCard{
			// No e-mail and no detail in the contacts: those of the site stay.
			// A new number: it replaces the old one.
			carte("MARTIN (C01)", "Camille", "0699999999"),
			// Left: the qualité and its detail follow the contacts.
			carte("Durand (ex loc C02)", "Alex", "0700000002"),
			// Typed on the site, and now in the contacts too: one person.
			carte("Petit (D01)", "Sacha"),
			// Renamed and moved: recognised by the phone number.
			carte("ROUX-BLANC (D05)", "Claude", "+33600000004"),
			carte("Nouveau (D13)", "Charlie", "0600000005"),
		})
		require.Len(t, plan.Ajouts, 1)
		assert.Equal(t, "Charlie Nouveau", plan.Ajouts[0].Nom)
		assert.Empty(t, plan.Absents)
		assert.Zero(t, plan.Inchanges)

		parID := make(map[string]db.ResidentDB)
		for _, m := range plan.MisAJour {
			parID[m.ID] = m
		}
		require.Len(t, parID, 4)

		camille := existants[0]
		camille.Telephone = "06 99 99 99 99"
		assert.Equal(t, camille, parID["1"])

		alex := existants[1]
		alex.Qualite, alex.Detail = db.ResidentAncien, "ancien locataire"
		assert.Equal(t, alex, parID["2"])

		sacha := existants[2]
		sacha.Origine = db.ResidentDesContacts // The phone typed on the site stays.
		assert.Equal(t, sacha, parID["3"])

		claude := existants[3]
		claude.Appartement, claude.Nom = "D05", "Claude ROUX-BLANC"
		assert.Equal(t, claude, parID["4"])
	})

	t.Run("who is no longer in the contacts is reported, unless typed on the site", func(t *testing.T) {
		plan := planExport(existants, []contactVCard{carte("MARTIN (C01)", "Camille")})
		assert.Equal(t, 1, plan.Inchanges)
		var absents []string
		for _, a := range plan.Absents {
			absents = append(absents, a.ID)
		}
		assert.Equal(t, []string{"2", "4"}, absents)
	})

	t.Run("a phone number isn't taken from somebody who is still there", func(t *testing.T) {
		// Two people of the same flat share a landline: the second isn't the
		// first one renamed.
		plan := planExport(existants[:1], []contactVCard{
			carte("MARTIN (C01)", "Camille", "0612345678"),
			carte("MARTIN (C01)", "Dominique", "0612345678"),
		})
		assert.Equal(t, 1, plan.Inchanges)
		require.Len(t, plan.Ajouts, 1)
		assert.Equal(t, "Dominique MARTIN", plan.Ajouts[0].Nom)
	})

	t.Run("the same person twice in the contacts is one row", func(t *testing.T) {
		plan := planExport(nil, []contactVCard{
			carte("Durand (ex loc D10)", "Alex", "0700000002"),
			carte("DURAND (D10)", "Alex"),
		})
		assert.Equal(t, 1, plan.Retenus)
		require.Len(t, plan.Ajouts, 1)
		// The one that says the person is still there, with the number that
		// only the other card had.
		assert.Equal(t, db.ResidentHabite, plan.Ajouts[0].Qualite)
		assert.Equal(t, "Alex DURAND", plan.Ajouts[0].Nom)
		assert.Equal(t, "07 00 00 00 02", plan.Ajouts[0].Telephone)
		require.Len(t, plan.Doublons, 1)
		assert.Equal(t, db.ResidentAncien, plan.Doublons[0].Qualite)
	})
}
