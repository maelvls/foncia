package main

import (
	"bytes"
	"database/sql"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	admin  = "mael@example.com"
	membre = "voisin@example.com"
)

// sourcesServer serves the affaires, the files, the sources and the share
// links on an empty in-memory database, with one administrator.
func sourcesServer(t *testing.T) (*httptest.Server, *sql.DB, *http.Client, copro) {
	t.Helper()
	sqlDB, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	oldFiles, oldAdmins := *filesDir, *adminUsers
	*filesDir, *adminUsers = t.TempDir(), admin
	t.Cleanup(func() { *filesDir, *adminUsers = oldFiles, oldAdmins })

	cle, err := chargerPartage(t.Context(), sqlDB)
	require.NoError(t, err)
	root := http.NewServeMux()
	sub := http.NewServeMux()
	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	c := copro{sqlDB: sqlDB, baseURL: srv.URL, partage: cle, brain: brainTrigger{path: t.TempDir() + "/brain/demande"}}
	addAffairesHandlers(sub, sqlDB, "")
	addSourcesHandlers(sub, c)
	addPublicHandlers(root, c)
	root.Handle("/", sub)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return srv, sqlDB, client, c
}

func getAs(t *testing.T, client *http.Client, user, u string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
	require.NoError(t, err)
	if user != "" {
		req.Header.Set(*authHeader, user)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func nouvelleAffaire(t *testing.T, sqlDB *sql.DB, num int, titre string) db.AffaireDB {
	t.Helper()
	a := db.AffaireDB{Numero: num, Titre: titre, Statut: db.AffaireStatutEnCours}
	id, err := db.InsertAffaire(t.Context(), sqlDB, a)
	require.NoError(t, err)
	a, err = db.GetAffaire(t.Context(), sqlDB, id)
	require.NoError(t, err)
	return a
}

func TestFichiers(t *testing.T) {
	srv, sqlDB, client, c := sourcesServer(t)
	a := nouvelleAffaire(t, sqlDB, 1, "Fuite toiture C02")

	// Upload a PDF as a co-owner who isn't an administrator.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("fichiers", "Devis étanchéité.pdf")
	require.NoError(t, err)
	_, _ = fw.Write([]byte("%PDF-1.4 un devis"))
	require.NoError(t, mw.WriteField("note", "reçu le 12/11"))
	require.NoError(t, mw.Close())
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/affaires/"+a.ID+"/fichiers", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set(*authHeader, membre)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	liens, err := db.GetLiens(t.Context(), sqlDB, a.ID)
	require.NoError(t, err)
	require.Len(t, liens, 1)
	assert.Equal(t, db.LienFichier, liens[0].Kind)
	assert.Equal(t, "Devis étanchéité.pdf", liens[0].Titre)
	f, err := db.GetFichier(t.Context(), sqlDB, liens[0].Ref)
	require.NoError(t, err)
	assert.Equal(t, "application/pdf", f.Mime)

	t.Run("every co-owner opens an attached file", func(t *testing.T) {
		status, got := getAs(t, client, membre, srv.URL+"/fichiers/"+f.SHA256+"/x.pdf")
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "%PDF-1.4 un devis", got)
	})

	t.Run("the dossier lists it with a share button", func(t *testing.T) {
		status, got := getAs(t, client, membre, srv.URL+"/affaires/"+a.ID)
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, got, "Devis étanchéité.pdf")
		assert.Contains(t, got, "/fichiers/"+f.SHA256+"/partager")
	})

	t.Run("a file of a message still to sort is for the administrators", func(t *testing.T) {
		g, err := stockerFichier(t.Context(), sqlDB, strings.NewReader("photo privée"), "IMG.jpg", "image/jpeg", db.FichierWhatsApp, "x")
		require.NoError(t, err)
		status, _ := getAs(t, client, membre, srv.URL+"/fichiers/"+g.SHA256)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = getAs(t, client, admin, srv.URL+"/fichiers/"+g.SHA256)
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("share links open without a login until they expire", func(t *testing.T) {
		lien := c.partage.lien(f, time.Now().Add(time.Hour))
		status, got := getAs(t, client, "", srv.URL+lien)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "%PDF-1.4 un devis", got)

		status, got = getAs(t, client, "", srv.URL+c.partage.lien(f, time.Now().Add(-time.Hour)))
		assert.Equal(t, http.StatusForbidden, status)
		assert.Contains(t, got, "expiré")

		forged := strings.Replace(lien, "&s=", "&s=x", 1)
		status, _ = getAs(t, client, "", srv.URL+forged)
		assert.Equal(t, http.StatusForbidden, status)

		other, err := stockerFichier(t.Context(), sqlDB, strings.NewReader("autre"), "a.txt", "", db.FichierEnvoi, "x")
		require.NoError(t, err)
		swapped := strings.Replace(lien, f.SHA256, other.SHA256, 1)
		status, _ = getAs(t, client, "", srv.URL+swapped)
		assert.Equal(t, http.StatusForbidden, status, "a signature is for one file")
	})

	t.Run("the share button gives the link in the flash", func(t *testing.T) {
		status, loc := post(t, client, membre, srv.URL+"/fichiers/"+f.SHA256+"/partager", url.Values{"retour": {"/affaires/" + a.ID + "#pieces"}})
		assert.Equal(t, http.StatusSeeOther, status)
		u, err := url.Parse(loc)
		require.NoError(t, err)
		assert.Contains(t, u.Query().Get("flash"), srv.URL+"/f/"+f.SHA256+"/")
	})

	t.Run("storing the same content twice keeps one file", func(t *testing.T) {
		g, err := stockerFichier(t.Context(), sqlDB, strings.NewReader("%PDF-1.4 un devis"), "autre nom.pdf", "", db.FichierGmail, "y")
		require.NoError(t, err)
		assert.Equal(t, f.SHA256, g.SHA256)
		assert.Equal(t, "Devis étanchéité.pdf", g.Nom)
	})

	t.Run("names can't escape the store or the header", func(t *testing.T) {
		assert.Equal(t, "passwd", nomPropre("../../etc/passwd"))
		assert.Equal(t, "ab.pdf", nomPropre("a\"b\r\n.pdf"))
		assert.Equal(t, "fichier", nomPropre(".."))
	})
}

func TestSources(t *testing.T) {
	srv, sqlDB, client, _ := sourcesServer(t)
	ctx := t.Context()
	a := nouvelleAffaire(t, sqlDB, 1, "Portail garage bloqué")
	pj, err := stockerFichier(ctx, sqlDB, strings.NewReader("%PDF devis SMF"), "devis.pdf", "application/pdf", db.FichierGmail, "smf")
	require.NoError(t, err)

	premier, err := db.InsertSource(ctx, sqlDB, db.SourceDB{
		Canal: db.CanalGmail, ExtID: "m1", Fil: "t1", Auteur: "SMF <contact@smf.fr>", Sujet: "Devis ventouse portail",
		Texte: "Veuillez trouver notre devis.", Date: time.Date(2026, 11, 2, 10, 0, 0, 0, paris),
		Fichiers: []db.SourceFichier{{FichierDB: pj, NomDansMessage: "Devis SMF.pdf"}},
	})
	require.NoError(t, err)
	reponse, err := db.InsertSource(ctx, sqlDB, db.SourceDB{Canal: db.CanalGmail, ExtID: "m2", Fil: "t1", Auteur: "Gestionnaire", Sujet: "Re: Devis ventouse portail", Texte: "Validé.", Date: time.Date(2026, 11, 3, 10, 0, 0, 0, paris)})
	require.NoError(t, err)
	_, err = db.InsertSource(ctx, sqlDB, db.SourceDB{Canal: db.CanalGmail, ExtID: "m1", Fil: "t1", Date: time.Now()})
	assert.ErrorIs(t, err, db.ErrSourceExists)

	t.Run("the messages to sort are for the administrators", func(t *testing.T) {
		status, _ := getAs(t, client, membre, srv.URL+"/sources")
		assert.Equal(t, http.StatusForbidden, status)
		status, _ = getAs(t, client, membre, srv.URL+"/sources/"+premier)
		assert.Equal(t, http.StatusNotFound, status)
		status, body := getAs(t, client, admin, srv.URL+"/sources")
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "Devis ventouse portail")
		assert.Contains(t, body, "À trier (2)")
	})

	t.Run("filing a message attaches its files and the rest of its thread", func(t *testing.T) {
		status, loc := post(t, client, admin, srv.URL+"/sources/"+premier+"/rattacher", url.Values{"affaire_id": {a.ID}, "retour": {"/sources"}})
		require.Equal(t, http.StatusSeeOther, status, loc)
		assert.Contains(t, loc, "autre")

		liens, err := db.GetLiens(ctx, sqlDB, a.ID)
		require.NoError(t, err)
		kinds := map[db.LienKind]int{}
		for _, l := range liens {
			kinds[l.Kind]++
		}
		assert.Equal(t, map[db.LienKind]int{db.LienSource: 2, db.LienFichier: 1}, kinds)
		r, err := db.GetSource(ctx, sqlDB, reponse)
		require.NoError(t, err)
		assert.Equal(t, db.SourceClassee, r.Etat)
		assert.Equal(t, "auto:fil", r.TraitePar)
	})

	t.Run("once filed, every co-owner reads it in the dossier", func(t *testing.T) {
		status, body := getAs(t, client, membre, srv.URL+"/affaires/"+a.ID)
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "Veuillez trouver notre devis.")
		assert.Contains(t, body, "Messages <small>(2)")
		assert.Less(t, strings.Index(body, "Veuillez trouver"), strings.Index(body, "Validé."), "oldest first")
		status, _ = getAs(t, client, membre, srv.URL+"/sources/"+premier)
		assert.Equal(t, http.StatusOK, status)
		status, _ = getAs(t, client, membre, srv.URL+"/fichiers/"+pj.SHA256)
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("a new answer in a filed thread is filed on arrival", func(t *testing.T) {
		ok, err := enregistrerSource(ctx, sqlDB, db.SourceDB{Canal: db.CanalGmail, ExtID: "m3", Fil: "t1", Auteur: "SMF", Texte: "Intervention mardi.", Date: time.Now()})
		require.NoError(t, err)
		assert.True(t, ok)
		got, err := db.GetSources(ctx, sqlDB, db.SourcesFilter{Canal: db.CanalGmail, Fil: "t1", Etats: []db.SourceEtat{db.SourceATrier}})
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("a message can be set aside and brought back", func(t *testing.T) {
		id, err := db.InsertSource(ctx, sqlDB, db.SourceDB{Canal: db.CanalWhatsApp, ExtID: "w1", Fil: "g", Texte: "Qui me prête la place 59 ?", Date: time.Now()})
		require.NoError(t, err)
		status, _ := post(t, client, admin, srv.URL+"/sources/"+id+"/etat", url.Values{"etat": {"ignoree"}})
		assert.Equal(t, http.StatusSeeOther, status)
		s, _ := db.GetSource(ctx, sqlDB, id)
		assert.Equal(t, db.SourceIgnoree, s.Etat)
		status, _ = post(t, client, membre, srv.URL+"/sources/"+id+"/etat", url.Values{"etat": {"a_trier"}})
		assert.Equal(t, http.StatusForbidden, status)
	})

	t.Run("a Foncia novelty becomes a link to the mission itself", func(t *testing.T) {
		require.NoError(t, db.SaveMissionsToDB(ctx, sqlDB, db.MissionDB{ID: "mis1", Number: "7000X", Kind: "Repair", Label: "SMF VENTOUSE", Status: "OPEN", StartedAt: time.Now()}))
		n, err := sourcesFoncia(ctx, sqlDB, "https://suivi", []db.MissionDB{{ID: "mis1", Number: "7000X", Kind: "Repair", Label: "SMF VENTOUSE", StartedAt: time.Now()}}, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		got, err := db.GetSources(ctx, sqlDB, db.SourcesFilter{Canal: db.CanalFoncia})
		require.NoError(t, err)
		require.Len(t, got, 1)
		_, err = rattacherSource(ctx, sqlDB, got[0], a, admin)
		require.NoError(t, err)
		liens, _ := db.GetLiens(ctx, sqlDB, a.ID)
		var mission bool
		for _, l := range liens {
			mission = mission || (l.Kind == db.LienMission && l.Ref == "mis1")
		}
		assert.True(t, mission)
	})
}

func TestPropositions(t *testing.T) {
	srv, sqlDB, client, c := sourcesServer(t)
	ctx := t.Context()
	a := nouvelleAffaire(t, sqlDB, 1, "VMC D04")
	src := func(ext, texte string) string {
		id, err := db.InsertSource(ctx, sqlDB, db.SourceDB{Canal: db.CanalGmail, ExtID: ext, Fil: ext, Auteur: "Gestionnaire", Texte: texte, Date: time.Now()})
		require.NoError(t, err)
		return id
	}
	prop := func(p db.PropositionDB) string {
		p.Auteur, p.Justification = "claude", "parce que"
		id, err := db.InsertProposition(ctx, sqlDB, p)
		require.NoError(t, err)
		return id
	}
	accepter := func(id string, form url.Values) string {
		status, loc := post(t, client, admin, srv.URL+"/propositions/"+id+"/accepter", form)
		require.Equal(t, http.StatusSeeOther, status, loc)
		return loc
	}

	t.Run("the page is for the administrators", func(t *testing.T) {
		status, _ := getAs(t, client, membre, srv.URL+"/propositions")
		assert.Equal(t, http.StatusForbidden, status)
	})

	t.Run("rattacher, then a second click does nothing", func(t *testing.T) {
		s := src("p1", "Les câbles sont changés.")
		id := prop(db.PropositionDB{Action: db.PropRattacher, AffaireID: a.ID, SourceIDs: []string{s}})
		status, body := getAs(t, client, admin, srv.URL+"/propositions")
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "Les câbles sont changés.")
		accepter(id, nil)
		got, _ := db.GetSource(ctx, sqlDB, s)
		assert.Equal(t, db.SourceClassee, got.Etat)
		loc := accepter(id, nil)
		assert.Contains(t, loc, "d%C3%A9j%C3%A0")
	})

	t.Run("commenter with the text corrected by the administrator", func(t *testing.T) {
		id := prop(db.PropositionDB{Action: db.PropCommenter, AffaireID: a.ID, Donnees: db.PropositionDonnees{Texte: "brouillon"}})
		accepter(id, url.Values{"texte": {"Câbles remplacés le 10/11."}})
		coms, _ := db.GetCommentaires(ctx, sqlDB, a.ID)
		require.Len(t, coms, 1)
		assert.True(t, strings.HasPrefix(coms[0].Texte, "Câbles remplacés le 10/11."))
		assert.Contains(t, coms[0].Texte, admin)
	})

	t.Run("relancer and lever", func(t *testing.T) {
		accepter(prop(db.PropositionDB{Action: db.PropRelancer, AffaireID: a.ID, Donnees: db.PropositionDonnees{Date: "12/11/2026", Note: "par mail"}}), nil)
		accepter(prop(db.PropositionDB{Action: db.PropLever, AffaireID: a.ID}), nil)
		got, _ := db.GetAffaire(ctx, sqlDB, a.ID)
		assert.Equal(t, db.AffaireStatutLevee, got.Statut)
		require.Len(t, got.Relances, 1)
		assert.Equal(t, "12/11/2026", got.Relances[0].Date)
	})

	t.Run("creer_affaire numbers it and files the messages", func(t *testing.T) {
		s := src("p2", "Le portail du garage reste ouvert.")
		loc := accepter(prop(db.PropositionDB{Action: db.PropCreerAffaire, SourceIDs: []string{s}, Donnees: db.PropositionDonnees{Titre: "Portail", Localisation: "Garage"}}), url.Values{"titre": {"Portail garage ouvert"}, "ensuite": {"affaire"}})
		assert.Contains(t, loc, "/affaires/")
		all, _ := db.GetAffaires(ctx, sqlDB, db.AffaireStatutEnCours)
		require.Len(t, all, 1)
		assert.Equal(t, "Portail garage ouvert", all[0].Titre)
		assert.Equal(t, "Garage", all[0].Localisation)
		refs, _ := db.AffairesOfSource(ctx, sqlDB, s)
		assert.Len(t, refs, 1)
	})

	t.Run("ignorer and refuser", func(t *testing.T) {
		s1, s2 := src("p3", "Merci !"), src("p4", "Absent du bureau")
		accepter(prop(db.PropositionDB{Action: db.PropIgnorer, SourceIDs: []string{s1}}), nil)
		got, _ := db.GetSource(ctx, sqlDB, s1)
		assert.Equal(t, db.SourceIgnoree, got.Etat)

		id := prop(db.PropositionDB{Action: db.PropIgnorer, SourceIDs: []string{s2}})
		status, _ := post(t, client, admin, srv.URL+"/propositions/"+id+"/refuser", nil)
		assert.Equal(t, http.StatusSeeOther, status)
		p, _ := db.GetProposition(ctx, sqlDB, id)
		assert.Equal(t, db.PropRefusee, p.Etat)
		got, _ = db.GetSource(ctx, sqlDB, s2)
		assert.Equal(t, db.SourceATrier, got.Etat, "refusing changes nothing")
	})

	t.Run("Lancer maintenant writes the trigger", func(t *testing.T) {
		status, _ := post(t, client, admin, srv.URL+"/claude/lancer", nil)
		assert.Equal(t, http.StatusSeeOther, status)
		e := c.brain.etat()
		assert.True(t, e.EnCours)
		assert.False(t, e.Demande.IsZero())
	})
}
