package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
	"golang.org/x/oauth2"
)

// /reglages, for the administrators: where the messages to sort come from,
// and the connection of the Gmail mailbox.
//
// Only one mailbox can be connected, that of --gmail-account, and only by
// that very account: the other administrators see the state, not the
// buttons, and a login that ends on any other Google account is refused
// (the address is asked to Google, see gmailAdresse). The collector checks
// the same thing before reading anything (gmailCollecteur.brancher).

// gmailAttenteMax is how long one has to come back from Google with the
// address of the localhost page.
const gmailAttenteMax = 15 * time.Minute

type reglages struct {
	copro
	fichier string // --gmail-token-file
	compte  string // --gmail-account
	requete string // --gmail-query
	api     string // --gmail-api

	// mu guards the token file (read, change, write) and the logins that
	// were started and wait for their code.
	mu       sync.Mutex
	attentes map[string]gmailAttente // By OAuth state.
}

type gmailAttente struct {
	verifier string // PKCE
	par      string
	quand    time.Time
}

func addReglagesHandlers(mux *http.ServeMux, c copro) {
	g := &reglages{copro: c, fichier: *gmailTokenFile, compte: strings.TrimSpace(*gmailAccount), requete: *gmailQuery, api: *gmailAPIFlag,
		attentes: map[string]gmailAttente{}}
	mux.HandleFunc("GET /reglages", g.voir)
	// These change who reads which mailbox: not from a form on another site.
	memeSite := http.NewCrossOriginProtection()
	post := func(path string, h http.HandlerFunc) {
		mux.Handle("POST "+path, memeSite.Handler(h))
	}
	post("/reglages/gmail/client", g.gmailClient)
	post("/reglages/gmail/connecter", g.gmailConnecter)
	post("/reglages/gmail/code", g.gmailCode)
	post("/reglages/gmail/deconnecter", g.gmailDeconnecter)
}

// gmailVue is what the page says about the mailbox.
type gmailVue struct {
	Active       bool   // --gmail-token-file is given.
	Compte       string // The only mailbox that can be connected.
	Proprietaire bool   // The one looking is that account.
	ClientID     string
	SecretConnu  bool
	Relie        bool
	Adresse      string // As Google gave it; "" for a file made by hand.
	Depuis       time.Time
	Par          string
	Probleme     string // The token file can't be read.
	Requete      string
	Periode      string
	Collecte     gmailCollecte
	Redirect     string
}

// canalVue is one line of the table of the channels.
type canalVue struct {
	Nom    string
	Etat   string
	Actif  bool
	Detail string
	db.CanalStats
}

func (g *reglages) vue(r *http.Request) gmailVue {
	v := gmailVue{Active: g.fichier != "", Compte: g.compte, Requete: g.requete, Periode: periode(*sourcesPeriod), Redirect: gmailRedirect}
	v.Proprietaire = g.compte != "" && memeAdresse(currentUser(r), g.compte)
	if !v.Active {
		return v
	}
	g.mu.Lock()
	tok, err := lireGmailToken(g.fichier)
	g.mu.Unlock()
	if err != nil {
		logutil.Errorf("%v", err)
		v.Probleme = "Le fichier du jeton est illisible sur le serveur (voir ses logs)."
		return v
	}
	v.ClientID, v.SecretConnu = tok.ClientID, tok.ClientSecret != ""
	v.Relie, v.Adresse, v.Depuis, v.Par = tok.relie(), tok.Account, tok.ConnectedAt, tok.ConnectedBy
	if v.Relie {
		if v.Collecte, err = lireGmailCollecte(r.Context(), g.sqlDB); err != nil {
			logutil.Errorf("%v", err)
		}
	}
	return v
}

// periode writes a duration the way one says it.
func periode(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d h", d/time.Hour)
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%d min", d/time.Minute)
	}
	return d.String()
}

func (g *reglages) voir(w http.ResponseWriter, r *http.Request) {
	if !g.adminOnly(w, r) {
		return
	}
	stats, err := db.StatsSources(r.Context(), g.sqlDB)
	if err != nil {
		g.fail(w, "counting sources per channel", err)
		return
	}
	whatsapp := canalVue{Nom: "WhatsApp", Etat: "pas branché", Detail: "rien, le service whatsapp n'est pas donné au serveur (--whatsapp-url)", CanalStats: stats[db.CanalWhatsApp]}
	if *whatsappURL != "" {
		whatsapp.Actif, whatsapp.Etat = true, "branché"
		whatsapp.Detail = fmt.Sprintf("%d conversation(s) en entier, %d autre(s) quand un échange contient un mot-clé, et les voisins du carnet d'adresses", len(jidSet(*whatsappChats)), len(jidSet(*whatsappFiltered)))
	}
	g.render(w, "reglages", struct {
		page
		Erreur string
		Gmail  gmailVue
		Emails db.CanalStats
		Canaux []canalVue
		Brain  brainEtat
	}{
		page:   g.page(r, "reglages"),
		Erreur: r.URL.Query().Get("erreur"),
		Gmail:  g.vue(r),
		Emails: stats[db.CanalGmail],
		Canaux: []canalVue{
			whatsapp,
			{Nom: "Foncia", Actif: true, Etat: "branché", Detail: "chaque nouvelle mission et chaque nouvelle facture trouvée par la synchronisation", CanalStats: stats[db.CanalFoncia]},
		},
		Brain: g.brain.etat(),
	})
}

// refuser goes back to the page with what went wrong, in red.
func (g *reglages) refuser(w http.ResponseWriter, r *http.Request, format string, args ...any) {
	q := url.Values{"erreur": {fmt.Sprintf(format, args...)}}
	http.Redirect(w, r, g.basePath+"/reglages?"+q.Encode()+"#gmail", http.StatusSeeOther)
}

// proprietaire lets only --gmail-account change the connection of its own
// mailbox.
func (g *reglages) proprietaire(w http.ResponseWriter, r *http.Request) bool {
	if !g.adminOnly(w, r) {
		return false
	}
	switch {
	case g.fichier == "":
		renderErr(w, http.StatusBadRequest, "La collecte des e-mails n'est pas activée sur ce serveur (--gmail-token-file).")
	case g.compte == "":
		renderErr(w, http.StatusForbidden, "Le compte à relier n'est pas fixé sur ce serveur (--gmail-account) : la connexion depuis le site est fermée.")
	case !memeAdresse(currentUser(r), g.compte):
		renderErr(w, http.StatusForbidden, "Seul "+g.compte+" peut relier ou débrancher sa boîte Gmail.")
	default:
		return true
	}
	return false
}

// changer reads the token file, changes it and writes it back.
func (g *reglages) changer(f func(*gmailToken) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	tok, err := lireGmailToken(g.fichier)
	if err != nil {
		return err
	}
	if err := f(&tok); err != nil {
		return err
	}
	return ecrireGmailToken(g.fichier, tok)
}

// oublierCollecte forgets how the last collection went: it was that of
// another connection.
func (g *reglages) oublierCollecte(ctx context.Context) {
	if err := db.SetReglage(ctx, g.sqlDB, reglageGmailCollecte, ""); err != nil {
		logutil.Errorf("%v", err)
	}
}

// errSaisie is a mistake of the person filling the form, shown as it is.
type errSaisie string

func (e errSaisie) Error() string { return string(e) }

// gmailClient sets the OAuth client. Another client forgets the mailbox:
// its refresh token only works with the client that got it.
func (g *reglages) gmailClient(w http.ResponseWriter, r *http.Request) {
	if !g.proprietaire(w, r) {
		return
	}
	id, secret := strings.TrimSpace(r.FormValue("client_id")), strings.TrimSpace(r.FormValue("client_secret"))
	autre := false
	err := g.changer(func(tok *gmailToken) error {
		if secret == "" && id == tok.ClientID {
			secret = tok.ClientSecret // Left empty to keep it.
		}
		if id == "" || secret == "" {
			return errSaisie("Il faut l'ID du client Google et son secret.")
		}
		if !strings.HasSuffix(id, ".apps.googleusercontent.com") {
			return errSaisie("L'ID d'un client Google finit par .apps.googleusercontent.com.")
		}
		autre = id != tok.ClientID || secret != tok.ClientSecret
		if autre {
			*tok = gmailToken{ClientID: id, ClientSecret: secret, AuthURI: tok.AuthURI, TokenURI: tok.TokenURI}
		}
		return nil
	})
	var saisie errSaisie
	switch {
	case errors.As(err, &saisie):
		g.refuser(w, r, "%s", saisie)
	case err != nil:
		g.fail(w, "setting the Google client", err)
	case autre:
		g.oublierCollecte(r.Context())
		g.redirect(w, r, "/reglages#gmail", "Client Google enregistré. Il reste à relier la boîte.")
	default:
		g.redirect(w, r, "/reglages#gmail", "Le client Google n'a pas changé.")
	}
}

// gmailConnecter sends the browser to Google, to allow reading the mailbox.
func (g *reglages) gmailConnecter(w http.ResponseWriter, r *http.Request) {
	if !g.proprietaire(w, r) {
		return
	}
	g.mu.Lock()
	tok, err := lireGmailToken(g.fichier)
	g.mu.Unlock()
	if err != nil {
		g.fail(w, "reading the Gmail token", err)
		return
	}
	if tok.ClientID == "" || tok.ClientSecret == "" {
		g.refuser(w, r, "Renseigne d'abord le client Google.")
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	state, verifier := hex.EncodeToString(b), oauth2.GenerateVerifier()
	now := time.Now()
	g.mu.Lock()
	for s, a := range g.attentes {
		if now.Sub(a.quand) > gmailAttenteMax {
			delete(g.attentes, s)
		}
	}
	g.attentes[state] = gmailAttente{verifier: verifier, par: currentUser(r), quand: now}
	g.mu.Unlock()
	conf := tok.conf()
	// offline + consent: Google gives a refresh token each time. login_hint
	// puts the right account first in Google's list.
	http.Redirect(w, r, conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce, oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("login_hint", g.compte)), http.StatusSeeOther)
}

// gmailCode ends the login: the address of the localhost page that Google
// sent the browser to, pasted in the form, has the code.
func (g *reglages) gmailCode(w http.ResponseWriter, r *http.Request) {
	if !g.proprietaire(w, r) {
		return
	}
	colle, err := url.Parse(strings.TrimSpace(r.FormValue("url")))
	if err != nil || colle.Query().Get("state") == "" {
		g.refuser(w, r, "Cette adresse n'est pas celle attendue : colle l'adresse entière de la page localhost, qui commence par %s?state=…", gmailRedirect)
		return
	}
	q := colle.Query()
	if e := q.Get("error"); e != "" {
		g.refuser(w, r, "Google n'a pas donné l'accès (%s). Recommence depuis « Ouvrir Google ».", e)
		return
	}
	if q.Get("code") == "" {
		g.refuser(w, r, "Cette adresse n'a pas de code : colle l'adresse entière de la page localhost.")
		return
	}
	g.mu.Lock()
	attente, connue := g.attentes[q.Get("state")]
	delete(g.attentes, q.Get("state"))
	g.mu.Unlock()
	if !connue || time.Since(attente.quand) > gmailAttenteMax || attente.par != currentUser(r) {
		g.refuser(w, r, "Cette connexion a expiré ou n'a pas été commencée ici. Recommence depuis « Ouvrir Google ».")
		return
	}

	g.mu.Lock()
	tok, err := lireGmailToken(g.fichier)
	g.mu.Unlock()
	if err != nil {
		g.fail(w, "reading the Gmail token", err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	conf := tok.conf()
	jeton, err := conf.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(attente.verifier))
	if err != nil {
		logutil.Errorf("exchanging the Google code: %v", err)
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode != "" {
			g.refuser(w, r, "Google a refusé le code (%s). Recommence depuis « Ouvrir Google » : un code ne sert qu'une fois.", re.ErrorCode)
			return
		}
		g.refuser(w, r, "Google n'a pas répondu comme prévu (voir les logs du serveur). Recommence depuis « Ouvrir Google ».")
		return
	}
	if jeton.RefreshToken == "" {
		g.refuser(w, r, "Google n'a pas donné de jeton durable. Recommence depuis « Ouvrir Google ».")
		return
	}
	// Whose mailbox is it? Asked to Google with the new token: nothing is
	// kept unless it is that of --gmail-account.
	adresse, err := gmailAdresse(ctx, gmailClientDe(ctx, conf, jeton), g.api)
	if err != nil {
		logutil.Errorf("checking whose mailbox was connected: %v", err)
		g.refuser(w, r, "Google a donné un jeton, mais pas le droit de lire la boîte : laisse la case de lecture des e-mails cochée, et recommence depuis « Ouvrir Google ».")
		return
	}
	if !memeAdresse(adresse, g.compte) {
		logutil.Errorf("refusing to connect the mailbox of %s: only %s can be", adresse, g.compte)
		g.refuser(w, r, "Google a répondu pour le compte %s. Seule la boîte de %s peut être reliée : rien n'a été enregistré. Recommence en choisissant %s chez Google.", adresse, g.compte, g.compte)
		return
	}
	par := currentUser(r)
	err = g.changer(func(tok *gmailToken) error {
		if tok.ClientID != conf.ClientID {
			return errSaisie("Le client Google a changé pendant la connexion. Recommence depuis « Ouvrir Google ».")
		}
		tok.RefreshToken, tok.Account, tok.ConnectedAt, tok.ConnectedBy = jeton.RefreshToken, adresse, time.Now().UTC().Truncate(time.Second), par
		return nil
	})
	var saisie errSaisie
	if errors.As(err, &saisie) {
		g.refuser(w, r, "%s", saisie)
		return
	}
	if err != nil {
		g.fail(w, "writing the Gmail token", err)
		return
	}
	g.oublierCollecte(r.Context())
	logutil.Infof("the mailbox of %s was connected by %s", adresse, par)
	g.redirect(w, r, "/reglages#gmail", fmt.Sprintf("La boîte de %s est reliée, en lecture seule. Ses e-mails arrivent au prochain passage (toutes les %s).", adresse, periode(*sourcesPeriod)))
}

// gmailDeconnecter forgets the refresh token; the OAuth client stays, to
// connect again. Google isn't told to cancel the token: that can cancel
// every login of that account with that client, and the client is often
// shared with a command-line tool. The page says where to do it.
func (g *reglages) gmailDeconnecter(w http.ResponseWriter, r *http.Request) {
	if !g.proprietaire(w, r) {
		return
	}
	err := g.changer(func(tok *gmailToken) error {
		tok.RefreshToken, tok.Account, tok.ConnectedAt, tok.ConnectedBy = "", "", time.Time{}, ""
		return nil
	})
	if err != nil {
		g.fail(w, "forgetting the Gmail token", err)
		return
	}
	g.oublierCollecte(r.Context())
	logutil.Infof("the mailbox was disconnected by %s", currentUser(r))
	g.redirect(w, r, "/reglages#gmail", "La boîte n'est plus lue : son jeton est effacé du serveur. Les e-mails déjà collectés restent.")
}
