package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// `foncia mcp-brain` is the MCP server, on stdin/stdout, that Claude gets when
// the runner of brain/ starts `claude -p` on the Pi: it reads the messages to
// sort, the affaires and the files, and it can only PROPOSE. What it proposes
// waits on /propositions for an administrator.
//
// It is never served over HTTP: the co-owners' assistants on /mcp don't see
// Maël's messages.

const brainInstructions = `Outils du secrétariat du conseil syndical de Terra Nostra 2. Lecture : sources_a_trier (les messages collectés pas encore classés), affaires, lire_affaire, lire_fichier (PDF, photo), et search / read_document pour les données Foncia. Écriture : uniquement des propositions (proposer_*), qu'un administrateur accepte ou refuse.`

func runBrainMCP(ctx context.Context, sqlDB *sql.DB, invoicesDir string) error {
	b := brainServer{sqlDB: sqlDB, mcpServer: mcpServer{sqlDB: sqlDB, invoicesDir: invoicesDir, baseURL: *serveBaseURL + *serveBasePath, lastSync: func() (time.Time, error) { return time.Time{}, nil }}}
	server := mcp.NewServer(&mcp.Implementation{Name: "copro", Title: "Secrétariat Terra Nostra 2", Version: version}, &mcp.ServerOptions{Instructions: brainInstructions})
	b.addTools(server)
	return server.Run(ctx, &mcp.StdioTransport{})
}

type brainServer struct {
	sqlDB *sql.DB
	mcpServer
}

var propose = &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: new(false), IdempotentHint: false, OpenWorldHint: new(false)}

func (b brainServer) addTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "sources_a_trier",
		Description: "Les messages collectés (e-mails, échanges WhatsApp, nouveautés Foncia) qui ne sont ni classés, ni écartés, ni déjà couverts par une proposition en attente, du plus ancien au plus récent. fil_affaires donne les affaires où d'autres messages du même fil sont déjà classés. reste dit combien il en reste après ceux-ci.",
		Annotations: readOnlyTool,
	}, b.sourcesATrier)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "affaires",
		Description: "La liste des affaires du conseil syndical (désordres, actions, décisions suivies), avec leur fiche et leurs derniers messages. statut: en_cours (défaut), levee ou toutes.",
		Annotations: readOnlyTool,
	}, b.affaires)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "lire_affaire",
		Description: "Le dossier complet d'une affaire : fiche, relances, commentaires, pièces et messages rattachés.",
		Annotations: readOnlyTool,
	}, b.lireAffaire)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "lire_fichier",
		Description: "Le contenu d'une pièce jointe d'un message, par son sha256 : le texte d'un PDF (par morceaux, avec offset), ou l'image elle-même pour une photo.",
		Annotations: readOnlyTool,
	}, b.lireFichier)
	addFonciaReadTools(server, b.mcpServer)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "proposer_rattachement",
		Description: "Proposer de rattacher un ou plusieurs messages à une affaire existante. Leurs pièces jointes rejoignent les pièces de l'affaire.",
		Annotations: propose,
	}, b.proposerRattachement)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "proposer_nouvelle_affaire",
		Description: "Proposer d'ouvrir une affaire pour un désordre, une action ou une décision qu'aucune affaire ne suit encore, avec les messages qui en parlent.",
		Annotations: propose,
	}, b.proposerNouvelleAffaire)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "proposer_commentaire",
		Description: "Proposer un commentaire sur une affaire : ce qu'un message apprend de nouveau (décision, date, montant d'un devis, réponse du syndic, ce qu'il reste à faire), en une à trois phrases factuelles. Les messages donnés sont aussi rattachés.",
		Annotations: propose,
	}, b.proposerCommentaire)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "proposer_relance",
		Description: "Proposer d'ajouter une relance à une affaire, quand un message relance le syndic ou une entreprise. date au format JJ/MM/AAAA.",
		Annotations: propose,
	}, b.proposerRelance)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "proposer_levee",
		Description: "Proposer de lever (clore) une affaire, quand un message confirme que le problème est réglé ou la décision prise.",
		Annotations: propose,
	}, b.proposerLevee)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "proposer_ecarter",
		Description: "Proposer d'écarter des messages qui ne concernent aucune affaire du conseil syndical (discussion sans suite, publicité, sujet personnel, doublon).",
		Annotations: propose,
	}, b.proposerEcarter)
}

// -----------------------------------------------------------------------------
// Lecture
// -----------------------------------------------------------------------------

type brainFichier struct {
	SHA256 string `json:"sha256"`
	Nom    string `json:"nom"`
	Type   string `json:"type"`
	Taille string `json:"taille"`
}

type brainSource struct {
	ID            string         `json:"id"`
	Canal         string         `json:"canal"`
	Date          string         `json:"date"`
	Auteur        string         `json:"auteur"`
	Destinataires string         `json:"destinataires,omitempty"`
	Conversation  string         `json:"conversation,omitempty"`
	Sujet         string         `json:"sujet,omitempty"`
	Texte         string         `json:"texte"`
	Fichiers      []brainFichier `json:"fichiers,omitempty"`
	FilAffaires   []string       `json:"fil_affaires,omitempty"`
}

func versBrainSource(s db.SourceDB, maxTexte int) brainSource {
	out := brainSource{
		ID: s.ID, Canal: s.Canal.French(), Date: s.Date.In(paris).Format("02/01/2006 15:04"), Auteur: s.Auteur,
		Destinataires: s.Destinataires, Conversation: s.FilTitre, Sujet: s.Sujet, Texte: s.Texte,
	}
	if r := []rune(out.Texte); len(r) > maxTexte {
		out.Texte = string(r[:maxTexte]) + " […]"
	}
	for _, f := range s.Fichiers {
		out.Fichiers = append(out.Fichiers, brainFichier{SHA256: f.SHA256, Nom: f.NomDansMessage, Type: f.Mime, Taille: taille(f.Taille)})
	}
	return out
}

type sourcesATrierInput struct {
	Limite int `json:"limite,omitempty" jsonschema:"Combien de messages au plus (15 par défaut, 40 au plus)."`
}

type sourcesATrierOutput struct {
	Sources []brainSource `json:"sources"`
	Reste   int           `json:"reste"`
}

func (b brainServer) sourcesATrier(ctx context.Context, _ *mcp.CallToolRequest, in sourcesATrierInput) (*mcp.CallToolResult, sourcesATrierOutput, error) {
	limite := in.Limite
	if limite <= 0 {
		limite = 15
	}
	limite = min(limite, 40)
	toutes, err := db.GetSources(ctx, b.sqlDB, db.SourcesFilter{Etats: []db.SourceEtat{db.SourceATrier}})
	if err != nil {
		return nil, sourcesATrierOutput{}, err
	}
	proposees, err := db.SourcesProposees(ctx, b.sqlDB)
	if err != nil {
		return nil, sourcesATrierOutput{}, err
	}
	var restantes []db.SourceDB
	for _, s := range toutes {
		if !proposees[s.ID] {
			restantes = append(restantes, s)
		}
	}
	slices.Reverse(restantes) // Oldest first.
	out := sourcesATrierOutput{Sources: []brainSource{}}
	for i, s := range restantes {
		if i >= limite {
			break
		}
		bs := versBrainSource(s, 6000)
		affaires, err := db.AffairesOfFil(ctx, b.sqlDB, s.Canal, s.Fil, s.ID)
		if err != nil {
			return nil, out, err
		}
		for _, a := range affaires {
			bs.FilAffaires = append(bs.FilAffaires, fmt.Sprintf("%s (n°%d %s)", a.ID, a.Numero, a.Titre))
		}
		out.Sources = append(out.Sources, bs)
	}
	out.Reste = max(len(restantes)-limite, 0)
	return nil, out, nil
}

type brainAffaire struct {
	ID              string   `json:"id"`
	Numero          int      `json:"numero"`
	Titre           string   `json:"titre"`
	Statut          string   `json:"statut"`
	Localisation    string   `json:"localisation,omitempty"`
	ActionFoncia    string   `json:"action_foncia,omitempty"`
	Responsable     string   `json:"responsable,omitempty"`
	DateSignalement string   `json:"date_signalement,omitempty"`
	Relances        []string `json:"relances,omitempty"`
	ObsCopro        string   `json:"obs_copro,omitempty"`
	ObsSyndic       string   `json:"obs_syndic,omitempty"`
	DateLevee       string   `json:"date_levee,omitempty"`
	DerniersMsgs    []string `json:"derniers_messages,omitempty"`
}

func versBrainAffaire(a db.AffaireDB) brainAffaire {
	out := brainAffaire{
		ID: a.ID, Numero: a.Numero, Titre: a.Titre, Statut: string(a.Statut), Localisation: a.Localisation,
		ActionFoncia: a.ActionFoncia, Responsable: a.Responsable, DateSignalement: a.DateSignalement,
		ObsCopro: a.ObsCopro, ObsSyndic: a.ObsSyndic, DateLevee: a.DateLevee,
	}
	for _, r := range a.Relances {
		out.Relances = append(out.Relances, strings.TrimSpace(r.Date+" "+r.Note))
	}
	return out
}

type affairesInput struct {
	Statut string `json:"statut,omitempty" jsonschema:"en_cours (défaut), levee ou toutes."`
}

type affairesOutput struct {
	Affaires []brainAffaire `json:"affaires"`
}

func (b brainServer) affaires(ctx context.Context, _ *mcp.CallToolRequest, in affairesInput) (*mcp.CallToolResult, affairesOutput, error) {
	var statut db.AffaireStatut
	switch in.Statut {
	case "", "en_cours":
		statut = db.AffaireStatutEnCours
	case "levee":
		statut = db.AffaireStatutLevee
	case "toutes":
	default:
		return nil, affairesOutput{}, fmt.Errorf("statut %q inconnu : en_cours, levee ou toutes", in.Statut)
	}
	list, err := db.GetAffaires(ctx, b.sqlDB, statut)
	if err != nil {
		return nil, affairesOutput{}, err
	}
	out := affairesOutput{Affaires: []brainAffaire{}}
	for _, a := range list {
		ba := versBrainAffaire(a)
		msgs, err := b.messagesAffaire(ctx, a.ID)
		if err != nil {
			return nil, out, err
		}
		for i := len(msgs) - 1; i >= 0 && len(ba.DerniersMsgs) < 3; i-- {
			m := msgs[i]
			ba.DerniersMsgs = append(ba.DerniersMsgs, m.Date.In(paris).Format("02/01/2006")+" "+m.Canal.French()+" de "+m.Auteur+" : "+m.Titre())
		}
		out.Affaires = append(out.Affaires, ba)
	}
	return nil, out, nil
}

// messagesAffaire returns the messages attached to an affaire, oldest first.
func (b brainServer) messagesAffaire(ctx context.Context, affaireID string) ([]db.SourceDB, error) {
	liens, err := db.GetLiens(ctx, b.sqlDB, affaireID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, l := range liens {
		if l.Kind == db.LienSource {
			ids = append(ids, l.Ref)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	msgs, err := db.GetSources(ctx, b.sqlDB, db.SourcesFilter{IDs: ids})
	slices.Reverse(msgs)
	return msgs, err
}

type lireAffaireInput struct {
	ID string `json:"id" jsonschema:"L'id de l'affaire (donné par affaires)."`
}

type lireAffaireOutput struct {
	Affaire      brainAffaire  `json:"affaire"`
	Commentaires []string      `json:"commentaires"`
	Pieces       []string      `json:"pieces"`
	Messages     []brainSource `json:"messages"`
}

func (b brainServer) lireAffaire(ctx context.Context, _ *mcp.CallToolRequest, in lireAffaireInput) (*mcp.CallToolResult, lireAffaireOutput, error) {
	a, err := db.GetAffaire(ctx, b.sqlDB, in.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, lireAffaireOutput{}, fmt.Errorf("pas d'affaire %q : utiliser l'id donné par affaires", in.ID)
	}
	if err != nil {
		return nil, lireAffaireOutput{}, err
	}
	out := lireAffaireOutput{Affaire: versBrainAffaire(a), Commentaires: []string{}, Pieces: []string{}, Messages: []brainSource{}}
	coms, err := db.GetCommentaires(ctx, b.sqlDB, a.ID)
	if err != nil {
		return nil, out, err
	}
	for _, c := range coms {
		out.Commentaires = append(out.Commentaires, c.CreatedAt.In(paris).Format("02/01/2006")+" "+c.Auteur+" : "+c.Texte)
	}
	liens, err := db.GetLiens(ctx, b.sqlDB, a.ID)
	if err != nil {
		return nil, out, err
	}
	for _, l := range liens {
		if l.Kind == db.LienSource {
			continue
		}
		p := l.Kind.French() + " : " + l.Titre
		if l.Note != "" {
			p += " (" + l.Note + ")"
		}
		out.Pieces = append(out.Pieces, p)
	}
	msgs, err := b.messagesAffaire(ctx, a.ID)
	if err != nil {
		return nil, out, err
	}
	if len(msgs) > 15 {
		msgs = msgs[len(msgs)-15:]
	}
	for _, m := range msgs {
		out.Messages = append(out.Messages, versBrainSource(m, 1500))
	}
	return nil, out, nil
}

type lireFichierInput struct {
	SHA256 string `json:"sha256" jsonschema:"Le sha256 d'une pièce jointe, donné dans fichiers."`
	Offset int    `json:"offset,omitempty" jsonschema:"Pour un long PDF : où reprendre (next_offset)."`
}

type lireFichierOutput struct {
	Nom        string `json:"nom"`
	Type       string `json:"type"`
	Texte      string `json:"texte,omitempty"`
	NextOffset int    `json:"next_offset,omitempty"`
	Note       string `json:"note,omitempty"`
}

const maxImageBrain = 4 << 20

func (b brainServer) lireFichier(ctx context.Context, _ *mcp.CallToolRequest, in lireFichierInput) (*mcp.CallToolResult, lireFichierOutput, error) {
	if !shaRe.MatchString(in.SHA256) {
		return nil, lireFichierOutput{}, fmt.Errorf("%q n'est pas un sha256", in.SHA256)
	}
	f, err := db.GetFichier(ctx, b.sqlDB, in.SHA256)
	if err != nil {
		return nil, lireFichierOutput{}, fmt.Errorf("fichier %s : %w", in.SHA256, err)
	}
	out := lireFichierOutput{Nom: f.Nom, Type: f.Mime}
	switch {
	case f.IsImage() && f.Taille <= maxImageBrain && f.Mime != "image/heic":
		data, err := os.ReadFile(cheminFichier(f.SHA256))
		if err != nil {
			return nil, out, err
		}
		out.Note = "L'image est jointe."
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.ImageContent{Data: data, MIMEType: f.Mime}}}, out, nil
	case f.IsPDF():
		pages, err := pdfPages(ctx, cheminFichier(f.SHA256))
		if err != nil {
			return nil, out, err
		}
		var sb strings.Builder
		for i, p := range pages {
			fmt.Fprintf(&sb, "--- page %d ---\n%s\n", i+1, p)
		}
		runes := []rune(sb.String())
		if len(strings.Fields(sb.String())) <= 3*len(pages) {
			out.Note = "PDF sans texte (sans doute un scan)."
		}
		start := min(max(in.Offset, 0), len(runes))
		end := min(start+15000, len(runes))
		out.Texte = string(runes[start:end])
		if end < len(runes) {
			out.NextOffset = end
		}
	case strings.HasPrefix(f.Mime, "text/"):
		data, err := os.ReadFile(cheminFichier(f.SHA256))
		if err != nil {
			return nil, out, err
		}
		out.Texte = string([]rune(string(data))[:min(len([]rune(string(data))), 15000)])
	default:
		out.Note = "Ce type de fichier ne se lit pas ici ; se fier à son nom."
	}
	return nil, out, nil
}

// -----------------------------------------------------------------------------
// Propositions
// -----------------------------------------------------------------------------

type propositionOutput struct {
	ID string `json:"id"`
}

// verifier checks what a proposition points to, so that Claude learns of a
// wrong id right away rather than the administrator on accepting.
func (b brainServer) verifier(ctx context.Context, affaireID string, sourceIDs []string, sourcesRequises bool) error {
	if affaireID != "" {
		if _, err := db.GetAffaire(ctx, b.sqlDB, affaireID); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("pas d'affaire %q : utiliser l'id donné par affaires", affaireID)
		} else if err != nil {
			return err
		}
	}
	if sourcesRequises && len(sourceIDs) == 0 {
		return fmt.Errorf("source_ids est vide")
	}
	if len(sourceIDs) == 0 {
		return nil
	}
	got, err := db.GetSources(ctx, b.sqlDB, db.SourcesFilter{IDs: sourceIDs})
	if err != nil {
		return err
	}
	if len(got) != len(slices.Compact(slices.Sorted(slices.Values(sourceIDs)))) {
		return fmt.Errorf("un des source_ids n'existe pas : utiliser les id donnés par sources_a_trier")
	}
	for _, s := range got {
		if s.Etat != db.SourceATrier {
			return fmt.Errorf("le message %s est déjà %s", s.ID, strings.ToLower(s.Etat.French()))
		}
	}
	return nil
}

func (b brainServer) proposer(ctx context.Context, p db.PropositionDB, sourcesRequises bool) (*mcp.CallToolResult, propositionOutput, error) {
	if strings.TrimSpace(p.Justification) == "" {
		return nil, propositionOutput{}, fmt.Errorf("justification est vide : dire en une phrase pourquoi")
	}
	if err := b.verifier(ctx, p.AffaireID, p.SourceIDs, sourcesRequises); err != nil {
		return nil, propositionOutput{}, err
	}
	p.Auteur = "claude"
	id, err := db.InsertProposition(ctx, b.sqlDB, p)
	return nil, propositionOutput{ID: id}, err
}

type commun struct {
	SourceIDs     []string `json:"source_ids" jsonschema:"Les id des messages concernés (sources_a_trier)."`
	Justification string   `json:"justification" jsonschema:"Pourquoi, en une phrase, pour l'administrateur qui valide."`
	Citation      string   `json:"citation,omitempty" jsonschema:"Le passage exact du message qui le montre, court."`
}

type rattachementInput struct {
	AffaireID string `json:"affaire_id"`
	commun
}

func (b brainServer) proposerRattachement(ctx context.Context, _ *mcp.CallToolRequest, in rattachementInput) (*mcp.CallToolResult, propositionOutput, error) {
	return b.proposer(ctx, db.PropositionDB{Action: db.PropRattacher, AffaireID: in.AffaireID, SourceIDs: in.SourceIDs, Justification: in.Justification, Citation: in.Citation}, true)
}

type nouvelleAffaireInput struct {
	Titre           string `json:"titre" jsonschema:"Court, comme dans le tableau : « Fuite toiture C02 »."`
	Localisation    string `json:"localisation,omitempty"`
	ActionFoncia    string `json:"action_foncia,omitempty" jsonschema:"Ce qui est demandé au syndic."`
	Responsable     string `json:"responsable,omitempty" jsonschema:"Le membre du conseil qui suit, s'il est clair."`
	DateSignalement string `json:"date_signalement,omitempty" jsonschema:"JJ/MM/AAAA."`
	commun
}

func (b brainServer) proposerNouvelleAffaire(ctx context.Context, _ *mcp.CallToolRequest, in nouvelleAffaireInput) (*mcp.CallToolResult, propositionOutput, error) {
	if strings.TrimSpace(in.Titre) == "" {
		return nil, propositionOutput{}, fmt.Errorf("titre est vide")
	}
	return b.proposer(ctx, db.PropositionDB{
		Action: db.PropCreerAffaire, SourceIDs: in.SourceIDs, Justification: in.Justification, Citation: in.Citation,
		Donnees: db.PropositionDonnees{Titre: in.Titre, Localisation: in.Localisation, ActionFoncia: in.ActionFoncia, Responsable: in.Responsable, DateSignalement: in.DateSignalement},
	}, true)
}

type commentaireInput struct {
	AffaireID string `json:"affaire_id"`
	Texte     string `json:"texte" jsonschema:"Le commentaire, factuel, une à trois phrases."`
	commun
}

func (b brainServer) proposerCommentaire(ctx context.Context, _ *mcp.CallToolRequest, in commentaireInput) (*mcp.CallToolResult, propositionOutput, error) {
	if strings.TrimSpace(in.Texte) == "" {
		return nil, propositionOutput{}, fmt.Errorf("texte est vide")
	}
	return b.proposer(ctx, db.PropositionDB{Action: db.PropCommenter, AffaireID: in.AffaireID, SourceIDs: in.SourceIDs, Justification: in.Justification, Citation: in.Citation, Donnees: db.PropositionDonnees{Texte: in.Texte}}, false)
}

type relanceInput struct {
	AffaireID string `json:"affaire_id"`
	Date      string `json:"date" jsonschema:"JJ/MM/AAAA."`
	Note      string `json:"note,omitempty" jsonschema:"Qui a relancé qui, par quel moyen."`
	commun
}

func (b brainServer) proposerRelance(ctx context.Context, _ *mcp.CallToolRequest, in relanceInput) (*mcp.CallToolResult, propositionOutput, error) {
	return b.proposer(ctx, db.PropositionDB{Action: db.PropRelancer, AffaireID: in.AffaireID, SourceIDs: in.SourceIDs, Justification: in.Justification, Citation: in.Citation, Donnees: db.PropositionDonnees{Date: in.Date, Note: in.Note}}, false)
}

type leveeInput struct {
	AffaireID string `json:"affaire_id"`
	commun
}

func (b brainServer) proposerLevee(ctx context.Context, _ *mcp.CallToolRequest, in leveeInput) (*mcp.CallToolResult, propositionOutput, error) {
	return b.proposer(ctx, db.PropositionDB{Action: db.PropLever, AffaireID: in.AffaireID, SourceIDs: in.SourceIDs, Justification: in.Justification, Citation: in.Citation}, false)
}

func (b brainServer) proposerEcarter(ctx context.Context, _ *mcp.CallToolRequest, in commun) (*mcp.CallToolResult, propositionOutput, error) {
	return b.proposer(ctx, db.PropositionDB{Action: db.PropIgnorer, SourceIDs: in.SourceIDs, Justification: in.Justification, Citation: in.Citation}, true)
}
