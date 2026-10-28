package main

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"path"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // The alpine base image may not have /usr/share/zoneinfo.

	"github.com/maelvls/foncia/db"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The MCP server (https://modelcontextprotocol.io) served on /mcp lets AI
// assistants (Claude, ChatGPT, Grok) read what the web UI shows: missions,
// expenses, documents and co-owners. It only reads.
//
// The clients get their access token from the OAuth 2.1 authorization server
// in http_oauth.go, which also checks it on every request.

const mcpInstructions = `Données de la copropriété Terra Nostra 2 (syndic Foncia), synchronisées toutes les 10 minutes depuis l'espace copropriétaire Foncia, comme sur https://suivi-terra-nostra-2.vls.dev. Les éléments que Foncia ne renvoie plus sont gardés.

- "mission" : une intervention demandée au syndic (incident ou travaux), avec ses ordres de service et les fournisseurs.
- "expense" : une dépense ou un crédit de la comptabilité de l'immeuble, souvent avec la facture en PDF.
- "visit_report" : un rapport de visite de l'immeuble par le gestionnaire.
- "general_assembly" : une convocation, un procès-verbal ou une annexe d'assemblée générale.

Utilise search pour trouver des éléments, puis read_document avec l'identifiant de document renvoyé pour lire le PDF. Les liens (url) demandent une connexion Google sur le site.`

// mcpItemType is the "type" of an item returned by the search tool.
const (
	mcpTypeMission         = "mission"
	mcpTypeExpense         = "expense"
	mcpTypeVisitReport     = "visit_report"
	mcpTypeGeneralAssembly = "general_assembly"
	mcpTypeOtherDocument   = "other_document"
)

var mcpTypes = []string{mcpTypeMission, mcpTypeExpense, mcpTypeVisitReport, mcpTypeGeneralAssembly, mcpTypeOtherDocument}

// Dates are shown in Paris time: Foncia stores "the 25th of April" as
// "2023-04-24T22:00:00.000Z".
var paris = func() *time.Location {
	loc, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		panic(err)
	}
	return loc
}()

type mcpServer struct {
	sqlDB       *sql.DB
	client      *http.Client
	uuid        string
	invoicesDir string
	baseURL     string // Example: "https://suivi-terra-nostra-2.vls.dev", with the base path.
	lastSync    func() (time.Time, error)
}

// newMCPHandler returns the handler for /mcp. It doesn't check who is asking:
// see oauthServer.requireToken.
func newMCPHandler(s mcpServer) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "foncia",
		Title:   "Suivi Terra Nostra 2",
		Version: version,
	}, &mcp.ServerOptions{Instructions: mcpInstructions})

	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(false)}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search",
		Title:       "Chercher dans le suivi Foncia",
		Description: "Search the missions (interventions), expenses (invoices, credits) and documents (visit reports, general assembly documents) of the building, newest first. Every word of the query must appear, case and accent insensitive, in the title, description, supplier, accounting key or file name. The text is in French, mostly upper case.",
		Annotations: readOnly,
	}, s.search)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_document",
		Title:       "Lire un document",
		Description: "Return the text of a PDF (invoice, contract, visit report, general assembly document) found with search. Long documents are returned in several parts: call again with offset set to next_offset. Scanned PDFs have no text; give the user the url instead.",
		Annotations: readOnly,
	}, s.readDocument)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_coowners",
		Title:       "Lister les copropriétaires",
		Description: "List the co-owners of the building with their postal address, apartment (e.g. C02, D11) and parking spaces, as Foncia knows them right now. This is personal data: only use it when the user asks about a co-owner.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(true)},
	}, s.listCoowners)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "sync_status",
		Title:       "État de la synchro",
		Description: "Tell when the data was last synchronized with Foncia, whether that failed, and how many items of each type there are.",
		Annotations: readOnly,
	}, s.syncStatus)

	// Stateless: there is no session to keep between two requests, which
	// suits the reverse proxy in front of us and survives restarts.
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
	})
}

// -----------------------------------------------------------------------------
// search
// -----------------------------------------------------------------------------

type searchInput struct {
	Query  string   `json:"query,omitempty" jsonschema:"Words that must all appear, e.g. 'ascenseur' or 'fuite C02'. Empty matches everything."`
	Types  []string `json:"types,omitempty" jsonschema:"Only these types: mission, expense, visit_report, general_assembly, other_document. Empty means all."`
	Since  string   `json:"since,omitempty" jsonschema:"Only items on or after this date, YYYY-MM-DD."`
	Until  string   `json:"until,omitempty" jsonschema:"Only items on or before this date, YYYY-MM-DD."`
	Limit  int      `json:"limit,omitempty" jsonschema:"Maximum number of items, 50 by default, at most 200."`
	Offset int      `json:"offset,omitempty" jsonschema:"Number of matching items to skip, to get the next page."`
}

type searchOutput struct {
	Total int       `json:"total" jsonschema:"Number of matching items, regardless of limit and offset."`
	Items []mcpItem `json:"items"`
}

type mcpItem struct {
	Type  string `json:"type" jsonschema:"mission, expense, visit_report, general_assembly or other_document."`
	ID    string `json:"id,omitempty"`
	Date  string `json:"date" jsonschema:"YYYY-MM-DD, Paris time. Start date for a mission."`
	Title string `json:"title"`
	URL   string `json:"url" jsonschema:"The item in the web UI."`

	// Missions.
	Number      string         `json:"number,omitempty"`
	Kind        string         `json:"kind,omitempty" jsonschema:"In French, e.g. Incident, Travaux, Ticket."`
	Status      string         `json:"status,omitempty"`
	Description string         `json:"description,omitempty"`
	WorkOrders  []mcpWorkOrder `json:"work_orders,omitempty"`

	// Expenses.
	AmountEUR   *float64 `json:"amount_eur,omitempty" jsonschema:"Positive for a charge (debit), negative for a credit."`
	Amount      string   `json:"amount,omitempty" jsonschema:"The same amount, written the French way."`
	Allocation  string   `json:"allocation,omitempty" jsonschema:"Accounting allocation, e.g. CHARGES ASCENSEUR D."`
	ExpenseType string   `json:"expense_type,omitempty" jsonschema:"e.g. CONTRAT ETENDU ASCENSEUR."`

	// Documents.
	Category string `json:"category,omitempty"`

	Document *mcpDocument `json:"document,omitempty" jsonschema:"The PDF: the invoice of an expense, or the document itself."`
}

type mcpWorkOrder struct {
	Number           string        `json:"number"`
	Label            string        `json:"label"`
	RepairDate       string        `json:"repair_date,omitempty" jsonschema:"YYYY-MM-DD."`
	Supplier         string        `json:"supplier,omitempty"`
	SupplierActivity string        `json:"supplier_activity,omitempty"`
	Contracts        []mcpDocument `json:"contracts,omitempty" jsonschema:"The supplier's contracts."`
}

type mcpDocument struct {
	ID       string `json:"id" jsonschema:"Give it to read_document."`
	Filename string `json:"filename,omitempty"`
	URL      string `json:"url" jsonschema:"Download link, needs a Google login on the site."`
}

func (s mcpServer) search(ctx context.Context, _ *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, searchOutput, error) {
	for _, t := range in.Types {
		if !slices.Contains(mcpTypes, t) {
			return nil, searchOutput{}, fmt.Errorf("unknown type %q, must be one of %s", t, strings.Join(mcpTypes, ", "))
		}
	}
	for _, d := range []string{in.Since, in.Until} {
		if _, err := time.Parse(time.DateOnly, d); d != "" && err != nil {
			return nil, searchOutput{}, fmt.Errorf("dates must be YYYY-MM-DD, got %q", d)
		}
	}
	if in.Limit <= 0 {
		in.Limit = 50
	}
	in.Limit = min(in.Limit, 200)
	in.Offset = max(in.Offset, 0)
	words := strings.Fields(foldText(in.Query))

	all, err := fetchFromDB(ctx, s.sqlDB, filter{})
	if err != nil {
		return nil, searchOutput{}, err
	}

	out := searchOutput{Items: []mcpItem{}}
	for _, e := range all {
		item, haystack := s.toItem(e)
		if len(in.Types) > 0 && !slices.Contains(in.Types, item.Type) {
			continue
		}
		if (in.Since != "" && item.Date < in.Since) || (in.Until != "" && item.Date > in.Until) {
			continue
		}
		if !containsAll(foldText(haystack), words) {
			continue
		}
		out.Total++
		if out.Total > in.Offset && len(out.Items) < in.Limit {
			out.Items = append(out.Items, item)
		}
	}
	return nil, out, nil
}

// toItem converts a row of the web UI into an item, and returns along with it
// the text that the query is matched against.
func (s mcpServer) toItem(e MissionOrExpense) (mcpItem, string) {
	switch {
	case e.Mission != nil:
		m := e.Mission
		item := mcpItem{
			Type:        mcpTypeMission,
			ID:          m.ID,
			Date:        parisDate(m.StartedAt),
			Title:       strings.TrimSpace(m.Label),
			URL:         s.baseURL + "/#" + m.ID,
			Number:      m.Number,
			Kind:        m.KindFrench(),
			Status:      m.StatusFrench(),
			Description: strings.TrimSpace(m.Description),
		}
		haystack := []string{m.Label, m.Number, m.Description, item.Kind, item.Status}
		for _, wo := range m.WorkOrders {
			w := mcpWorkOrder{
				Number:           wo.Number,
				Label:            strings.TrimSpace(wo.Label),
				RepairDate:       parisDate(wo.RepairDateEnd),
				Supplier:         wo.Supplier.Name,
				SupplierActivity: wo.Supplier.Activity,
			}
			for _, c := range wo.Supplier.Documents {
				if c.HashFile != "" && c.FilePath != "" {
					w.Contracts = append(w.Contracts, s.document("contract", string(c.HashFile), path.Base(c.FilePath)))
				}
			}
			item.WorkOrders = append(item.WorkOrders, w)
			haystack = append(haystack, wo.Number, wo.Label, wo.Supplier.Name)
		}
		return item, strings.Join(haystack, " ")

	case e.Expense != nil:
		x := e.Expense
		amount := float64(x.Amount) / 100
		// Expenses have no ID of their own; this is the anchor that the web
		// UI uses, and it may be shared by several expenses.
		anchor := cmp.Or(string(x.HashFile), x.InvoiceID)
		item := mcpItem{
			Type:        mcpTypeExpense,
			ID:          anchor,
			Date:        parisDate(x.Date),
			Title:       strings.TrimSpace(x.Label),
			URL:         s.baseURL + "/#" + anchor,
			AmountEUR:   &amount,
			Amount:      x.Amount.String(),
			Allocation:  x.AccountingKey.Allocation,
			ExpenseType: x.AccountingKey.ExpenseType,
		}
		if anchor == "" {
			item.URL = s.baseURL + "/"
		}
		// Same rule as the web UI: the link only works once the file is on
		// disk.
		if x.FilePath != "" {
			switch {
			case x.HashFile != "":
				item.Document = new(s.document("invoice", string(x.HashFile), x.Filename()))
			case x.InvoiceID != "":
				item.Document = new(s.document("invoiceid", x.InvoiceID, x.Filename()))
			}
		}
		return item, strings.Join([]string{x.Label, x.AccountingKey.Allocation, x.AccountingKey.ExpenseType, x.Filename(), item.Amount}, " ")

	default:
		d := e.AccountDocument
		item := mcpItem{
			Type:     mcpTypeOtherDocument,
			ID:       d.ID,
			Date:     parisDate(d.CreatedAt),
			Title:    d.CategoryFrench(),
			URL:      s.baseURL + "/#" + d.ID,
			Category: d.CategoryFrench(),
		}
		switch {
		case d.Category == db.DocumentCategoryReportVisit:
			item.Type = mcpTypeVisitReport
		case d.IsGeneralAssembly():
			item.Type = mcpTypeGeneralAssembly
		}
		if d.FilePath != "" {
			item.Title = d.Filename()
		}
		// Not on disk yet is fine: read_document downloads it, like the web
		// UI does.
		if d.HashFile != "" {
			item.Document = new(s.document("doc", string(d.HashFile), d.Filename()))
		}
		return item, strings.Join([]string{d.CategoryFrench(), d.Filename()}, " ")
	}
}

func (s mcpServer) document(typ, id, filename string) mcpDocument {
	if filename == "." {
		filename = ""
	}
	u := s.baseURL + "/dl/" + typ + "/" + id
	if filename != "" {
		u += "/" + url.PathEscape(filename)
	}
	return mcpDocument{ID: typ + "/" + id, Filename: filename, URL: u}
}

// -----------------------------------------------------------------------------
// read_document
// -----------------------------------------------------------------------------

type readDocumentInput struct {
	Document string `json:"document" jsonschema:"The document id given by search, e.g. doc/64850e8057dcdd65a89cc462, or its url."`
	Offset   int    `json:"offset,omitempty" jsonschema:"Character to start at; use next_offset from the previous call."`
	MaxChars int    `json:"max_chars,omitempty" jsonschema:"Maximum number of characters, 20000 by default, at most 100000."`
}

type readDocumentOutput struct {
	Filename   string `json:"filename"`
	URL        string `json:"url"`
	Pages      int    `json:"pages"`
	TotalChars int    `json:"total_chars"`
	Offset     int    `json:"offset"`
	NextOffset int    `json:"next_offset,omitempty" jsonschema:"Where the rest starts; absent once the end is reached."`
	Text       string `json:"text" jsonschema:"Pages are separated by lines like '--- page 2 ---'."`
	Note       string `json:"note,omitempty"`
}

func (s mcpServer) readDocument(ctx context.Context, _ *mcp.CallToolRequest, in readDocumentInput) (*mcp.CallToolResult, readDocumentOutput, error) {
	typ, id, err := parseDocumentID(in.Document)
	if err != nil {
		return nil, readDocumentOutput{}, err
	}
	if in.MaxChars <= 0 {
		in.MaxChars = 20000
	}
	in.MaxChars = min(in.MaxChars, 100000)
	in.Offset = max(in.Offset, 0)

	filePath, err := resolveDocument(ctx, s.sqlDB, s.client, s.invoicesDir, typ, id)
	if err != nil {
		return nil, readDocumentOutput{}, fmt.Errorf("document %s/%s: %w", typ, id, err)
	}
	doc := s.document(typ, id, path.Base(filePath))
	out := readDocumentOutput{Filename: doc.Filename, URL: doc.URL, Offset: in.Offset}

	pages, err := pdfPages(ctx, filePath)
	if err != nil {
		return nil, readDocumentOutput{}, fmt.Errorf("while reading the text of %s: %w", doc.Filename, err)
	}
	out.Pages = len(pages)

	var b strings.Builder
	words := 0
	for i, p := range pages {
		if len(pages) > 1 {
			fmt.Fprintf(&b, "--- page %d ---\n", i+1)
		}
		b.WriteString(p)
		b.WriteString("\n")
		words += len(strings.Fields(p))
	}
	runes := []rune(b.String())
	out.TotalChars = len(runes)

	// A scanned page has no text at all, or just a stamp or a page number.
	if words <= 3*len(pages) {
		out.Note = "Ce PDF ne contient pas (ou presque pas) de texte : c'est sans doute un scan. Donne le lien à l'utilisateur."
	}
	if in.Offset < len(runes) {
		end := min(in.Offset+in.MaxChars, len(runes))
		out.Text = string(runes[in.Offset:end])
		if end < len(runes) {
			out.NextOffset = end
		}
	}
	return nil, out, nil
}

// parseDocumentID accepts "doc/<id>", "/dl/doc/<id>/<filename>" and the full
// URL of a document.
func parseDocumentID(s string) (typ, id string, _ error) {
	s = strings.TrimSpace(s)
	if _, after, found := strings.Cut(s, "/dl/"); found {
		s = after
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) < 2 || parts[1] == "" {
		return "", "", fmt.Errorf("%q isn't a document id: expected something like doc/64850e8057dcdd65a89cc462, as given by search", s)
	}
	if _, known := documentLookups[parts[0]]; !known {
		return "", "", fmt.Errorf("%q isn't a document id: it must start with invoice/, invoiceid/, contract/ or doc/", s)
	}
	return parts[0], parts[1], nil
}

// pdfPages extracts the text of each page of a PDF with pdftotext, from
// poppler-utils. The pure-Go PDF libraries return gibberish for the general
// assembly documents, whose fonts are Type 3 fonts with a custom encoding.
func pdfPages(ctx context.Context, filePath string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "pdftotext", "-enc", "UTF-8", filePath, "-")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if errors.Is(err, exec.ErrNotFound) {
		return nil, fmt.Errorf("pdftotext isn't installed, it comes with poppler-utils")
	}
	if err != nil {
		return nil, fmt.Errorf("pdftotext: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	// Every page ends with a form feed, so the last element is empty.
	pages := strings.Split(strings.TrimSuffix(string(out), "\f"), "\f")
	for i := range pages {
		pages[i] = strings.TrimSpace(pages[i])
	}
	return pages, nil
}

// -----------------------------------------------------------------------------
// list_coowners and sync_status
// -----------------------------------------------------------------------------

type listCoownersOutput struct {
	Coowners []coownerRow `json:"coowners"`
}

func (s mcpServer) listCoowners(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, listCoownersOutput, error) {
	coowners, err := fetchCoowners(ctx, s.client, s.uuid)
	if err != nil {
		return nil, listCoownersOutput{}, fmt.Errorf("while asking Foncia for the co-owners: %w", err)
	}
	if coowners == nil {
		coowners = []coownerRow{}
	}
	return nil, listCoownersOutput{Coowners: coowners}, nil
}

type syncStatusOutput struct {
	LastSync string         `json:"last_sync,omitempty" jsonschema:"RFC 3339, Paris time. Absent if no synchronization was done since the server started."`
	Error    string         `json:"error,omitempty" jsonschema:"Why the last synchronization failed."`
	Counts   map[string]int `json:"counts" jsonschema:"Number of items per type."`
	Oldest   string         `json:"oldest,omitempty" jsonschema:"Date of the oldest item, YYYY-MM-DD."`
	Newest   string         `json:"newest,omitempty" jsonschema:"Date of the newest item, YYYY-MM-DD."`
}

func (s mcpServer) syncStatus(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, syncStatusOutput, error) {
	all, err := fetchFromDB(ctx, s.sqlDB, filter{})
	if err != nil {
		return nil, syncStatusOutput{}, err
	}

	out := syncStatusOutput{Counts: map[string]int{}}
	for _, t := range mcpTypes {
		out.Counts[t] = 0
	}
	for _, e := range all {
		item, _ := s.toItem(e)
		out.Counts[item.Type]++
		if out.Newest == "" || item.Date > out.Newest {
			out.Newest = item.Date
		}
		if out.Oldest == "" || item.Date < out.Oldest {
			out.Oldest = item.Date
		}
	}

	when, syncErr := s.lastSync()
	if !when.IsZero() {
		out.LastSync = when.In(paris).Format(time.RFC3339)
	}
	if syncErr != nil {
		out.Error = syncErr.Error()
	}
	return nil, out, nil
}

// -----------------------------------------------------------------------------
// Helpers.
// -----------------------------------------------------------------------------

func parisDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(paris).Format(time.DateOnly)
}

var accents = strings.NewReplacer(
	"à", "a", "â", "a", "ä", "a", "ç", "c", "é", "e", "è", "e", "ê", "e", "ë", "e",
	"î", "i", "ï", "i", "ô", "o", "ö", "o", "ù", "u", "û", "u", "ü", "u", "ÿ", "y",
	"œ", "oe", "æ", "ae",
)

// foldText lower-cases and removes the accents, so that "électricité" matches
// "ELECTRICITE".
func foldText(s string) string {
	return accents.Replace(strings.ToLower(s))
}

func containsAll(haystack string, words []string) bool {
	for _, w := range words {
		if !strings.Contains(haystack, w) {
			return false
		}
	}
	return true
}
