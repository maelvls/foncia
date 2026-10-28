package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startMCP serves /mcp like ServeHTTP does and returns a client session
// connected to it with an access token obtained through OAuth.
func startMCP(t *testing.T, sqlDB *sql.DB) *mcp.ClientSession {
	t.Helper()
	srv := newMCPServer(t, sqlDB)
	tokens := obtainTokens(t, srv)

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:   srv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: withBearer(tokens.AccessToken)},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

const testUser = "coowner@example.com"

// newMCPServer mounts the MCP and OAuth endpoints like ServeHTTP does. The
// browser routes (subMux) are wrapped the way Caddy does it: it logs the user
// in and sets X-Token-User-Email, unless the request has the header
// "Test-Not-Logged-In".
func newMCPServer(t *testing.T, sqlDB *sql.DB) *httptest.Server {
	t.Helper()
	rootMux, subMux := http.NewServeMux(), http.NewServeMux()
	srv := httptest.NewServer(rootMux) // Started first: the issuer is its URL.
	t.Cleanup(srv.Close)

	addOAuthHandlers(rootMux, subMux, oauthServer{
		sqlDB:      sqlDB,
		issuer:     srv.URL,
		userHeader: "X-Token-User-Email",
	}, newMCPHandler(mcpServer{
		sqlDB:       sqlDB,
		client:      failingClient(t),
		uuid:        "some-uuid",
		invoicesDir: t.TempDir(),
		baseURL:     "https://suivi.example.com",
		lastSync: func() (time.Time, error) {
			return time.Date(2024, 7, 1, 12, 0, 0, 0, time.UTC), nil
		},
	}))
	rootMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Token-User-Email")
		if r.Header.Get("Test-Not-Logged-In") == "" {
			r.Header.Set("X-Token-User-Email", testUser)
		}
		subMux.ServeHTTP(w, r)
	}))
	return srv
}

func withBearer(token string) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+token)
		return http.DefaultTransport.RoundTrip(r)
	})
}

// callTool calls a tool and decodes its structured output into out.
func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any, out any) *mcp.CallToolResult {
	t.Helper()
	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	if res.IsError || out == nil {
		return res
	}
	b, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, out))
	return res
}

func toolError(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	require.True(t, res.IsError, "the tool was expected to fail")
	require.NotEmpty(t, res.Content)
	return res.Content[0].(*mcp.TextContent).Text
}

func TestMCP_ListTools(t *testing.T) {
	session := startMCP(t, openTestDB(t))

	res, err := session.ListTools(t.Context(), nil)
	require.NoError(t, err)

	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		assert.True(t, tool.Annotations.ReadOnlyHint, "%s should be read-only", tool.Name)
	}
	assert.ElementsMatch(t, []string{"search", "read_document", "list_coowners", "sync_status"}, names)
	assert.Contains(t, session.InitializeResult().Instructions, "Terra Nostra 2")
}

func seedForSearch(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	seedExpenseWithFile(t, sqlDB, "66eda6344b41c38804f77fc1", "", "facture-2024-09.pdf", "%PDF-1.4")
	require.NoError(t, db.UpsertExpensesWithDB(t.Context(), sqlDB, db.ExpenseDocumentDB{
		Label:  "VIRT SMABTP 04/03/2024 ELECTRICITE",
		Amount: db.Amount(-350000),
		Date:   time.Date(2024, 3, 4, 21, 59, 59, 0, time.UTC),
		Source: db.SourceAccounting,
	}))
	require.NoError(t, db.SaveMissionsToDB(t.Context(), sqlDB, db.MissionDB{
		ID:          "64850e8019d5d64c415d13dd",
		Number:      "7000YRK51",
		Kind:        "Incident",
		Label:       "FUITE PLAFOND PARKING",
		Status:      "WORK_IN_PROGRESS",
		StartedAt:   time.Date(2023, 4, 24, 22, 0, 0, 0, time.UTC), // The 25th in Paris.
		Description: "Fuite au-dessus de la place 44",
	}))
	require.NoError(t, db.UpsertAccountDocumentsWithDB(t.Context(), sqlDB, []db.AccountDocumentDB{{
		ID:        "64850e8057dcdd65a89cc462",
		HashFile:  "64850e8057dcdd65a89cc462",
		FilePath:  "reports/CRvisite_0290-4661_202210131015.pdf",
		MimeType:  "application/pdf",
		Category:  db.DocumentCategoryReportVisit,
		CreatedAt: time.Date(2022, 10, 13, 8, 15, 0, 0, time.UTC),
	}}))
}

func TestMCP_Search(t *testing.T) {
	sqlDB := openTestDB(t)
	seedForSearch(t, sqlDB)
	session := startMCP(t, sqlDB)

	t.Run("everything, newest first", func(t *testing.T) {
		var out searchOutput
		callTool(t, session, "search", map[string]any{}, &out)

		require.Equal(t, 4, out.Total)
		var types []string
		for _, item := range out.Items {
			types = append(types, item.Type)
		}
		assert.Equal(t, []string{"expense", "expense", "mission", "visit_report"}, types)
	})

	t.Run("the query ignores case and accents", func(t *testing.T) {
		var out searchOutput
		callTool(t, session, "search", map[string]any{"query": "électricité"}, &out)

		require.Equal(t, 1, out.Total)
		item := out.Items[0]
		assert.Equal(t, "VIRT SMABTP 04/03/2024 ELECTRICITE", item.Title)
		assert.Equal(t, "2024-03-04", item.Date)
		require.NotNil(t, item.AmountEUR)
		assert.Equal(t, -3500.0, *item.AmountEUR)
		assert.Equal(t, "-3500,00 €", item.Amount)
		assert.Nil(t, item.Document, "no file on disk, so no document")
	})

	t.Run("every word must match", func(t *testing.T) {
		var out searchOutput
		callTool(t, session, "search", map[string]any{"query": "fuite 44"}, &out)
		require.Equal(t, 1, out.Total)
		assert.Equal(t, "mission", out.Items[0].Type)
		assert.Equal(t, "2023-04-25", out.Items[0].Date, "dates are in Paris time")
		assert.Equal(t, "https://suivi.example.com/#64850e8019d5d64c415d13dd", out.Items[0].URL)

		callTool(t, session, "search", map[string]any{"query": "fuite 45"}, &out)
		assert.Equal(t, 0, out.Total)
		assert.NotNil(t, out.Items, "items must be [] rather than null")
	})

	t.Run("types and dates", func(t *testing.T) {
		var out searchOutput
		callTool(t, session, "search", map[string]any{"types": []string{"expense", "visit_report"}, "until": "2024-03-31"}, &out)

		require.Equal(t, 2, out.Total)
		assert.Equal(t, "expense", out.Items[0].Type)
		assert.Equal(t, "visit_report", out.Items[1].Type)
		assert.Equal(t, &mcpDocument{
			ID:       "doc/64850e8057dcdd65a89cc462",
			Filename: "CRvisite_0290-4661_202210131015.pdf",
			URL:      "https://suivi.example.com/dl/doc/64850e8057dcdd65a89cc462/CRvisite_0290-4661_202210131015.pdf",
		}, out.Items[1].Document)
	})

	t.Run("the invoice of an expense", func(t *testing.T) {
		var out searchOutput
		callTool(t, session, "search", map[string]any{"query": "smf"}, &out)

		require.Equal(t, 1, out.Total)
		require.NotNil(t, out.Items[0].Document)
		assert.Equal(t, "invoice/66eda6344b41c38804f77fc1", out.Items[0].Document.ID)
	})

	t.Run("limit and offset", func(t *testing.T) {
		var out searchOutput
		callTool(t, session, "search", map[string]any{"limit": 1, "offset": 2}, &out)

		assert.Equal(t, 4, out.Total)
		require.Len(t, out.Items, 1)
		assert.Equal(t, "mission", out.Items[0].Type)
	})

	t.Run("an unknown type is an error", func(t *testing.T) {
		res := callTool(t, session, "search", map[string]any{"types": []string{"invoice"}}, nil)
		assert.Contains(t, toolError(t, res), `unknown type "invoice"`)
	})

	t.Run("a malformed date is an error", func(t *testing.T) {
		res := callTool(t, session, "search", map[string]any{"since": "04/03/2024"}, nil)
		assert.Contains(t, toolError(t, res), "YYYY-MM-DD")
	})
}

func TestMCP_ReadDocument(t *testing.T) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("pdftotext isn't installed; it comes with poppler-utils")
	}
	const hash = "66eda6344b41c38804f77fc1"
	sqlDB := openTestDB(t)
	filePath := filepath.Join(t.TempDir(), "facture.pdf")
	require.NoError(t, os.WriteFile(filePath, minimalPDF("FACTURE ASCENSEUR", "TOTAL 410,49"), 0o600))
	require.NoError(t, db.UpsertExpensesWithDB(t.Context(), sqlDB, db.ExpenseDocumentDB{
		Label:    "SARL SMF SERVICES - CONTRAT MAINTENANCE",
		Amount:   db.Amount(41049),
		Date:     time.Date(2024, 9, 20, 16, 43, 33, 0, time.UTC),
		FilePath: filePath,
		HashFile: db.HashFile(hash),
		Source:   db.SourceAccounting,
	}))
	session := startMCP(t, sqlDB)

	t.Run("the whole text", func(t *testing.T) {
		var out readDocumentOutput
		callTool(t, session, "read_document", map[string]any{"document": "invoice/" + hash}, &out)

		assert.Equal(t, 2, out.Pages)
		assert.Contains(t, out.Text, "--- page 1 ---\nFACTURE ASCENSEUR")
		assert.Contains(t, out.Text, "--- page 2 ---\nTOTAL 410,49")
		assert.Equal(t, "facture.pdf", out.Filename)
		assert.Equal(t, "https://suivi.example.com/dl/invoice/"+hash+"/facture.pdf", out.URL)
		assert.Zero(t, out.NextOffset)
	})

	t.Run("in several parts, given the url", func(t *testing.T) {
		var first, second readDocumentOutput
		callTool(t, session, "read_document", map[string]any{"document": "https://suivi.example.com/dl/invoice/" + hash + "/facture.pdf", "max_chars": 10}, &first)
		require.Equal(t, 10, first.NextOffset)
		callTool(t, session, "read_document", map[string]any{"document": "invoice/" + hash, "offset": first.NextOffset, "max_chars": 1000}, &second)

		assert.Equal(t, first.TotalChars, len([]rune(first.Text+second.Text)))
		assert.Contains(t, first.Text+second.Text, "TOTAL 410,49")
	})

	t.Run("unknown document", func(t *testing.T) {
		res := callTool(t, session, "read_document", map[string]any{"document": "invoice/000000000000000000000000"}, nil)
		assert.Contains(t, toolError(t, res), "no expense with hash file")
	})

	t.Run("not a document id", func(t *testing.T) {
		res := callTool(t, session, "read_document", map[string]any{"document": "facture.pdf"}, nil)
		assert.Contains(t, toolError(t, res), "isn't a document id")
	})
}

func TestMCP_SyncStatus(t *testing.T) {
	sqlDB := openTestDB(t)
	seedForSearch(t, sqlDB)
	session := startMCP(t, sqlDB)

	var out syncStatusOutput
	callTool(t, session, "sync_status", map[string]any{}, &out)

	assert.Equal(t, "2024-07-01T14:00:00+02:00", out.LastSync)
	assert.Empty(t, out.Error)
	assert.Equal(t, map[string]int{"mission": 1, "expense": 2, "visit_report": 1, "general_assembly": 0, "other_document": 0}, out.Counts)
	assert.Equal(t, "2022-10-13", out.Oldest)
	assert.Equal(t, "2024-09-20", out.Newest)
}

func TestParseDocumentID(t *testing.T) {
	for in, want := range map[string]string{
		"doc/abc":                       "doc abc",
		"/dl/contract/abc/contrat.pdf":  "contract abc",
		"https://x.dev/dl/invoiceid/a1": "invoiceid a1",
		" invoice/abc/ ":                "invoice abc",
	} {
		typ, id, err := parseDocumentID(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, typ+" "+id, in)
	}
	for _, in := range []string{"", "abc", "doc/", "nonsense/abc"} {
		_, _, err := parseDocumentID(in)
		assert.Error(t, err, in)
	}
}

// minimalPDF writes a PDF with one line of text per page, with a correct
// cross-reference table since the PDF library needs one.
func minimalPDF(lines ...string) []byte {
	var objs []string
	kids := ""
	for i := range lines {
		kids += fmt.Sprintf("%d 0 R ", 4+2*i)
	}
	objs = append(objs,
		"<< /Type /Catalog /Pages 2 0 R >>",
		fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids, len(lines)),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	)
	for i, line := range lines {
		stream := fmt.Sprintf("BT /F1 12 Tf 72 720 Td (%s) Tj ET", line)
		objs = append(objs,
			fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", 5+2*i),
			fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream),
		)
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, o := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}
