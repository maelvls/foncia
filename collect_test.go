package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	sqlDB, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	old := *filesDir
	*filesDir = t.TempDir()
	t.Cleanup(func() { *filesDir = old })
	return sqlDB
}

func b64(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) }

func TestGmail(t *testing.T) {
	sqlDB := testDB(t)
	logo := strings.Repeat("x", 3000) // A signature logo: too small to keep.
	devis := "%PDF-1.4 " + strings.Repeat("devis ", 5000)
	msgs := map[string]any{
		"m1": map[string]any{
			"id": "m1", "threadId": "t1", "internalDate": "1794787200000",
			"payload": map[string]any{
				"mimeType": "multipart/mixed",
				"headers": []map[string]string{
					{"name": "From", "value": "=?UTF-8?Q?Jean_Gestion?= <gestionnaire@foncia.example>"},
					{"name": "To", "value": "moi@example.com"},
					{"name": "Cc", "value": "Alice <alice@example.com>"},
					{"name": "Subject", "value": "=?UTF-8?Q?Devis_=C3=A9tanch=C3=A9it=C3=A9_C02?="},
				},
				"parts": []map[string]any{
					{"mimeType": "multipart/alternative", "parts": []map[string]any{
						{"mimeType": "text/plain", "body": map[string]any{"data": b64("Bonjour,\r\n\r\nCi-joint le devis.\r\n\r\n\r\n\r\nCordialement\r\n\r\nLe 10/11/2026 à 09:00, Maël Valais a écrit :\r\n> Avez-vous le devis ?\r\n")}},
						{"mimeType": "text/html", "body": map[string]any{"data": b64("<p>Bonjour</p>")}},
					}},
					{"mimeType": "application/pdf", "filename": "Devis 42.pdf", "body": map[string]any{"attachmentId": "a1", "size": len(devis)}},
					{"mimeType": "image/png", "filename": "logo.png", "body": map[string]any{"attachmentId": "a2", "size": len(logo)}},
				},
			},
		},
		"m2": map[string]any{
			"id": "m2", "threadId": "t2", "internalDate": "1794873600000",
			"payload": map[string]any{
				"mimeType": "text/html",
				"headers":  []map[string]string{{"name": "From", "value": "noreply@foncia.com"}, {"name": "Subject", "value": "Ordre de service"}},
				"body":     map[string]any{"data": b64("<html><head><style>p{}</style></head><body><p>Objet&nbsp;: Commande&nbsp;1 vigik</p><div>Merci</div></body></html>")},
			},
		},
	}
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/messages":
			queries = append(queries, r.URL.Query().Get("q"))
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]string{{"id": "m2"}, {"id": "m1"}}})
		case r.URL.Path == "/messages/m1/attachments/a1":
			_ = json.NewEncoder(w).Encode(map[string]string{"data": b64(devis)})
		case r.URL.Path == "/messages/m1/attachments/a2":
			t.Error("the logo must not be downloaded")
		case strings.HasPrefix(r.URL.Path, "/messages/"):
			_ = json.NewEncoder(w).Encode(msgs[strings.TrimPrefix(r.URL.Path, "/messages/")])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	g := &gmailCollecteur{sqlDB: sqlDB, client: srv.Client(), query: "from:foncia.com", account: "moi@example.com", api: srv.URL}

	n, err := g.collecter(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	require.Len(t, queries, 1)
	assert.Contains(t, queries[0], "from:foncia.com after:")

	got, err := db.GetSources(t.Context(), sqlDB, db.SourcesFilter{Canal: db.CanalGmail})
	require.NoError(t, err)
	require.Len(t, got, 2)
	m1 := got[1]
	assert.Equal(t, "Devis étanchéité C02", m1.Sujet)
	assert.Equal(t, "Jean Gestion <gestionnaire@foncia.example>", m1.Auteur)
	assert.Equal(t, "moi@example.com, Alice <alice@example.com>", m1.Destinataires)
	assert.Equal(t, "Bonjour,\n\nCi-joint le devis.\n\nCordialement", m1.Texte, "the quoted message and the blank lines go")
	assert.Equal(t, "t1", m1.Fil)
	assert.Equal(t, "https://mail.google.com/mail/u/moi@example.com/#all/m1", m1.URL)
	require.Len(t, m1.Fichiers, 1)
	assert.Equal(t, "Devis 42.pdf", m1.Fichiers[0].NomDansMessage)
	assert.Equal(t, "application/pdf", m1.Fichiers[0].Mime)

	assert.Equal(t, "Objet : Commande 1 vigik\nMerci", got[0].Texte, "HTML-only mail")

	t.Run("a second run reads nothing again and starts after the last one", func(t *testing.T) {
		n, err := g.collecter(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 0, n)
		cur, _ := db.GetReglage(t.Context(), sqlDB, reglageGmailDepuis)
		assert.Equal(t, time.UnixMilli(1794873600000).UTC().Format(time.RFC3339), cur)
	})
}

func TestDecouperEchanges(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 9, 0, 0, 0, paris)
	m := func(min int, text string) waMessage {
		return waMessage{ID: text, Time: t0.Add(time.Duration(min) * time.Minute), Kind: "text", Text: text}
	}
	msgs := []waMessage{m(0, "a"), m(5, "b"), {ID: "r", Time: t0.Add(6 * time.Minute), Kind: "reaction"}, m(300, "c"), m(310, "d")}

	t.Run("the last exchange waits while people may still write", func(t *testing.T) {
		e, ouvert := decouperEchanges(msgs, 3*time.Hour, t0.Add(305*time.Minute))
		assert.True(t, ouvert)
		require.Len(t, e, 1)
		assert.Equal(t, []string{"a", "b"}, []string{e[0][0].Text, e[0][1].Text}, "the reaction is dropped")
	})

	t.Run("once quiet, it's recorded", func(t *testing.T) {
		e, ouvert := decouperEchanges(msgs, 3*time.Hour, t0.Add(24*time.Hour))
		assert.False(t, ouvert)
		require.Len(t, e, 2)
		assert.Equal(t, "c", e[1][0].Text)
	})
}

func TestWhatsapp(t *testing.T) {
	sqlDB := testDB(t)
	old := *sourcesSince
	*sourcesSince = "2026-11-01"
	t.Cleanup(func() { *sourcesSince = old })
	t0 := time.Date(2026, 11, 10, 9, 0, 0, 0, paris)
	at := func(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }
	photo := strings.Repeat("jpeg", 1000)
	served := map[string][]map[string]any{
		"cs@g.us": {
			{"id": "A", "sender_name": "Alice", "time": at(0), "kind": "text", "text": "Le portail est bloqué"},
			{"id": "B", "from_me": true, "time": at(3), "kind": "image", "text": "regardez", "mimetype": "image/jpeg", "size": len(photo)},
			{"id": "C", "sender_name": "Bruno", "time": at(4), "kind": "image", "mimetype": "image/jpeg", "size": 10},
		},
		"res@g.us": {
			{"id": "D", "sender_name": "Léa", "time": at(0), "kind": "text", "text": "Qui me prête la place 59 ?"},
			{"id": "E", "sender_name": "Paul", "time": at(400), "kind": "text", "text": "Le portail du garage reste ouvert"},
		},
		"33600@s.whatsapp.net": {{"id": "F", "sender_name": "Chloé", "time": at(0), "kind": "text", "text": "La VMC fait du bruit"}},
		"33700@s.whatsapp.net": {{"id": "G", "sender_name": "Maman", "time": at(0), "kind": "text", "text": "Bisous"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/internal/chats":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"jid": "cs@g.us", "name": "Conseil Syndical", "is_group": true},
				{"jid": "res@g.us", "name": "Residence Nostra", "is_group": true},
				{"jid": "33600@s.whatsapp.net", "name": "Chloé", "contact_name": "Chloé Martin (D04)"},
				{"jid": "33700@s.whatsapp.net", "name": "Maman", "contact_name": "Maman"},
			})
		case "/internal/messages":
			_ = json.NewEncoder(w).Encode(served[r.URL.Query().Get("chat")])
		case "/internal/media":
			if r.URL.Query().Get("id") == "C" {
				http.Error(w, "gone", http.StatusGone)
				return
			}
			_, _ = w.Write([]byte(photo))
		}
	}))
	t.Cleanup(srv.Close)
	*whatsappContacts = `\((prop |loc )?[A-D]\d{2}\)`
	w := &whatsappCollecteur{
		sqlDB: sqlDB, client: srv.Client(), base: srv.URL, token: func() (string, error) { return "tok", nil },
		chats: jidSet("cs@g.us"), filtered: jidSet("res@g.us"),
		now: func() time.Time { return t0.Add(48 * time.Hour) },
	}
	var err error
	w.contacts, err = regexp.Compile(*whatsappContacts)
	require.NoError(t, err)
	w.keywords, err = regexp.Compile(*whatsappKeywords)
	require.NoError(t, err)

	n, err := w.collecter(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 3, n, "the CS exchange, the neighbour, and the filtered message about the gate")

	got, err := db.GetSources(t.Context(), sqlDB, db.SourcesFilter{Canal: db.CanalWhatsApp})
	require.NoError(t, err)
	byChat := map[string]db.SourceDB{}
	for _, s := range got {
		byChat[s.Fil] = s
	}
	cs := byChat["cs@g.us"]
	assert.Equal(t, "Conseil Syndical", cs.FilTitre)
	assert.Equal(t, "Alice, Maël, Bruno", cs.Auteur)
	assert.Equal(t, "10/11 09:00 Alice : Le portail est bloqué\n09:03 Maël : [photo] regardez\n09:04 Bruno : [photo plus disponible sur WhatsApp]", cs.Texte)
	require.Len(t, cs.Fichiers, 1)
	assert.Equal(t, "image/jpeg", cs.Fichiers[0].Mime)

	assert.Equal(t, "Chloé Martin (D04)", byChat["33600@s.whatsapp.net"].FilTitre)
	assert.Contains(t, byChat["res@g.us"].Texte, "portail du garage")
	assert.NotContains(t, byChat["res@g.us"].Texte, "place 59")
	_, family := byChat["33700@s.whatsapp.net"]
	assert.False(t, family, "conversations not listed are never read")

	n, err = w.collecter(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "idempotent")
}

func TestBrainMCP(t *testing.T) {
	sqlDB := testDB(t)
	ctx := t.Context()
	a := nouvelleAffaire(t, sqlDB, 3, "VMC D04")
	s1, err := db.InsertSource(ctx, sqlDB, db.SourceDB{Canal: db.CanalGmail, ExtID: "x1", Fil: "t", Auteur: "ELECO", Texte: "Câbles changés", Date: time.Now().Add(-time.Hour)})
	require.NoError(t, err)
	s2, err := db.InsertSource(ctx, sqlDB, db.SourceDB{Canal: db.CanalWhatsApp, ExtID: "x2", Fil: "g", Auteur: "Léa", Texte: "Merci à tous", Date: time.Now()})
	require.NoError(t, err)

	server := mcp.NewServer(&mcp.Implementation{Name: "copro", Version: "test"}, nil)
	brainServer{sqlDB: sqlDB, mcpServer: mcpServer{sqlDB: sqlDB}}.addTools(server)
	st, ct := mcp.NewInMemoryTransports()
	_, err = server.Connect(ctx, st, nil)
	require.NoError(t, err)
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil).Connect(ctx, ct, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	var aTrier sourcesATrierOutput
	callTool(t, session, "sources_a_trier", map[string]any{}, &aTrier)
	require.Len(t, aTrier.Sources, 2)
	assert.Equal(t, s1, aTrier.Sources[0].ID, "oldest first")

	t.Run("wrong ids are refused right away", func(t *testing.T) {
		res := callTool(t, session, "proposer_rattachement", map[string]any{"affaire_id": "nope", "source_ids": []string{s1}, "justification": "x"}, nil)
		assert.Contains(t, toolError(t, res), "pas d'affaire")
		res = callTool(t, session, "proposer_rattachement", map[string]any{"affaire_id": a.ID, "source_ids": []string{"nope"}, "justification": "x"}, nil)
		assert.Contains(t, toolError(t, res), "n'existe pas")
		res = callTool(t, session, "proposer_rattachement", map[string]any{"affaire_id": a.ID, "source_ids": []string{s1}, "justification": ""}, nil)
		assert.Contains(t, toolError(t, res), "justification")
	})

	t.Run("a proposition takes its messages out of the next list", func(t *testing.T) {
		var out propositionOutput
		callTool(t, session, "proposer_rattachement", map[string]any{"affaire_id": a.ID, "source_ids": []string{s1}, "justification": "ELECO parle des câbles du D04", "citation": "Câbles changés"}, &out)
		require.NotEmpty(t, out.ID)
		callTool(t, session, "proposer_ecarter", map[string]any{"source_ids": []string{s2}, "justification": "remerciements"}, &out)

		aTrier = sourcesATrierOutput{}
		callTool(t, session, "sources_a_trier", map[string]any{}, &aTrier)
		assert.Empty(t, aTrier.Sources)

		props, err := db.GetPropositions(ctx, sqlDB, 0, db.PropEnAttente)
		require.NoError(t, err)
		require.Len(t, props, 2)
		assert.Equal(t, "claude", props[0].Auteur)
		got, _ := db.GetSource(ctx, sqlDB, s1)
		assert.Equal(t, db.SourceATrier, got.Etat, "nothing is applied before an administrator accepts")
	})

	t.Run("affaires lists the fiche", func(t *testing.T) {
		var out affairesOutput
		callTool(t, session, "affaires", map[string]any{}, &out)
		require.Len(t, out.Affaires, 1)
		assert.Equal(t, "VMC D04", out.Affaires[0].Titre)
	})
}
