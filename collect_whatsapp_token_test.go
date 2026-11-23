package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The token is a workload identity, replaced every few minutes: each call
// sends the one that is in the file then.
func TestWhatsappTokenReadAtEachCall(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "token")
	w := &whatsappCollecteur{client: srv.Client(), base: srv.URL, token: jetonFichier(path)}

	// The issuer hasn't written it yet: nothing is sent.
	if _, err := w.get(context.Background(), "/internal/chats"); err == nil || len(got) != 0 {
		t.Fatalf("without the file: %v, %d call(s)", err, len(got))
	}
	for _, token := range []string{"first\n", "second\n"} {
		if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		resp, err := w.get(context.Background(), "/internal/chats")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if len(got) != 2 || got[0] != "Bearer first" || got[1] != "Bearer second" {
		t.Errorf("sent %q", got)
	}
	if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.get(context.Background(), "/internal/chats"); err == nil || len(got) != 2 {
		t.Errorf("with an empty file: %v, %d call(s)", err, len(got))
	}
}
