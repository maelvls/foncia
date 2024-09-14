package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/glebarez/go-sqlite"
)

func TestDoInBatches(t *testing.T) {
	tests := []struct {
		name           string
		givenbatchSize int
		givenElmts     []int
		wantBatches    [][]int
		wantErr        error
	}{
		{
			name:           "when each batch is full, only two batches are needed, not three",
			givenbatchSize: 5,
			givenElmts:     []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			wantBatches:    [][]int{{1, 2, 3, 4, 5}, {6, 7, 8, 9, 10}},
		},
		{
			name:           "when the last batch is not full, it is processed",
			givenbatchSize: 5,
			givenElmts:     []int{1, 2, 3, 4, 5, 6, 7, 8},
			wantBatches:    [][]int{{1, 2, 3, 4, 5}, {6, 7, 8}},
		},
		{
			name:           "OK",
			givenbatchSize: 5,
			givenElmts:     []int{1, 2, 3, 4, 5},
			wantBatches:    [][]int{{1, 2, 3, 4, 5}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBatches [][]int
			err := DoInBatches(tt.givenbatchSize, tt.givenElmts, func(elmts []int) error {
				gotBatches = append(gotBatches, elmts)
				return nil
			})
			if tt.wantErr != nil {
				require.EqualError(t, tt.wantErr, err.Error())
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantBatches, gotBatches)
		})
	}
}

func TestSMTPServer(t *testing.T) {
	t.Run("sample email is correctly parsed", func(t *testing.T) {
		msg, err := mail.ReadMessage(bytes.NewBufferString(email))
		require.NoError(t, err)

		mediaType, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
		require.True(t, strings.HasPrefix(mediaType, "multipart/"))

		multi := multipart.NewReader(msg.Body, params["boundary"])
		buf := new(strings.Builder)
		for {
			part, err := multi.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)

			contentType := part.Header.Get("Content-Type")
			require.False(t, strings.HasPrefix(contentType, "multipart/"))
			_, err = io.Copy(buf, part)

			require.NoError(t, err)
		}

		assert.Equal(t, "Ordre de service N° OSMIL805898844 – 2NRT POMPE ENVIRONNEMENT - 3 RUE BERTRAN 31200 TOULOUSE", msg.Header.Get("Subject"))
		assert.Equal(t, "--0739d2f849e1b0908d960e9150db9732fb6f9e461a99ad7e55ecddc820f9\nContent-Transfer-Encoding: quoted-printable\nContent-Type: text/plain; charset=utf-8\nMime-Version: 1.0\n\nBonjour,<br/ ><br/ >En notre qualité de syndic du bien désigné en objet, nous vous remercions d'exécuter les travaux décrits dans l’ordre de service détaillé ci-dessous :<br/ ><br/ >Immeuble N° 501292910 : TERRA NOSTRA 2 - 3 RUE BERTRAN 31200 TOULOUSE,<br/ ><br/ >digicode(s): CODE, 2308, CODE, 2308<br/ ><br/ ><br/ ><br/ >Objet : 2NRT POMPE ENVIRONNEMENT - REGARD EN SOUS-SOL<br/ ><br/ >Date de début des travaux : vendredi 23 août 2024<br/ ><br/ >Merci de nous confirmer la bonne exécution des travaux par retour de mail.<br/ ><br/ >Afin de faciliter le traitement de votre facture, merci de reporter le N° du présent ordre de service sur votre facture, libellée à l’ordre du syndicat des copropriétaires.<br/ ><br/ >MERCI D'INTERVENIR POUR POMPER DES REGARD EN SOUS SOL. CONTACTER MR VALAIS AU 07 86 48 43 91   .<br/ ><br/ >Cordialement.<br/ ><br/ >Sincères salutations.\n\nMHAMDI Sihem\n\nFoncia Toulouse - Arthaud\n6 boulevard Florence Arthaud 31200 Toulouse France\nsihem.mhamdi@foncia.com ( sihem.mhamdi@foncia.com )\n", buf.String())
	})

	t.Run("run server", func(t *testing.T) {
		db, err := sql.Open("sqlite", ":memory:")
		require.NoError(t, err)
		err = initSchemaDB(context.Background(), db)
		require.NoError(t, err)

		d := t.TempDir()

		// Using UNIX sockets so that macOS stops asking me "Do you want to
		// allow incoming network connections?" each time I run the tests.
		httpL, err := net.Listen("unix", filepath.Join(d, "http.sock"))
		require.NoError(t, err)

		smtpL, err := net.Listen("unix", filepath.Join(d, "smtp.sock"))
		require.NoError(t, err)

		go func() {
			err = ServeCmd(context.Background(), db, httpL, "", "foo", "bar", smtpL, nil, "foo")
			require.NoError(t, err)
		}()

		// Pause.
		time.Sleep(1 * time.Second)

		// Send an email
		conn, err := net.Dial("unix", smtpL.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		err = smtp.NewClient(conn).SendMail("foo@bar.fr", []string{"foo2bar@foo.co"}, bytes.NewBufferString(email))
		require.NoError(t, err)
	})
}

// freePort asks the kernel for a free open port that is ready to use. Copied
// from https://github.com/phayes/freeport/blob/master/freeport.go.
func freePort() string {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}
