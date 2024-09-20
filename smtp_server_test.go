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
		smtpL, err := net.Listen("unix", filepath.Join(d, "smtp.sock"))
		require.NoError(t, err)
		t.Logf("You can test the SMTP server by running:\n  socat - UNIX-CONNECT:%s", smtpL.Addr().String())

		go func() {
			err = ServeSMTP(context.Background(), db, smtpL)
			require.NoError(t, err)
		}()

		// Pause until the server is ready.
		assert.Eventually(t, func() bool {
			return CanConnect("unix", smtpL.Addr().String())
		}, 1*time.Second, 1*time.Millisecond)

		// Send an email.
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

// Addr is of the form ip:port. Only supports IPs, not hostnames. We check that
// we can connect() to this ip:port by running the TCP handshake SYN-SYNACK-ACK
// until the the connection is ESTABLISHED. The `network` parameter is "tcp",
// "udp", "unix", or any other protocol supported by the `net.Dial` func.
func CanConnect(network string, addr string) bool {
	conn, err := net.DialTimeout(network, addr, 1*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}
