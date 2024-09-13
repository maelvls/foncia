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

// Note that the body is multipart and that the text/plain message uses a
// MIME-encoded quoted-printable encoding (e.g., "qualit=C3=A9").
const email = `Subject: Ordre de service N° OSMIL805898844 – 2NRT POMPE ENVIRONNEMENT - 3 RUE BERTRAN 31200 TOULOUSE
From: noreply@foncia.com
To: sihem.mhamdi@foncia.com, 2nrt@pompesenvironnement.fr
Cc: didier.fadel@foncia.com, mael65@gmail.com
Reply-To: sihem.mhamdi@foncia.com
Delivered-To: mael65@gmail.com
Date: Fri, 23 Aug 2024 08:58:12 +0000 (UTC)
Mime-Version: 1.0
Message-ID: <ZExd3_m3SXiUKIanwb7ivw@geopod-ismtpd-2>
Content-Type: multipart/alternative; boundary=0739d2f849e1b0908d960e9150db9732fb6f9e461a99ad7e55ecddc820f9

--0739d2f849e1b0908d960e9150db9732fb6f9e461a99ad7e55ecddc820f9
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset=utf-8
Mime-Version: 1.0

Bonjour,<br/ ><br/ >En notre qualit=C3=A9 de syndic du bien d=C3=A9sign=C3=
=A9 en objet, nous vous remercions d'ex=C3=A9cuter les travaux d=C3=A9crits=
 dans l=E2=80=99ordre de service d=C3=A9taill=C3=A9 ci-dessous :<br/ ><br/ =
>Immeuble N=C2=B0 501292910 : TERRA NOSTRA 2 - 3 RUE BERTRAN 31200 TOULOUSE=
,<br/ ><br/ >digicode(s): CODE, 2308, CODE, 2308<br/ ><br/ ><br/ ><br/ >Obj=
et : 2NRT POMPE ENVIRONNEMENT - REGARD EN SOUS-SOL<br/ ><br/ >Date de d=C3=
=A9but des travaux : vendredi 23 ao=C3=BBt 2024<br/ ><br/ >Merci de nous co=
nfirmer la bonne ex=C3=A9cution des travaux par retour de mail.<br/ ><br/ >=
Afin de faciliter le traitement de votre facture, merci de reporter le N=C2=
=B0 du pr=C3=A9sent ordre de service sur votre facture, libell=C3=A9e =C3=
=A0 l=E2=80=99ordre du syndicat des copropri=C3=A9taires.<br/ ><br/ >MERCI =
D'INTERVENIR POUR POMPER DES REGARD EN SOUS SOL. CONTACTER MR VALAIS AU 07 =
86 48 43 91   .<br/ ><br/ >Cordialement.<br/ ><br/ >Sinc=C3=A8res salutatio=
ns.

MHAMDI Sihem

Foncia Toulouse - Arthaud
6 boulevard Florence Arthaud 31200 Toulouse France
sihem.mhamdi@foncia.com ( sihem.mhamdi@foncia.com )

( https://u19049598.ct.sendgrid.net/ls/click?upn=3Du001.42-2BruBDFhEzIWqQkn=
vWFMLTDyoNn-2Fpy9FeFmgiP2dBgCRChgczdJFISCiv4fF3nLZZ1j_DaCUCeel0mqe9lxlk2PyR=
2f-2F4wmvAt2zgze8JAPR1TX0mxFnIDnULobMeDXH8sC5DxStuEg-2B9gqDvD839saOqeddSoXP=
xclhMr6rlzbJK1NFzjZFgtqrSCResdUakk1PT2T-2Fm-2BU0mAKeMHjvJXV91ap9Y61tPYM2mJL=
Apo-2BOmbfIcIA8Q6lkuMSfd4OgN4L5TySkJgTFdwOZ0h4OVtvWlHzPMCcFS7eRgdX2OvS-2F2r=
M0oGkdqhEAqWHbMXxQJMP61qCan5ZJ4iLoIK8WPcwZej8Qy4xD0B1-2BNOj7dBVagTgCP0OWicR=
zKIqQ4oag9ym38vAgXyRBxZeiy4FiZyAnQQ-3D-3D ) ( https://u19049598.ct.sendgrid=
.net/ls/click?upn=3Du001.42-2BruBDFhEzIWqQknvWFMN-2Fh9YX8ZSVX54DfkkTBNWDqKZ=
7ffXLTyqIcvvAM8ZD8XqMqqica187KifrGTByqvJ0UY5UNzFFEk4KTr7mBTNaUaiiyD7Ixc5vLe=
GeRAkDwmmMG_DaCUCeel0mqe9lxlk2PyR2f-2F4wmvAt2zgze8JAPR1TX0mxFnIDnULobMeDXH8=
sC5DxStuEg-2B9gqDvD839saOqeddSoXPxclhMr6rlzbJK1NFzjZFgtqrSCResdUakk1PT2T-2F=
m-2BU0mAKeMHjvJXV91ap9Y61tPYM2mJLApo-2BOmbfIcIA8Q6lkuMSfd4OgN4L5TySkJgTFdwO=
Z0h4OVtvWlJZf-2BcSVxhpNTbC8VA83cU9TNTGZgs46SBNRim7fVBmpFTU6gILX9mByrbNiBiRe=
keh0kZWOA6ZwVITSwmGasnqJHZFZn6xO-2FHfAr5yTmSLOJIZpxScD7bQ-2Bj9int6DcIw-3D-3=
D ) ( https://u19049598.ct.sendgrid.net/ls/click?upn=3Du001.42-2BruBDFhEzIW=
qQknvWFMGhD5teAZOZRtlH8bF9-2B-2B0U3m3l585C8BuYxKlA1CCHg-2BE4oU-2BjWd4LFHF9O=
LEHLP-2FH7iQuc9aas46wZ4ZRxhis-3DU_jC_DaCUCeel0mqe9lxlk2PyR2f-2F4wmvAt2zgze8=
JAPR1TX0mxFnIDnULobMeDXH8sC5DxStuEg-2B9gqDvD839saOqeddSoXPxclhMr6rlzbJK1NFz=
jZFgtqrSCResdUakk1PT2T-2Fm-2BU0mAKeMHjvJXV91ap9Y61tPYM2mJLApo-2BOmbfIcIA8Q6=
lkuMSfd4OgN4L5TySkJgTFdwOZ0h4OVtvWlFP6GlCSa0cXk0QG84-2BKCnN1hOsfnC26Op-2FL4=
RUVXUgt7dYnjKuXW8HlNuWku6K5FjvCqJ8Rlft-2BncPK4fBSMOPhscRJn8bovmPXEWti-2BnLH=
t9gJHQsOlYC2lR-2BDDf0mag-3D-3D )

foncia.com
--0739d2f849e1b0908d960e9150db9732fb6f9e461a99ad7e55ecddc820f9--
`

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
