package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFilenameFromURL(t *testing.T) {
	tests := []struct {
		fileURL    string
		want       string
		wantErrMsg string
	}{
		{
			fileURL:    "https://fon-mil-prod-plato-prv.s3.eu-west-3.amazonaws.com/e/6/6/6/2/674836bfb753160398ee6662?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAXMTESETVHY3LHMDR%2F20250129%2Feu-west-3%2Fs3%2Faws4_request&X-Amz-Date=20250129T171628Z&X-Amz-Expires=900&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIf%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMyJHMEUCIQDj8iWPBGZspCL2CUSMniDTOhPCKTr8o17mjxtWdO00UwIgL4D1u5DtZfYCKCEpUX78c0b4SDYeR2VddKGkGdcNdpIqgAQIkP%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARACGgw1MDgwOTA3ODcwNTAiDN51Bas9kmYPyShHAyrUA7wx2z79PWterZcfjBNa1kQmpd1SESDoHBUV05Bv%2FW2HIiGMDBVv1l1B4Xa4hH3ixDokqYjttUqbOde3oJLgKzhdSRx8AKWtNLxGFGRKg49bEi6TC2SjuOFCd51ZGOcLxRY1EnyP9jr9CaDsDk%2FJDurkEdInf8ASH56pXwpaz4BhCSn7PKexefL7YNfNmYFl0u9LAXR24%2FOCngnLP%2Fug0klrN3qttY50MxiLvKN1nnjwpBIr%2FMeGexwf0btY4LWgh6ipWURmdsCHyMQtfkn%2B7sAhQ3ujUXmcrRrTcffaqDckJEkfC2Od7y4CnTNWrHdgWrkR2ksD8pfjIrL4Iv2Ct8IhKaGmlG0sbiP5YprFHmLA1nkr87buei8EOkTfSiuZu%2FKGaWcYHOzdGQitRBeT4MZkNd4uOL%2F6V62ncHHP8MoD%2BXIBcQkL7W1cUkMXrkyHT6VaDGiEXLJ1J7Y194wE0uJq6XTfGtJc2SEzMDm4wN2TvSBUAjBo1RAmEDzMSV6evXNCv2oATxufxKDQ0HLJ0Dq6IWsm0pbMwc2n1pjdx9aHFpFd9U%2BJHwjruKQfpTbY2LYxc2LhkhHlW0xH2UzXWxO94eU%2BVIZLFiy2yuEUBVggIgTVCDDXhum8BjqlAdxyOC29dGCIo%2F3dk1vvqbzAppsm4mKv0TjM45BOiReDsu%2FPpEpLd1klWv7iWuW%2BG8uqQr0Gilfbt6y%2F6I5eOzYlm%2BfmYWCOPxVFAaR1iosjwpmpOKmDxow6O4CvntbXC1TgE8gUb3WLI45xq1A2kYMD9PjgoiZj01hia1qwh47bptY8%2BOnkCfF1UByAm2nis9fd5P75QLRVj%2B8DLqKbahlQ0O7jsA%3D%3D&X-Amz-Signature=7c1094dee2ee4812de265c48533846f9a353a4be234180ed47b0d772c91dcbd6&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22IZQUIERDO%2520-%2520OSMIL806596688%2520-%25202024-11-28%2520-%252025-074.pdf%22&x-id=GetObject",
			want:       "IZQUIERDO - OSMIL806596688 - 2024-11-28 - 25-074.pdf",
			wantErrMsg: "",
		},
		{
			fileURL: "https://fon-mil-prod-plato-prv.s3.eu-west-3.amazonaws.com/0/1/f/d/9/66bc771ee645112312b01fd9?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAXMTESETVMYSWTMQT%2F20250129%2Feu-west-3%2Fs3%2Faws4_request&X-Amz-Date=20250129T181523Z&X-Amz-Expires=900&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMyJIMEYCIQDMFwtw4MioWV8xl8rBHBL5MfLlYeIrStIF8t5sgqnnUQIhANGJIbQxbD2GB5TYnzooZcB3vy73VvJytyQdqrjWVsmjKoAECJP%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQAhoMNTA4MDkwNzg3MDUwIgxoCclVymgZL763LSYq1APcvjEIEChlGgXPdlZUht2foV8YfMjpZqri9prql8vz68JHVyJakOz076bgasF%2FNV0O7btaE2nis1Sf%2BWfUDwqyTvj6%2FNPYSsA938huLIn1SrKGwSuGq1QNy8BzX2ANixVB9k5CJy4TKrnXS0vEjjJJTAARF6W2tz6j7YjcMJCddII4O1xtTiHoHNnAl6x0ydRCc5y3%2B2oEv%2BZS6MG%2FTbHdfxDYtD2DpURnORNdeO%2FQfDDAHzTgw1OsrgBnNHLh%2ByfeyNh4KJym1qLQopJaL4VJDa%2BiOMF1xopuWSFvyLiJ0tWa219%2B6ek4BHIGaTTcXpHgrQ9vu%2BE74sdwZQcyD5bF%2FfM1pSvMPcziv7WYlVbzkYyvr4uf1uROsFd9Dd%2BIzE5yIuSpvkBgj91BfKAWealyQd65ntGGZgfHQJPSin4uDX5B2I5NVVgjlh%2F4q8C5u8%2BqWzMtNpS3DeGBFo3rUiYws2KI8h4a4fnULCYYf%2FUWRopRYnx0fwtdZDfZjpnZmXucRdnRFygCv7oR8XEjsGtgP4gXgPQ7pxgGtmV9dhnarKGi8Ioms4YwYCUNznK8zg%2FwbstZWosDrdbvfVdGMQ%2BvfFlaDhqwkcheUVSuB56L3wQ%2FaY0wn9bpvAY6pAG1ruoJ0Mtjc7ps0VYYZtTX39s9qnU67IumKgWTOoFzeoQk6XtY%2FJbLq6HKxp5FusUY1SyP9jkLLrix%2B71xNwXPvG7v7WXYur%2Fmk0LQtFXjLh%2FjWTlljyQc2AGNniaIUGl4AZePUTZ4HqzMzQfx9tujmT0sjuhOzKkRZa61lym1V1F3Rc68GQxFU37%2BBT4bpRY%2BcUX2YeQWzTsq51D3vtAqispBJg%3D%3D&X-Amz-Signature=28b58b496179eac70b6f77dff72ecaf8578a069eae1551780667ed3716758eb1&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22VALAIS%2520-%2520OSMIL805875306%2520-%25202024-08-14%2520-%252023%2F07%2F2024.pdf%22&x-id=GetObject",
			// Orig:    "VALAIS - OSMIL805875306 - 2024-08-14 - 23/07/2024.pdf"
			want:       "VALAIS - OSMIL805875306 - 2024-08-14 - 23-07-2024.pdf",
			wantErrMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.fileURL, func(t *testing.T) {
			got, err := getFilenameFromURL(tt.fileURL)
			if tt.wantErrMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErrMsg)
			}
			assert.Equal(t, tt.want, got)
		})
	}
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
