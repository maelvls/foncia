package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/dreamscached/minequery/v2"
	"github.com/maelvls/foncia/logutil"
)

func ServeMinecraft(w http.ResponseWriter, r *http.Request) {
	logutil.Debugf("serving %s", r.URL.Path)
	hostname := "lisa.valais.dev"
	javaPort := 25565
	bedrockPort := 19132
	res, err := minequery.Ping17(hostname, javaPort)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmplMC.Execute(w, tmlpMCData{
		MC:            res,
		JavaServer:    fmt.Sprintf("%s:%d", hostname, javaPort),
		BedrockServer: fmt.Sprintf("%s:%d", hostname, bedrockPort),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type tmlpMCData struct {
	MC            *minequery.Status17
	JavaServer    string
	BedrockServer string
}

var tmplMC = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
<head>
<title>Minecraft</title>
<meta charset="utf-8">
</head>
<body>
	<h2>Minecraft</h2>

	<p>Java endpoint: <strong>{{.JavaServer}}</strong></p>
	<p>Bedrock endpoint: <strong>{{.BedrockServer}}</strong></p>

	<p>{{.MC}}</p>

	<h2>Players</h2>

	<table>
		<tr>
			<th>Player</th>
			<th>UUID</th>
		</tr>
		{{range .MC.SamplePlayers}}
		<tr>
			<td>{{.Nickname}}</td>
			<td>{{.UUID}}</td>
		</tr>
		{{end}}
	</table>
</body>
</html>
`))
