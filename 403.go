package oauth

import (
	"html/template"
)

var rejectHTML = `
<html>
<head>
<style>
</style>
</head>
<body>
    {{if .Message}}
    <div class="msg">{{.Message}}</div>
    {{end}}
    <div class="box">
        <h3><a href={{.LoginURL}}>Please Log In</a></h3>
        <p>
            The page you are trying to access requires login via github. Click <a href="{{.LoginURL}}">here</a> to log in.
        </p>
    </div>
</body>
</html>
`
var rejectTemplate = template.Must(template.New("").Parse(rejectHTML))
