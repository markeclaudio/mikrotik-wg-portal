package main

import (
	"encoding/base64"
	"html/template"
	"log"
	"net/http"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const pageCSS = `
:root{color-scheme:light dark}
*{box-sizing:border-box;margin:0}
body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;
display:flex;align-items:center;justify-content:center;padding:1rem}
.card{background:#1e293b;border-radius:16px;padding:2rem;max-width:420px;width:100%;
box-shadow:0 10px 30px rgba(0,0,0,.4);text-align:center}
h1{font-size:1.25rem;margin-bottom:.25rem}
p.sub{color:#94a3b8;font-size:.9rem;margin-bottom:1.5rem}
.btn{display:block;width:100%;padding:.75rem;margin:.5rem 0;border-radius:10px;border:0;
font-size:1rem;cursor:pointer;text-decoration:none;color:#fff;font-weight:600}
.google{background:#4285f4}.microsoft{background:#5e5e5e}
.primary{background:#059669}.secondary{background:#334155}.danger{background:#b91c1c}
.qr{background:#fff;border-radius:12px;padding:12px;display:inline-block;margin:1rem 0}
.qr img{display:block;width:240px;height:240px}
.err{background:#7f1d1d;color:#fecaca;padding:.6rem;border-radius:8px;margin-bottom:1rem;font-size:.9rem}
.meta{color:#94a3b8;font-size:.85rem;margin:.75rem 0}
.email{color:#38bdf8;word-break:break-all}
`

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Access</title><style>` + pageCSS + `</style></head><body>
<div class="card">
<h1>🔐 WireGuard VPN</h1>
<p class="sub">Sign in to generate your connection profile</p>
{{if .Err}}<div class="err">{{.Err}}</div>{{end}}
{{if .Google}}<a class="btn google" href="/auth/google">Sign in with Google</a>{{end}}
{{if .Microsoft}}<a class="btn microsoft" href="/auth/microsoft">Sign in with Microsoft</a>{{end}}
{{if .None}}<p class="meta">No login method is configured yet — the administrator must set the OAuth credentials.</p>{{end}}
</div></body></html>`))

var profileTmpl = template.Must(template.New("profile").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Profile</title><style>` + pageCSS + `</style></head><body>
<div class="card">
<h1>🔐 WireGuard VPN</h1>
<p class="sub"><span class="email">{{.Email}}</span></p>
{{if .Err}}<div class="err">{{.Err}}</div>{{end}}
{{if .Have}}
  <p>Scan the QR code with the WireGuard app:</p>
  <div class="qr"><img src="data:image/png;base64,{{.QR}}" alt="WireGuard QR"></div>
  <div class="meta">Assigned IP: <b>{{.IP}}</b><br>
  Expires: <b>{{.Expires}}</b> (in {{.Remaining}})</div>
  <a class="btn primary" href="/profile.conf">⬇ Download .conf profile</a>
  <form method="post" action="/generate"><button class="btn secondary">↻ Regenerate profile</button></form>
  <form method="post" action="/revoke"><button class="btn danger">✕ Revoke access</button></form>
{{else}}
  <p class="meta">No active profile.</p>
  <form method="post" action="/generate"><button class="btn primary">Generate VPN profile</button></form>
{{end}}
<a class="btn secondary" href="/logout">Sign out</a>
</div></body></html>`))

func renderLogin(w http.ResponseWriter, cfg Config, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := loginTmpl.Execute(w, map[string]any{
		"Google":    cfg.GoogleID != "",
		"Microsoft": cfg.MSID != "",
		"None":      cfg.GoogleID == "" && cfg.MSID == "",
		"Err":       errMsg,
	})
	if err != nil {
		log.Printf("login template: %v", err)
	}
}

func renderProfile(w http.ResponseWriter, email string, ce confEntry, have bool, errMsg string) {
	data := map[string]any{"Email": email, "Have": have, "Err": errMsg}
	if have {
		png, err := qrcode.Encode(ce.Conf, qrcode.Medium, 480)
		if err != nil {
			log.Printf("qr: %v", err)
			have = false
			data["Have"] = false
		} else {
			data["QR"] = base64.StdEncoding.EncodeToString(png)
			data["IP"] = ce.IP.String()
			data["Expires"] = ce.Expires.Local().Format("02/01/2006 15:04")
			data["Remaining"] = time.Until(ce.Expires).Truncate(time.Minute).String()
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := profileTmpl.Execute(w, data); err != nil {
		log.Printf("profile template: %v", err)
	}
}
