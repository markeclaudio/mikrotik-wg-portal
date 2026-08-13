package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/markeclaudio/mikrotik-wg-portal/internal/wgutil"
)

type oidcProvider struct {
	Name        string
	AuthURL     string
	TokenURL    string
	UserinfoURL string
	ClientID    string
	Secret      string
}

func (a *App) provider(name string) (oidcProvider, bool) {
	switch name {
	case "google":
		if a.cfg.GoogleID == "" {
			return oidcProvider{}, false
		}
		return oidcProvider{
			Name:        "google",
			AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:    "https://oauth2.googleapis.com/token",
			UserinfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
			ClientID:    a.cfg.GoogleID,
			Secret:      a.cfg.GoogleSecret,
		}, true
	case "microsoft":
		if a.cfg.MSID == "" {
			return oidcProvider{}, false
		}
		base := "https://login.microsoftonline.com/" + url.PathEscape(a.cfg.MSTenant) + "/oauth2/v2.0"
		return oidcProvider{
			Name:        "microsoft",
			AuthURL:     base + "/authorize",
			TokenURL:    base + "/token",
			UserinfoURL: "https://graph.microsoft.com/oidc/userinfo",
			ClientID:    a.cfg.MSID,
			Secret:      a.cfg.MSSecret,
		}, true
	}
	return oidcProvider{}, false
}

func (a *App) redirectURI(provider string) string {
	return a.cfg.PublicURL + "/auth/" + provider + "/callback"
}

func (a *App) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")

	// Test login without OAuth, only active when DEV_FAKE_AUTH is set in the .env
	if name == "dev" && a.cfg.DevFakeAuth != "" {
		a.loginSuccess(w, r, a.cfg.DevFakeAuth)
		return
	}

	p, ok := a.provider(name)
	if !ok {
		http.Error(w, "provider not configured", http.StatusNotFound)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(wgutil.RandomBytes(16))
	stExp := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)
	stPayload := state + "." + stExp
	http.SetCookie(w, &http.Cookie{
		Name: "wgp_o", Value: stPayload + "." + a.sign(stPayload),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600,
		Secure: strings.HasPrefix(a.cfg.PublicURL, "https://"),
	})
	q := url.Values{
		"client_id":     {p.ClientID},
		"redirect_uri":  {a.redirectURI(p.Name)},
		"response_type": {"code"},
		"scope":         {"openid email"},
		"state":         {state},
	}
	if p.Name == "google" {
		q.Set("prompt", "select_account")
	}
	http.Redirect(w, r, p.AuthURL+"?"+q.Encode(), http.StatusFound)
}

func (a *App) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	p, ok := a.provider(r.PathValue("provider"))
	if !ok {
		http.Error(w, "provider not configured", http.StatusNotFound)
		return
	}
	// verify state
	c, err := r.Cookie("wgp_o")
	if err != nil {
		http.Redirect(w, r, "/?err="+urlQuery("Login session expired, please retry."), http.StatusSeeOther)
		return
	}
	parts := strings.Split(c.Value, ".")
	valid := len(parts) == 3 && a.sign(parts[0]+"."+parts[1]) == parts[2]
	if valid {
		if exp, err := strconv.ParseInt(parts[1], 10, 64); err != nil || time.Now().Unix() > exp {
			valid = false
		}
	}
	if !valid || r.URL.Query().Get("state") != parts[0] {
		http.Redirect(w, r, "/?err="+urlQuery("Security check failed (state), please retry."), http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "wgp_o", Value: "", Path: "/", MaxAge: -1})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "/?err="+urlQuery("Login cancelled."), http.StatusSeeOther)
		return
	}
	email, err := a.exchangeForEmail(p, code)
	if err != nil {
		log.Printf("oauth %s: %v", p.Name, err)
		http.Redirect(w, r, "/?err="+urlQuery("Authentication failed."), http.StatusSeeOther)
		return
	}
	a.loginSuccess(w, r, email)
}

func (a *App) loginSuccess(w http.ResponseWriter, r *http.Request, email string) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !a.emailAllowed(email) {
		log.Printf("access denied for %s (not in allowlist)", email)
		http.Redirect(w, r, "/?err="+urlQuery("Account not authorized: "+email), http.StatusSeeOther)
		return
	}
	a.setSession(w, email)
	log.Printf("login successful: %s", email)
	// Generate the profile right away, as per the flow: login -> keys -> peer -> QR
	if err := a.generateProfile(email); err != nil {
		log.Printf("post-login profile generation for %s failed: %v", email, err)
		http.Redirect(w, r, "/?err="+urlQuery("Login ok but profile creation failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) exchangeForEmail(p oidcProvider, code string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.ClientID},
		"client_secret": {p.Secret},
		"redirect_uri":  {a.redirectURI(p.Name)},
	}
	res, err := http.PostForm(p.TokenURL, form)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		return "", fmt.Errorf("token endpoint HTTP %d: %s", res.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	// The id_token comes straight from the token endpoint over TLS: claims are trustworthy.
	if email := emailFromIDToken(tok.IDToken); email != "" {
		return email, nil
	}
	// fallback: the userinfo endpoint
	req, _ := http.NewRequest("GET", p.UserinfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	ures, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer ures.Body.Close()
	var ui struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(ures.Body).Decode(&ui); err != nil {
		return "", err
	}
	if ui.Email == "" {
		return "", fmt.Errorf("no email in OIDC data")
	}
	return ui.Email, nil
}

func emailFromIDToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		UPN               string `json:"upn"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	for _, c := range []string{claims.Email, claims.PreferredUsername, claims.UPN} {
		if strings.Contains(c, "@") {
			return c
		}
	}
	return ""
}
