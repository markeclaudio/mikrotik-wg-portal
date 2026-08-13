package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ListenAddr    string
	PublicURL     string
	SessionSecret []byte

	GoogleID     string
	GoogleSecret string
	MSID         string
	MSSecret     string
	MSTenant     string

	AllowedDomains []string
	AllowedEmails  []string

	MikrotikURL      string
	MikrotikUser     string
	MikrotikPass     string
	MikrotikInsecure bool

	WGInterface  string
	WGEndpoint   string
	WGSubnet     netip.Prefix
	WGDNS        string
	WGAllowedIPs string
	TTL          time.Duration
	CleanupEvery time.Duration

	DevFakeAuth string
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseTTL accepts Go durations ("8h", "30m") plus a "Nd" day suffix.
func parseTTL(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(n * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

func loadConfig() Config {
	c := Config{
		ListenAddr:       env("LISTEN_ADDR", ":8080"),
		PublicURL:        strings.TrimRight(env("PUBLIC_URL", "http://localhost:8080"), "/"),
		GoogleID:         env("GOOGLE_CLIENT_ID", ""),
		GoogleSecret:     env("GOOGLE_CLIENT_SECRET", ""),
		MSID:             env("MS_CLIENT_ID", ""),
		MSSecret:         env("MS_CLIENT_SECRET", ""),
		MSTenant:         env("MS_TENANT", "common"),
		AllowedDomains:   splitList(env("ALLOWED_DOMAINS", "")),
		AllowedEmails:    splitList(env("ALLOWED_EMAILS", "")),
		MikrotikURL:      strings.TrimRight(env("MIKROTIK_URL", "http://192.168.88.1"), "/"),
		MikrotikUser:     env("MIKROTIK_USER", ""),
		MikrotikPass:     env("MIKROTIK_PASS", ""),
		MikrotikInsecure: env("MIKROTIK_INSECURE", "false") == "true",
		WGInterface:      env("WG_INTERFACE", "wg-portal"),
		WGEndpoint:       env("WG_ENDPOINT", ""),
		WGDNS:            env("WG_DNS", ""),
		WGAllowedIPs:     env("WG_ALLOWED_IPS", "0.0.0.0/0"),
		DevFakeAuth:      env("DEV_FAKE_AUTH", ""),
	}
	sub, err := netip.ParsePrefix(env("WG_SUBNET", "10.99.99.0/24"))
	if err != nil {
		log.Fatalf("WG_SUBNET non valida: %v", err)
	}
	c.WGSubnet = sub.Masked()
	ttl, err := parseTTL(env("WG_TTL", "8h"))
	if err != nil {
		log.Fatalf("WG_TTL non valido: %v", err)
	}
	c.TTL = ttl
	ce, err := time.ParseDuration(env("CLEANUP_INTERVAL", "60s"))
	if err != nil {
		log.Fatalf("CLEANUP_INTERVAL non valido: %v", err)
	}
	c.CleanupEvery = ce
	if s := env("SESSION_SECRET", ""); s != "" {
		c.SessionSecret = []byte(s)
	} else {
		c.SessionSecret = randomBytes(32)
		log.Print("SESSION_SECRET non impostato: generato secret casuale (le sessioni non sopravvivono al riavvio)")
	}
	if c.MikrotikUser == "" || c.MikrotikPass == "" {
		log.Fatal("MIKROTIK_USER e MIKROTIK_PASS sono obbligatori")
	}
	if c.WGEndpoint == "" {
		log.Fatal("WG_ENDPOINT è obbligatorio (host:porta pubblico del server WireGuard)")
	}
	if c.GoogleID == "" && c.MSID == "" && c.DevFakeAuth == "" {
		log.Fatal("nessun metodo di login configurato: impostare GOOGLE_CLIENT_ID/SECRET o MS_CLIENT_ID/SECRET")
	}
	return c
}

type confEntry struct {
	Conf    string
	IP      netip.Addr
	Expires time.Time
}

type App struct {
	cfg Config
	mt  *Mikrotik

	mu    sync.Mutex
	confs map[string]confEntry // email -> ultimo profilo generato (solo in RAM)
}

func main() {
	cfg := loadConfig()
	app := &App{cfg: cfg, mt: newMikrotik(cfg), confs: map[string]confEntry{}}

	if iface, err := app.mt.WGInterface(cfg.WGInterface); err != nil {
		log.Printf("ATTENZIONE: interfaccia WireGuard %q non raggiungibile/trovata: %v", cfg.WGInterface, err)
	} else {
		log.Printf("MikroTik OK: interfaccia %s, chiave pubblica %s, porta %s", iface.Name, iface.PublicKey, iface.ListenPort)
	}

	go app.cleanupLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.handleIndex)
	mux.HandleFunc("GET /auth/{provider}", app.handleAuthStart)
	mux.HandleFunc("GET /auth/{provider}/callback", app.handleAuthCallback)
	mux.HandleFunc("POST /generate", app.handleGenerate)
	mux.HandleFunc("POST /revoke", app.handleRevoke)
	mux.HandleFunc("GET /profile.conf", app.handleDownload)
	mux.HandleFunc("GET /logout", app.handleLogout)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	log.Printf("wg-portal in ascolto su %s (public URL %s, TTL peer %s)", cfg.ListenAddr, cfg.PublicURL, cfg.TTL)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, mux))
}

// ---- sessioni (cookie firmato HMAC, stateless) ----

func (a *App) sign(payload string) string {
	m := hmac.New(sha256.New, a.cfg.SessionSecret)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *App) setSession(w http.ResponseWriter, email string) {
	exp := time.Now().Add(12 * time.Hour).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(email)) + "." + strconv.FormatInt(exp, 10)
	http.SetCookie(w, &http.Cookie{
		Name: "wgp_s", Value: payload + "." + a.sign(payload),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: strings.HasPrefix(a.cfg.PublicURL, "https://"),
		MaxAge: int(12 * time.Hour / time.Second),
	})
}

func (a *App) session(r *http.Request) (string, bool) {
	c, err := r.Cookie("wgp_s")
	if err != nil {
		return "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(a.sign(payload)), []byte(parts[2])) {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	email, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	return string(email), true
}

func (a *App) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "wgp_s", Value: "", Path: "/", MaxAge: -1})
}

// ---- autorizzazione ----

func (a *App) emailAllowed(email string) bool {
	email = strings.ToLower(email)
	if len(a.cfg.AllowedEmails) == 0 && len(a.cfg.AllowedDomains) == 0 {
		return true
	}
	for _, e := range a.cfg.AllowedEmails {
		if e == email {
			return true
		}
	}
	if at := strings.LastIndex(email, "@"); at >= 0 {
		dom := email[at+1:]
		for _, d := range a.cfg.AllowedDomains {
			if d == dom {
				return true
			}
		}
	}
	return false
}

// ---- handler ----

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	email, ok := a.session(r)
	if !ok {
		renderLogin(w, a.cfg, r.URL.Query().Get("err"))
		return
	}
	a.mu.Lock()
	ce, have := a.confs[email]
	a.mu.Unlock()
	if have && time.Now().After(ce.Expires) {
		have = false
	}
	renderProfile(w, email, ce, have, r.URL.Query().Get("err"))
}

func (a *App) handleGenerate(w http.ResponseWriter, r *http.Request) {
	email, ok := a.session(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := a.generateProfile(email); err != nil {
		log.Printf("generazione profilo per %s fallita: %v", email, err)
		http.Redirect(w, r, "/?err="+urlQuery("Errore nella creazione del profilo: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleRevoke(w http.ResponseWriter, r *http.Request) {
	email, ok := a.session(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := a.removePeersFor(email); err != nil {
		log.Printf("revoca per %s fallita: %v", email, err)
	}
	a.mu.Lock()
	delete(a.confs, email)
	a.mu.Unlock()
	log.Printf("profilo revocato per %s", email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleDownload(w http.ResponseWriter, r *http.Request) {
	email, ok := a.session(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.mu.Lock()
	ce, have := a.confs[email]
	a.mu.Unlock()
	if !have || time.Now().After(ce.Expires) {
		http.Error(w, "nessun profilo attivo", http.StatusNotFound)
		return
	}
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, strings.ToLower(strings.SplitN(email, "@", 2)[0]))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=wg-%s.conf", name))
	w.Write([]byte(ce.Conf))
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.clearSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// generateProfile: chiavi nuove, peer sul MikroTik (sostituendo quello esistente), conf in RAM.
func (a *App) generateProfile(email string) error {
	iface, err := a.mt.WGInterface(a.cfg.WGInterface)
	if err != nil {
		return fmt.Errorf("interfaccia WireGuard: %w", err)
	}
	if err := a.removePeersFor(email); err != nil {
		return fmt.Errorf("rimozione peer precedente: %w", err)
	}
	peers, err := a.mt.WGPeers(a.cfg.WGInterface)
	if err != nil {
		return fmt.Errorf("lettura peer: %w", err)
	}
	ip, err := allocateIP(a.cfg.WGSubnet, peers)
	if err != nil {
		return err
	}
	priv, pub, err := genKeypair()
	if err != nil {
		return err
	}
	psk := base64.StdEncoding.EncodeToString(randomBytes(32))
	expires := time.Now().UTC().Add(a.cfg.TTL).Truncate(time.Second)

	err = a.mt.AddWGPeer(map[string]string{
		"interface":       a.cfg.WGInterface,
		"public-key":      pub,
		"preshared-key":   psk,
		"allowed-address": ip.String() + "/32",
		"comment":         peerComment(email, expires),
	})
	if err != nil {
		return fmt.Errorf("creazione peer: %w", err)
	}

	endpoint := a.cfg.WGEndpoint
	if !strings.Contains(endpoint, ":") && iface.ListenPort != "" {
		endpoint += ":" + iface.ListenPort
	}
	conf := buildClientConf(priv, ip, a.cfg.WGSubnet.Bits(), a.cfg.WGDNS, iface.PublicKey, psk, a.cfg.WGAllowedIPs, endpoint)

	a.mu.Lock()
	a.confs[email] = confEntry{Conf: conf, IP: ip, Expires: expires}
	a.mu.Unlock()
	log.Printf("profilo creato per %s: ip %s, scade %s", email, ip, expires.Format(time.RFC3339))
	return nil
}

func (a *App) removePeersFor(email string) error {
	peers, err := a.mt.WGPeers(a.cfg.WGInterface)
	if err != nil {
		return err
	}
	for _, p := range peers {
		if em, _, ok := parsePeerComment(p.Comment); ok && strings.EqualFold(em, email) {
			if err := a.mt.DeleteWGPeer(p.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// cleanupLoop rimuove i peer scaduti; la scadenza vive nel commento del peer,
// quindi funziona anche dopo un riavvio del container.
func (a *App) cleanupLoop() {
	t := time.NewTicker(a.cfg.CleanupEvery)
	defer t.Stop()
	for range t.C {
		peers, err := a.mt.WGPeers(a.cfg.WGInterface)
		if err != nil {
			log.Printf("cleanup: lettura peer fallita: %v", err)
			continue
		}
		now := time.Now()
		for _, p := range peers {
			email, exp, ok := parsePeerComment(p.Comment)
			if !ok || now.Before(exp) {
				continue
			}
			if err := a.mt.DeleteWGPeer(p.ID); err != nil {
				log.Printf("cleanup: rimozione peer %s (%s) fallita: %v", p.ID, email, err)
				continue
			}
			log.Printf("cleanup: peer scaduto rimosso (%s, scadenza %s)", email, exp.Format(time.RFC3339))
			a.mu.Lock()
			if ce, okc := a.confs[email]; okc && !ce.Expires.After(exp) {
				delete(a.confs, email)
			}
			a.mu.Unlock()
		}
	}
}

const commentPrefix = "wg-portal|"

func peerComment(email string, expires time.Time) string {
	return commentPrefix + email + "|expires=" + expires.Format(time.RFC3339)
}

func parsePeerComment(c string) (email string, expires time.Time, ok bool) {
	if !strings.HasPrefix(c, commentPrefix) {
		return "", time.Time{}, false
	}
	rest := strings.TrimPrefix(c, commentPrefix)
	i := strings.LastIndex(rest, "|expires=")
	if i < 0 {
		return "", time.Time{}, false
	}
	exp, err := time.Parse(time.RFC3339, rest[i+len("|expires="):])
	if err != nil {
		return "", time.Time{}, false
	}
	return rest[:i], exp, true
}

func urlQuery(s string) string {
	var b strings.Builder
	for _, r := range []byte(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_':
			b.WriteByte(r)
		case r == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", r)
		}
	}
	return b.String()
}
