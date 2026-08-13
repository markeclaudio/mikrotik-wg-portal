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

	"golang.org/x/crypto/acme/autocert"

	"github.com/markeclaudio/mikrotik-wg-portal/internal/cloudflare"
	"github.com/markeclaudio/mikrotik-wg-portal/internal/mikrotik"
	"github.com/markeclaudio/mikrotik-wg-portal/internal/wgutil"
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

	AcmeDomain string
	AcmeEmail  string
	AcmeCache  string
	ListenTLS  string

	CFToken    string
	CFRecord   string
	CFZone     string
	CFProxied  bool
	CFInterval time.Duration
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
		AcmeDomain:       env("ACME_DOMAIN", ""),
		AcmeEmail:        env("ACME_EMAIL", ""),
		AcmeCache:        env("ACME_CACHE", "/acme"),
		ListenTLS:        env("LISTEN_TLS", ":8443"),
		CFToken:          env("CF_API_TOKEN", ""),
		CFRecord:         env("CF_RECORD", ""),
		CFZone:           env("CF_ZONE", ""),
		CFProxied:        env("CF_PROXIED", "false") == "true",
	}
	cfi, err0 := time.ParseDuration(env("CF_INTERVAL", "5m"))
	if err0 != nil {
		log.Fatalf("invalid CF_INTERVAL: %v", err0)
	}
	c.CFInterval = cfi
	sub, err := netip.ParsePrefix(env("WG_SUBNET", "10.99.99.0/24"))
	if err != nil {
		log.Fatalf("invalid WG_SUBNET: %v", err)
	}
	c.WGSubnet = sub.Masked()
	ttl, err := parseTTL(env("WG_TTL", "8h"))
	if err != nil {
		log.Fatalf("invalid WG_TTL: %v", err)
	}
	c.TTL = ttl
	ce, err := time.ParseDuration(env("CLEANUP_INTERVAL", "60s"))
	if err != nil {
		log.Fatalf("invalid CLEANUP_INTERVAL: %v", err)
	}
	c.CleanupEvery = ce
	if s := env("SESSION_SECRET", ""); s != "" {
		c.SessionSecret = []byte(s)
	} else {
		c.SessionSecret = wgutil.RandomBytes(32)
		log.Print("SESSION_SECRET not set: generated a random secret (sessions will not survive a restart)")
	}
	if c.MikrotikUser == "" || c.MikrotikPass == "" {
		log.Fatal("MIKROTIK_USER and MIKROTIK_PASS are required")
	}
	if c.WGEndpoint == "" {
		log.Fatal("WG_ENDPOINT is required (public host:port of the WireGuard server)")
	}
	if c.GoogleID == "" && c.MSID == "" {
		log.Print("WARNING: no login method configured (set GOOGLE_CLIENT_ID/SECRET or MS_CLIENT_ID/SECRET): nobody will be able to sign in")
	}
	if len(c.AllowedDomains) == 0 && len(c.AllowedEmails) == 0 {
		log.Print("WARNING: ALLOWED_DOMAINS and ALLOWED_EMAILS are empty: EVERY authenticated account gets a VPN profile")
	}
	if c.MSID != "" {
		switch c.MSTenant {
		case "common", "organizations", "consumers":
			log.Printf("WARNING: MS_TENANT=%s is multi-tenant: a rogue Entra tenant admin can spoof email addresses (nOAuth). Use your tenant GUID to enforce the tenant.", c.MSTenant)
		}
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
	mt  *mikrotik.Client

	mu    sync.Mutex
	confs map[string]confEntry // email -> last generated profile (RAM only)

	genMu sync.Mutex // serializes profile generation (peer listing + IP allocation)
}

func main() {
	cfg := loadConfig()
	app := &App{
		cfg:   cfg,
		mt:    mikrotik.New(cfg.MikrotikURL, cfg.MikrotikUser, cfg.MikrotikPass, cfg.MikrotikInsecure),
		confs: map[string]confEntry{},
	}

	if iface, err := app.mt.WGInterface(cfg.WGInterface); err != nil {
		log.Printf("WARNING: WireGuard interface %q unreachable/not found: %v", cfg.WGInterface, err)
	} else {
		log.Printf("MikroTik OK: interface %s, public key %s, port %s", iface.Name, iface.PublicKey, iface.ListenPort)
	}

	go app.cleanupLoop()

	// Cloudflare dynamic DNS: keep CF_RECORD's A record pointed at the
	// current public IP so a custom domain can be used for portal + endpoint.
	if cfg.CFToken != "" && cfg.CFRecord != "" {
		go cloudflareLoop(cfg)
	} else if cfg.CFToken != "" || cfg.CFRecord != "" {
		log.Print("WARNING: Cloudflare DDNS needs both CF_API_TOKEN and CF_RECORD, ignoring")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.handleIndex)
	mux.HandleFunc("GET /auth/{provider}", app.handleAuthStart)
	mux.HandleFunc("GET /auth/{provider}/callback", app.handleAuthCallback)
	mux.HandleFunc("POST /generate", app.handleGenerate)
	mux.HandleFunc("POST /revoke", app.handleRevoke)
	mux.HandleFunc("GET /profile.conf", app.handleDownload)
	mux.HandleFunc("GET /logout", app.handleLogout)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	handler := securityHeaders(mux)

	// With ACME_DOMAIN set, also serve HTTPS with an automatic Let's Encrypt
	// certificate (TLS-ALPN-01: the public side of LISTEN_TLS must be
	// reachable as https://ACME_DOMAIN:443 for issuance and renewals).
	if cfg.AcmeDomain != "" {
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.AcmeDomain),
			Cache:      autocert.DirCache(cfg.AcmeCache),
			Email:      cfg.AcmeEmail,
		}
		srv := &http.Server{Addr: cfg.ListenTLS, Handler: handler, TLSConfig: mgr.TLSConfig()}
		go func() {
			log.Printf("wg-portal HTTPS listening on %s (ACME domain %s, cache %s)", cfg.ListenTLS, cfg.AcmeDomain, cfg.AcmeCache)
			log.Fatal(srv.ListenAndServeTLS("", ""))
		}()
	}

	log.Printf("wg-portal listening on %s (public URL %s, peer TTL %s)", cfg.ListenAddr, cfg.PublicURL, cfg.TTL)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, handler))
}

// securityHeaders hardens every response. Cache-Control: no-store matters
// most: the profile page and .conf contain the client's private key.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// ---- sessions (HMAC-signed cookie, stateless) ----

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

// ---- authorization ----

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

// ---- handlers ----

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
		log.Printf("profile generation for %s failed: %v", email, err)
		http.Redirect(w, r, "/?err="+urlQuery("Error while creating the profile: "+err.Error()), http.StatusSeeOther)
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
		log.Printf("revoke for %s failed: %v", email, err)
	}
	a.mu.Lock()
	delete(a.confs, email)
	a.mu.Unlock()
	log.Printf("profile revoked for %s", email)
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
		http.Error(w, "no active profile", http.StatusNotFound)
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

// generateProfile: fresh keys, peer on the MikroTik (replacing any existing one), conf kept in RAM.
func (a *App) generateProfile(email string) error {
	// Serialized: concurrent generations would race on the free-IP scan and
	// could hand out the same address twice.
	a.genMu.Lock()
	defer a.genMu.Unlock()

	iface, err := a.mt.WGInterface(a.cfg.WGInterface)
	if err != nil {
		return fmt.Errorf("WireGuard interface: %w", err)
	}
	if err := a.removePeersFor(email); err != nil {
		return fmt.Errorf("removing previous peer: %w", err)
	}
	peers, err := a.mt.WGPeers(a.cfg.WGInterface)
	if err != nil {
		return fmt.Errorf("listing peers: %w", err)
	}
	used := make([]string, 0, len(peers))
	for _, p := range peers {
		used = append(used, p.AllowedAddress)
	}
	ip, err := wgutil.AllocateIP(a.cfg.WGSubnet, used)
	if err != nil {
		return err
	}
	priv, pub, err := wgutil.GenKeypair()
	if err != nil {
		return err
	}
	psk := base64.StdEncoding.EncodeToString(wgutil.RandomBytes(32))
	expires := time.Now().UTC().Add(a.cfg.TTL).Truncate(time.Second)

	err = a.mt.AddWGPeer(map[string]string{
		"interface":       a.cfg.WGInterface,
		"public-key":      pub,
		"preshared-key":   psk,
		"allowed-address": ip.String() + "/32",
		"comment":         peerComment(email, expires),
	})
	if err != nil {
		return fmt.Errorf("creating peer: %w", err)
	}

	endpoint := a.cfg.WGEndpoint
	if !strings.Contains(endpoint, ":") && iface.ListenPort != "" {
		endpoint += ":" + iface.ListenPort
	}
	conf := wgutil.BuildClientConf(priv, ip, a.cfg.WGSubnet.Bits(), a.cfg.WGDNS, iface.PublicKey, psk, a.cfg.WGAllowedIPs, endpoint)

	a.mu.Lock()
	a.confs[email] = confEntry{Conf: conf, IP: ip, Expires: expires}
	a.mu.Unlock()
	log.Printf("profile created for %s: ip %s, expires %s", email, ip, expires.Format(time.RFC3339))
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

// cleanupLoop removes expired peers; the expiry lives in the peer comment,
// so it keeps working even after a container restart.
func (a *App) cleanupLoop() {
	t := time.NewTicker(a.cfg.CleanupEvery)
	defer t.Stop()
	for range t.C {
		peers, err := a.mt.WGPeers(a.cfg.WGInterface)
		if err != nil {
			log.Printf("cleanup: listing peers failed: %v", err)
			continue
		}
		now := time.Now()
		for _, p := range peers {
			email, exp, ok := parsePeerComment(p.Comment)
			if !ok || now.Before(exp) {
				continue
			}
			if err := a.mt.DeleteWGPeer(p.ID); err != nil {
				log.Printf("cleanup: removing peer %s (%s) failed: %v", p.ID, email, err)
				continue
			}
			log.Printf("cleanup: expired peer removed (%s, expiry %s)", email, exp.Format(time.RFC3339))
			a.mu.Lock()
			if ce, okc := a.confs[email]; okc && !ce.Expires.After(exp) {
				delete(a.confs, email)
			}
			a.mu.Unlock()
		}
	}
}

// cloudflareLoop upserts the A record immediately and then every CF_INTERVAL.
func cloudflareLoop(cfg Config) {
	cf := cloudflare.New(cfg.CFToken)
	update := func() {
		ip, err := cloudflare.PublicIP(nil)
		if err != nil {
			log.Printf("cloudflare ddns: public IP lookup failed: %v", err)
			return
		}
		changed, err := cf.UpsertA(cfg.CFRecord, cfg.CFZone, ip, cfg.CFProxied)
		if err != nil {
			log.Printf("cloudflare ddns: %v", err)
			return
		}
		if changed {
			log.Printf("cloudflare ddns: %s -> %s (proxied=%v)", cfg.CFRecord, ip, cfg.CFProxied)
		}
	}
	update()
	t := time.NewTicker(cfg.CFInterval)
	defer t.Stop()
	for range t.C {
		update()
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
