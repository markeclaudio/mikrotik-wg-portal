// Package cloudflare keeps an A record of a Cloudflare-managed zone pointed
// at the current public IP (dynamic-DNS style), using an API token.
package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

type Client struct {
	token string
	hc    *http.Client

	zoneID   string
	recordID string
}

func New(token string) *Client {
	return &Client{token: token, hc: &http.Client{Timeout: 15 * time.Second}}
}

type apiEnvelope struct {
	Success bool            `json:"success"`
	Errors  []struct{ Message string } `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

func (c *Client) req(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, apiBase+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var env apiEnvelope
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		return fmt.Errorf("cloudflare %s %s: HTTP %d: %w", method, path, res.StatusCode, err)
	}
	if !env.Success {
		msg := "unknown error"
		if len(env.Errors) > 0 {
			msg = env.Errors[0].Message
		}
		return fmt.Errorf("cloudflare %s %s: %s", method, path, msg)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// findZone resolves the zone containing record: for "vpn.example.com" it
// tries "vpn.example.com", then "example.com", ... zoneName overrides the search.
func (c *Client) findZone(record, zoneName string) (string, error) {
	candidates := []string{}
	if zoneName != "" {
		candidates = append(candidates, zoneName)
	} else {
		parts := strings.Split(record, ".")
		for i := 0; i < len(parts)-1; i++ {
			candidates = append(candidates, strings.Join(parts[i:], "."))
		}
	}
	for _, cand := range candidates {
		var zones []zone
		if err := c.req("GET", "/zones?name="+cand, nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("no Cloudflare zone found for %q (token missing Zone:Read permission, or wrong account?)", record)
}

// UpsertA points record (e.g. "vpn.example.com") at ip. proxied must stay
// false for WireGuard endpoints and TLS-ALPN ACME issuance to work.
// Returns true when the record was created or its content changed.
func (c *Client) UpsertA(record, zoneName, ip string, proxied bool) (bool, error) {
	if c.zoneID == "" {
		id, err := c.findZone(record, zoneName)
		if err != nil {
			return false, err
		}
		c.zoneID = id
	}
	var recs []dnsRecord
	if err := c.req("GET", "/zones/"+c.zoneID+"/dns_records?type=A&name="+record, nil, &recs); err != nil {
		return false, err
	}
	want := dnsRecord{Type: "A", Name: record, Content: ip, TTL: 60, Proxied: proxied}
	if len(recs) == 0 {
		if err := c.req("POST", "/zones/"+c.zoneID+"/dns_records", want, nil); err != nil {
			return false, err
		}
		return true, nil
	}
	cur := recs[0]
	if cur.Content == ip && cur.Proxied == proxied {
		c.recordID = cur.ID
		return false, nil
	}
	if err := c.req("PUT", "/zones/"+c.zoneID+"/dns_records/"+cur.ID, want, nil); err != nil {
		return false, err
	}
	c.recordID = cur.ID
	return true, nil
}

// PublicIP returns the current public IPv4, asking Cloudflare first and
// falling back to ipify.
func PublicIP(hc *http.Client) (string, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	if res, err := hc.Get("https://1.1.1.1/cdn-cgi/trace"); err == nil {
		defer res.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		for _, line := range strings.Split(string(body), "\n") {
			if v, ok := strings.CutPrefix(line, "ip="); ok && strings.Count(v, ".") == 3 {
				return strings.TrimSpace(v), nil
			}
		}
	}
	res, err := hc.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if strings.Count(ip, ".") != 3 {
		return "", fmt.Errorf("unexpected public IP answer: %q", ip)
	}
	return ip, nil
}
