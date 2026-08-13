// Package mikrotik is a minimal RouterOS v7 REST API client covering the
// WireGuard endpoints used by the portal.
package mikrotik

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	base string
	user string
	pass string
	hc   *http.Client
}

// New creates a client for baseURL (e.g. "http://172.18.0.1").
// insecure skips TLS verification for self-signed www-ssl certificates.
func New(baseURL, user, pass string, insecure bool) *Client {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{
		base: baseURL,
		user: user,
		pass: pass,
		hc:   &http.Client{Timeout: 15 * time.Second, Transport: tr},
	}
}

func (m *Client) req(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, m.base+"/rest"+path, rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(m.user, m.pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := m.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("mikrotik %s %s: HTTP %d: %s", method, path, res.StatusCode, string(msg))
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

type WGIface struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public-key"`
	ListenPort string `json:"listen-port"`
}

type WGPeer struct {
	ID             string `json:".id"`
	Interface      string `json:"interface"`
	PublicKey      string `json:"public-key"`
	AllowedAddress string `json:"allowed-address"`
	Comment        string `json:"comment"`
	Dynamic        string `json:"dynamic"`
}

func (m *Client) WGInterface(name string) (WGIface, error) {
	var list []WGIface
	if err := m.req("GET", "/interface/wireguard?name="+url.QueryEscape(name), nil, &list); err != nil {
		return WGIface{}, err
	}
	if len(list) == 0 {
		return WGIface{}, fmt.Errorf("interface %q not found", name)
	}
	return list[0], nil
}

func (m *Client) WGPeers(iface string) ([]WGPeer, error) {
	var list []WGPeer
	err := m.req("GET", "/interface/wireguard/peers?interface="+url.QueryEscape(iface), nil, &list)
	return list, err
}

func (m *Client) AddWGPeer(fields map[string]string) error {
	return m.req("PUT", "/interface/wireguard/peers", fields, nil)
}

// DeleteWGPeer removes a peer by .id. The id is passed as-is: RouterOS wants
// the literal "*2E" and rejects a %-escaped asterisk.
func (m *Client) DeleteWGPeer(id string) error {
	return m.req("DELETE", "/interface/wireguard/peers/"+id, nil, nil)
}
