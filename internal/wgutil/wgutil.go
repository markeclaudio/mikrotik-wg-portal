// Package wgutil holds the WireGuard helpers: key generation, client IP
// allocation and .conf rendering.
package wgutil

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
)

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// GenKeypair generates a WireGuard (Curve25519) key pair in base64.
func GenKeypair() (privB64, pubB64 string, err error) {
	raw := RandomBytes(32)
	// clamping as per the Curve25519 spec
	raw[0] &= 248
	raw[31] &= 127
	raw[31] |= 64
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// AllocateIP picks the first free host in the subnet, skipping the network
// address and .1 (the router). usedAddrs entries may be "a.b.c.d" or "a.b.c.d/nn".
func AllocateIP(subnet netip.Prefix, usedAddrs []string) (netip.Addr, error) {
	used := map[netip.Addr]bool{}
	for _, entry := range usedAddrs {
		for _, part := range strings.Split(entry, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if pfx, err := netip.ParsePrefix(part); err == nil {
				used[pfx.Addr()] = true
			} else if a, err := netip.ParseAddr(part); err == nil {
				used[a] = true
			}
		}
	}
	first := subnet.Addr().Next() // .1 = server
	for ip := first.Next(); subnet.Contains(ip); ip = ip.Next() {
		if !used[ip] {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no free address in %s", subnet)
}

func BuildClientConf(priv string, ip netip.Addr, bits int, dns, serverPub, psk, allowedIPs, endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/%d\n", priv, ip, bits)
	if dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = 25\n",
		serverPub, psk, allowedIPs, endpoint)
	return b.String()
}
