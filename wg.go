package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// genKeypair generates a WireGuard (Curve25519) key pair in base64.
func genKeypair() (privB64, pubB64 string, err error) {
	raw := randomBytes(32)
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

// allocateIP picks the first free host in the subnet, skipping network and .1 (server).
func allocateIP(subnet netip.Prefix, peers []WGPeer) (netip.Addr, error) {
	used := map[netip.Addr]bool{}
	for _, p := range peers {
		for _, part := range strings.Split(p.AllowedAddress, ",") {
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

func buildClientConf(priv string, ip netip.Addr, bits int, dns, serverPub, psk, allowedIPs, endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/%d\n", priv, ip, bits)
	if dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = 25\n",
		serverPub, psk, allowedIPs, endpoint)
	return b.String()
}
