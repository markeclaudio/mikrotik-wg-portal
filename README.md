# wg-portal — self-service WireGuard VPN portal for MikroTik

Minimal web portal (single Go binary, `FROM scratch` Docker image, ~5 MB) that:

1. authenticates the user via **Google / Microsoft** (OAuth2/OIDC, keys in `.env`)
2. generates the **WireGuard key pair** (never written to disk)
3. creates the **peer on the MikroTik via REST API** (with preshared key)
4. shows a **QR code** + a **"Download .conf profile"** button
5. **automatically removes the peer when it expires** (`WG_TTL` in `.env`)

The expiry timestamp is stored in the peer *comment* on the router
(`wg-portal|email|expires=...`), so cleanup keeps working even after the
container restarts: no database, no volumes.

## Router requirements

- RouterOS v7 with the REST API enabled (`www` or `www-ssl` service)
- A WireGuard interface dedicated to portal clients, e.g.:

```
/interface/wireguard add name=wg-portal listen-port=13300
/ip/address add address=10.99.99.1/24 interface=wg-portal
```

- A dedicated API user (group with `read,write,api,rest-api` policies):

```
/user/group add name=wg-portal policy=read,write,api,rest-api
/user add name=wg-portal group=wg-portal password=<strong-password>
```

- A firewall rule for the WireGuard port from WAN:

```
/ip/firewall/filter add chain=input protocol=udp dst-port=13300 action=accept comment="wg-portal"
```

## Configuration

```
cp .env.example .env   # then fill in the values
```

OAuth note: Google and Microsoft only accept **HTTPS** redirect URIs
(except `http://localhost`). You therefore need a public hostname with TLS
in front of the portal (reverse proxy, `mynetname.net` DDNS + certificate,
etc.) configured in `PUBLIC_URL`.

## Running on regular Docker (x86/ARM64)

```
docker compose up -d --build
```

## Running as a native RouterOS container (e.g. L009, hAP ax, RB5009)

Build the image for the router architecture and export it as a tar
(`arm/v7` for 32-bit ARM MikroTiks like the L009, `arm64` for RB5009/hAP ax):

```
docker buildx build --platform linux/arm/v7 -t wg-portal:arm --load .
docker save wg-portal:arm -o wg-portal.tar
```

Upload `wg-portal.tar` to the router (Files), then:

```
/interface/veth add name=veth-portal address=172.18.0.2/24 gateway=172.18.0.1
/ip/address add address=172.18.0.1/24 interface=veth-portal
/interface/list/member add list=LAN interface=veth-portal
/container/envs add list=portal name=MIKROTIK_URL value="http://172.18.0.1"
/container/envs add list=portal name=MIKROTIK_USER value="wg-portal"
/container/envs add list=portal name=MIKROTIK_PASS value="<password>"
... (all the other .env variables) ...
/container add file=wg-portal.tar interface=veth-portal envlist=portal \
    root-dir=wg-portal-root start-on-boot=yes logging=yes
/container/start 0
```

The portal listens on `http://172.18.0.2:8080` (reachable from the LAN).
To expose it with TLS use a reverse proxy or the router's
`/ip/firewall/nat` dst-nat.

## Main variables (`.env`)

| Variable | Description |
|---|---|
| `WG_TTL` | Profile lifetime (`30m`, `8h`, `7d`): when it expires the peer is removed from the router |
| `WG_INTERFACE` | Router WireGuard interface where peers are created |
| `WG_SUBNET` | Client IP pool (`.1` belongs to the router) |
| `WG_ENDPOINT` | Public `host[:port]` of the WireGuard server, goes into the `.conf` |
| `WG_ALLOWED_IPS` | Routes pushed to the client (`0.0.0.0/0` = all traffic) |
| `ALLOWED_DOMAINS` / `ALLOWED_EMAILS` | Access allowlist (empty = anyone who authenticates!) |
| `DEV_FAKE_AUTH` | Test email: enables fake login without OAuth — **development only** |

## Security

- The client private key only exists in the container RAM and in the QR/`.conf` shown to the user.
- Every regeneration deletes the user's previous peer.
- One user = one peer; the "Revoke" button removes the peer from the router immediately.
- Use a dedicated RouterOS user for the portal, not `admin`.
