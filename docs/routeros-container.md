# Running wg-portal as a native RouterOS container

Tested on a MikroTik L009UiGS (32-bit ARM) with RouterOS 7.23. Also applies to
hAP ax / RB5009 (arm64) and CHR/x86 (amd64) — just change the build platform.

## 0. One-time prerequisites on the router

**Container package** — download the `container` extra package matching your
RouterOS version/architecture from mikrotik.com, drop it in Files, reboot.

**Device-mode** — containers are disabled by default as a security measure:

```
/system/device-mode/print
/system/device-mode/update container=yes
```

The router then asks for **physical proof of access**: press the reset/mode
button (short press!) or power-cycle the device within the shown time window,
otherwise the change is discarded. This cannot be done remotely by design.

## 1. WireGuard interface for portal clients

```
/interface/wireguard add name=wg-portal listen-port=13300
/ip/address add address=10.99.99.1/24 interface=wg-portal
/ip/firewall/filter add chain=input protocol=udp dst-port=13300 action=accept \
    place-before=0 comment="wg-portal handshake"
```

## 2. Dedicated API user for the portal

```
/user/group add name=wg-portal policy=read,write,api,rest-api
/user add name=wg-portal group=wg-portal password=<strong-password>
```

The REST API rides on the `www` (or `www-ssl`) service — make sure it is
enabled and reachable from the container subnet.

## 3. Build the image and upload it

On any machine with Docker:

```
docker buildx build --platform linux/arm/v7 -t wg-portal:arm --load .
docker save wg-portal:arm -o wg-portal.tar
```

(`linux/arm/v7` for 32-bit ARM devices like the L009; `linux/arm64` for
RB5009/hAP ax; `linux/amd64` for CHR.) Upload `wg-portal.tar` to the router's
Files via Winbox drag-and-drop, FTP or SFTP. The image is ~9 MB.

## 4. Container network (veth)

```
/interface/veth add name=veth-portal address=172.18.0.2/24 gateway=172.18.0.1
/ip/address add address=172.18.0.1/24 interface=veth-portal
/interface/list/member add list=LAN interface=veth-portal
```

Adding the veth to the `LAN` interface list lets the container reach the REST
API on `172.18.0.1` and lets LAN clients reach the portal, with the default
firewall. Adapt if your firewall is stricter.

## 5. Environment variables

One `add` per variable (RouterOS REST users: the fields are `list`, `key`,
`value`):

```
/container/envs add list=portal key=MIKROTIK_URL value="http://172.18.0.1"
/container/envs add list=portal key=MIKROTIK_USER value="wg-portal"
/container/envs add list=portal key=MIKROTIK_PASS value="<strong-password>"
/container/envs add list=portal key=WG_INTERFACE value="wg-portal"
/container/envs add list=portal key=WG_SUBNET value="10.99.99.0/24"
/container/envs add list=portal key=WG_ENDPOINT value="vpn.example.com:13300"
/container/envs add list=portal key=WG_DNS value="192.168.1.1"
/container/envs add list=portal key=WG_ALLOWED_IPS value="192.168.1.0/24"
/container/envs add list=portal key=WG_TTL value="8h"
/container/envs add list=portal key=PUBLIC_URL value="https://vpn.example.com"
/container/envs add list=portal key=SESSION_SECRET value="<long-random-string>"
/container/envs add list=portal key=GOOGLE_CLIENT_ID value="..."
/container/envs add list=portal key=GOOGLE_CLIENT_SECRET value="..."
/container/envs add list=portal key=ALLOWED_DOMAINS value="example.com"
```

See [oauth-setup.md](oauth-setup.md) for obtaining the OAuth credentials and
`.env.example` for the full variable reference.

## 6. Create and start the container

```
/container add file=wg-portal.tar interface=veth-portal env=portal \
    root-dir=wg-portal-root start-on-boot=yes logging=yes \
    comment="wg-portal self-service VPN"
/container/print
/container/start 0
```

Note: the CLI parameter linking the env list is `env` on current RouterOS
versions (older docs mention `envlist`). Logs go to `/log` with
`logging=yes`.

The portal is now on `http://172.18.0.2:8080` from the LAN.

## 7. Automatic HTTPS with the built-in ACME client (recommended)

Google/Microsoft OAuth requires `PUBLIC_URL` to be HTTPS. The portal can get
and renew a **Let's Encrypt certificate by itself** (TLS-ALPN-01) — no
reverse proxy needed.

**a.** Make sure the router has a public DNS name. The free MikroTik cloud
DDNS is perfect:

```
/ip/cloud set ddns-enabled=yes
/ip/cloud print    # -> dns-name: xxxxxxxx.sn.mynetname.net
```

**b.** Persistent mount for the certificate cache (otherwise every container
restart burns a Let's Encrypt issuance — rate limits apply):

```
/container/mounts add name=acme-cache src=/acme-cache dst=/acme
```

and add `mounts=acme-cache` when creating the container.

**c.** Environment variables:

```
/container/envs add list=portal key=ACME_DOMAIN value="xxxxxxxx.sn.mynetname.net"
/container/envs add list=portal key=ACME_EMAIL value="you@example.com"
/container/envs add list=portal key=PUBLIC_URL value="https://xxxxxxxx.sn.mynetname.net"
```

**d.** Forward public port 443 to the container's HTTPS listener (8443):

```
/ip/firewall/nat add chain=dstnat protocol=tcp dst-port=443 \
    in-interface-list=WAN action=dst-nat to-addresses=172.18.0.2 to-ports=8443 \
    comment="wg-portal HTTPS"
```

At the first HTTPS request the container requests the certificate (a few
seconds); renewals are automatic. Port 80 stays closed and the router's own
web services are never exposed.

The WireGuard handshake itself (`WG_ENDPOINT`, UDP 13300) does not need any
of this — only the web portal does:

```
/ip/firewall/filter add chain=input protocol=udp dst-port=13300 action=accept \
    place-before=0 comment="wg-portal handshake"
```

Alternative: any reverse proxy you already run (nginx/caddy/traefik)
forwarding `https://vpn.example.com` → `172.18.0.2:8080`, with `ACME_DOMAIN`
left empty.

## Removal

```
/container/stop 0
/container/remove 0
/container/envs remove [find list=portal]
/interface/list/member remove [find interface=veth-portal]
/ip/address remove [find interface=veth-portal]
/interface/veth remove veth-portal
/ip/address remove [find interface=wg-portal]
/interface/wireguard remove wg-portal
/file/remove wg-portal.tar
```
