# wg-portal — self-service WireGuard VPN portal for MikroTik

Minimal web portal (single Go binary, `FROM scratch` Docker image, ~9 MB) that:

1. authenticates the user via **Google / Microsoft** (OAuth2/OIDC, keys in `.env`)
2. generates the **WireGuard key pair** (never written to disk)
3. creates the **peer on the MikroTik via REST API** (with preshared key)
4. shows a **QR code** + a **"Download .conf profile"** button
5. **automatically removes the peer when it expires** (`WG_TTL` in `.env`)

The expiry timestamp is stored in the peer *comment* on the router
(`wg-portal|email|expires=...`), so cleanup keeps working even after the
container restarts: no database, no volumes. Small enough to run **directly
on the router** as a native RouterOS container.

## Repository layout

```
cmd/wg-portal/        application: HTTP handlers, OAuth, session, HTML
internal/mikrotik/    RouterOS v7 REST API client
internal/wgutil/      WireGuard helpers: keygen, IP allocation, .conf builder
docs/oauth-setup.md   how to get Google/Microsoft credentials for the .env
docs/routeros-container.md  full RouterOS deployment guide (L009 & co.)
Dockerfile            multi-arch build (amd64 / arm64 / arm v7)
docker-compose.yml    for running on a regular Docker host
.env.example          all configuration variables, commented
```

## Quick start

```bash
cp .env.example .env
```

1. Fill in the OAuth credentials — follow **[docs/oauth-setup.md](docs/oauth-setup.md)**
   (step-by-step for both Google Cloud Console and Microsoft Entra ID).
2. Prepare the router (WireGuard interface, dedicated API user) and fill in
   the MikroTik/WireGuard variables — see the header comments in
   [.env.example](.env.example).
3. Run it:
   - on a Docker host: `docker compose up -d --build`
   - on the MikroTik itself: follow **[docs/routeros-container.md](docs/routeros-container.md)**

## Prebuilt images

Every push to `main` builds the image for `linux/amd64`, `linux/arm64` and
`linux/arm/v7` via GitHub Actions:

- **Registry (multi-arch)**: `ghcr.io/markeclaudio/mikrotik-wg-portal:latest`
  — usable with `docker pull` or directly from RouterOS
  (`/container add remote-image=...`, see the RouterOS guide).
- **RouterOS tar files**: on the
  [Actions page](https://github.com/markeclaudio/mikrotik-wg-portal/actions)
  every run exposes a `wg-portal-routeros-tars` artifact with one
  `wg-portal-<arch>.tar` per architecture, ready for `/container add file=...`.
  Tagged releases (`v*`) also attach the tars to the
  [Releases page](https://github.com/markeclaudio/mikrotik-wg-portal/releases)
  (downloadable without a GitHub account).

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

Full reference with comments: [.env.example](.env.example).

## Security

- The client private key only exists in the container RAM and in the QR/`.conf` shown to the user.
- Every regeneration deletes the user's previous peer; "Revoke" removes it immediately.
- One user = one peer, tracked via the peer comment.
- Use a dedicated RouterOS user for the portal (policy `read,write,api,rest-api`), not `admin`.
- Set `ALLOWED_DOMAINS`/`ALLOWED_EMAILS`: authentication alone should not grant VPN access.
