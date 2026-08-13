# wg-portal — VPN self-service WireGuard per MikroTik

Portale web minimale (singolo binario Go, immagine Docker `FROM scratch`, ~5 MB) che:

1. autentica l'utente via **Google / Microsoft** (OAuth2/OIDC, chiavi nel `.env`)
2. genera la coppia di chiavi **WireGuard** (mai salvate su disco)
3. crea il **peer sul MikroTik via REST API** (con preshared-key)
4. mostra **QR code** + tasto **"Scarica profilo .conf"**
5. **rimuove automaticamente il peer alla scadenza** (`WG_TTL` nel `.env`)

La scadenza è scritta nel *commento* del peer sul router
(`wg-portal|email|expires=...`), quindi il cleanup funziona anche dopo un
riavvio del container: nessun database, nessun volume.

## Requisiti sul router

- RouterOS v7 con REST API attiva (servizio `www` o `www-ssl`)
- Un'interfaccia WireGuard dedicata ai client del portale, es.:

```
/interface/wireguard add name=wg-portal listen-port=13300
/ip/address add address=10.99.99.1/24 interface=wg-portal
```

- Un utente API dedicato (gruppo con policy `read,write,api,rest-api`):

```
/user/group add name=wg-portal policy=read,write,api,rest-api
/user add name=wg-portal group=wg-portal password=<password-robusta>
```

- Regola firewall per la porta WireGuard dal WAN:

```
/ip/firewall/filter add chain=input protocol=udp dst-port=13300 action=accept comment="wg-portal"
```

## Configurazione

```
cp .env.example .env   # e compila i valori
```

Nota OAuth: Google e Microsoft accettano solo redirect URI **HTTPS**
(tranne `http://localhost`). Serve quindi un hostname pubblico con TLS
davanti al portale (reverse proxy, DDNS `mynetname.net` + certificato, ecc.)
impostato in `PUBLIC_URL`.

## Esecuzione su Docker classico (x86/ARM64)

```
docker compose up -d --build
```

## Esecuzione come container nativo RouterOS (es. L009, hAP ax, RB5009)

Build dell'immagine per l'architettura del router e export in tar
(`arm/v7` per i MikroTik ARM 32-bit come L009, `arm64` per RB5009/hAP ax):

```
docker buildx build --platform linux/arm/v7 -t wg-portal:arm --load .
docker save wg-portal:arm -o wg-portal.tar
```

Carica `wg-portal.tar` sul router (Files), poi:

```
/interface/veth add name=veth-portal address=172.18.0.2/24 gateway=172.18.0.1
/ip/address add address=172.18.0.1/24 interface=veth-portal
/interface/list/member add list=LAN interface=veth-portal
/container/envs add list=portal name=MIKROTIK_URL value="http://172.18.0.1"
/container/envs add list=portal name=MIKROTIK_USER value="wg-portal"
/container/envs add list=portal name=MIKROTIK_PASS value="<password>"
... (tutte le altre variabili del .env) ...
/container add file=wg-portal.tar interface=veth-portal envlist=portal \
    root-dir=wg-portal-root start-on-boot=yes logging=yes
/container/start 0
```

Il portale risponde su `http://172.18.0.2:8080` (raggiungibile dalla LAN).
Per esporlo con TLS si può usare un reverse proxy o il
`/ip/firewall/nat` dst-nat del router.

## Variabili principali (`.env`)

| Variabile | Descrizione |
|---|---|
| `WG_TTL` | Durata del profilo (`30m`, `8h`, `7d`): alla scadenza il peer sparisce dal router |
| `WG_INTERFACE` | Interfaccia WireGuard del router su cui creare i peer |
| `WG_SUBNET` | Pool IP client (il `.1` è del router) |
| `WG_ENDPOINT` | `host[:porta]` pubblico del server WireGuard, finisce nel `.conf` |
| `WG_ALLOWED_IPS` | Rotte spinte al client (`0.0.0.0/0` = tutto il traffico) |
| `ALLOWED_DOMAINS` / `ALLOWED_EMAILS` | Allowlist accessi (vuote = chiunque si autentichi!) |
| `DEV_FAKE_AUTH` | Email di test: abilita login finto senza OAuth — **solo sviluppo** |

## Sicurezza

- La chiave privata del client esiste solo nella RAM del container e nel QR/`.conf` mostrato all'utente.
- Ogni rigenerazione elimina il peer precedente dell'utente.
- Un utente = un peer; il pulsante "Revoca" elimina subito il peer dal router.
- Usare un utente RouterOS dedicato per il portale, non `admin`.
