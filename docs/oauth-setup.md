# OAuth setup — Google & Microsoft

The portal signs users in with OpenID Connect. You need to register the portal
as an "application" on Google and/or Microsoft (at least one), copy the
resulting **Client ID** and **Client Secret** into the `.env`, and register the
portal's **redirect URI**.

Both providers require the redirect URI to be **HTTPS** — plain `http://` is
only accepted for `localhost` testing. Decide your public URL first (e.g.
`https://vpn.example.com`) and set it as `PUBLIC_URL` in the `.env`; every
redirect URI below is derived from it.

| Provider | Redirect URI to register |
|---|---|
| Google | `$PUBLIC_URL/auth/google/callback` |
| Microsoft | `$PUBLIC_URL/auth/microsoft/callback` |

---

## Google

1. Go to <https://console.cloud.google.com/> and sign in.
2. Create a project (top bar → project selector → **New project**), e.g.
   `wg-portal`. Any name works; it is not shown to users after setup.
3. Configure the consent screen: **APIs & Services → OAuth consent screen**
   (Google may call it "Google Auth Platform / Branding"):
   - **App name**: e.g. `WireGuard VPN`, and your support email.
   - **Audience / User type**:
     - **Internal** — only accounts of your Google Workspace organization can
       log in. Best choice if you have Workspace: nothing else to configure.
     - **External** — any Google account can *authenticate* (the portal still
       enforces its own `ALLOWED_DOMAINS`/`ALLOWED_EMAILS` allowlist).
       While the app is in **Testing** status you must add each user under
       **Test users**; click **Publish app** to remove that limit. Since the
       portal only asks for `openid email` (non-sensitive scopes), publishing
       does not require Google's verification review.
4. Create the credentials: **APIs & Services → Credentials → Create
   credentials → OAuth client ID**:
   - **Application type**: `Web application`
   - **Name**: `wg-portal`
   - **Authorized redirect URIs** → **Add URI**:
     `https://vpn.example.com/auth/google/callback` (your `PUBLIC_URL` +
     `/auth/google/callback`, exact match, no trailing slash)
5. Copy the values shown into the `.env`:

```dotenv
GOOGLE_CLIENT_ID=1234567890-abcdefg.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxxxxxx
```

> The client secret is only shown at creation time. If you lose it, open the
> client and generate a new secret.

---

## Microsoft (Entra ID / Azure AD)

1. Go to <https://entra.microsoft.com> (or <https://portal.azure.com>) →
   **Microsoft Entra ID** → **App registrations** → **New registration**.
2. Fill in:
   - **Name**: `wg-portal`
   - **Supported account types** — this decides who can authenticate and the
     matching `MS_TENANT` value in the `.env`:

     | Choice in the portal | `MS_TENANT` value |
     |---|---|
     | Accounts in this organizational directory only (single tenant) | your **Directory (tenant) ID** (or `yourdomain.onmicrosoft.com`) |
     | Accounts in any organizational directory (multitenant) | `organizations` |
     | Any organizational directory + personal Microsoft accounts | `common` |
     | Personal Microsoft accounts only | `consumers` |

     For a company VPN the **single tenant** option is almost always what you
     want.
   - **Redirect URI**: platform `Web`, value
     `https://vpn.example.com/auth/microsoft/callback` (your `PUBLIC_URL` +
     `/auth/microsoft/callback`)
3. Register, then from the app's **Overview** page copy:
   - **Application (client) ID** → `MS_CLIENT_ID`
   - **Directory (tenant) ID** → `MS_TENANT` (single-tenant setups)
4. Create the secret: **Certificates & secrets → Client secrets → New client
   secret**. Pick an expiry (max 24 months — put a reminder in your calendar,
   you will need to rotate it) and copy the **Value** column (⚠ not the
   "Secret ID") immediately: it is never shown again.
5. Permissions: nothing to do. The portal only requests the OpenID scopes
   (`openid email`), which are granted on first login without admin consent.
   If your tenant requires admin consent for every app, an admin can grant it
   from **API permissions → Grant admin consent**.

Resulting `.env` entries:

```dotenv
MS_CLIENT_ID=11111111-2222-3333-4444-555555555555
MS_CLIENT_SECRET=abc8Q~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
MS_TENANT=99999999-8888-7777-6666-555555555555
```

---

## Finishing the `.env`

With the credentials in place, the minimum login-related block looks like:

```dotenv
PUBLIC_URL=https://vpn.example.com
SESSION_SECRET=<long random string, e.g. output of: openssl rand -base64 32>

GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
# and/or
MS_CLIENT_ID=...
MS_CLIENT_SECRET=...
MS_TENANT=...

# Who may actually get a VPN profile (authentication alone is not enough):
ALLOWED_DOMAINS=example.com          # comma-separated email domains
ALLOWED_EMAILS=guest@gmail.com       # and/or individual addresses
```

⚠ If both `ALLOWED_DOMAINS` and `ALLOWED_EMAILS` are empty, **every**
successfully authenticated account gets a VPN profile. Always set at least one
of them in production.

You can leave either provider's variables empty: the corresponding button
simply disappears from the login page.

🔒 **Microsoft hardening**: prefer a single-tenant app registration and set
`MS_TENANT` to the tenant **GUID** (Directory ID), not the domain name. The
portal then verifies the `tid` claim of every token and rejects logins from
any other tenant — this closes the "nOAuth" email-spoofing vector of
multi-tenant apps. With `common`/`organizations` a warning is logged at
startup. Accounts whose email the IdP reports as unverified are rejected.

## Troubleshooting

- **`redirect_uri_mismatch` (Google) / `AADSTS50011` (Microsoft)** — the URI
  registered on the provider differs from `PUBLIC_URL` +
  `/auth/<provider>/callback`. Check scheme (https), host, port and the exact
  path; no trailing slash.
- **Google `access_denied` in Testing status** — the account is not in the
  Test users list and the app is not published.
- **Microsoft `AADSTS700016` / `unauthorized_client`** — wrong `MS_TENANT`
  for the chosen "supported account types" (e.g. a personal account against a
  single-tenant app).
- **`Account not authorized: ...` shown by the portal** — the login worked;
  the email simply is not matched by `ALLOWED_DOMAINS`/`ALLOWED_EMAILS`.
