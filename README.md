# Luma

Luma Auth is a lightweight, modern, and self-hostable authentication and token management server.
It’s designed as a plug-and-play alternative to heavier solutions like Auth0, Keycloak, or Duende IdentityServer, with simplicity, transparency, and developer control in mind.

Luma Auth handles everything from magic link logins and numeric code verification to OAuth2 / OpenID Connect token issuance, while keeping configuration effortless through a single `luma.config.json` file or environment variables. It only allows **passwordless** authentication methods.

It’s built entirely on Entity Framework Core, ASP.NET Core, and HMAC-secured tokens, with full flexibility to run on SQLite, PostgreSQL, or SQL Server, locally or in production.

## Features

- **OAuth 2.0 / OpenID Connect provider**
  - `authorization_code` (with mandatory **PKCE** for public clients), `refresh_token` (rotating), and `client_credentials` grants
  - Pushed Authorization Requests (PAR), token introspection and revocation, UserInfo, JWKS
  - Discovery: `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`
  - `query` and `form_post` response modes; `prompt=login|consent|select_account|none`
- **Passwordless interactive login**
  - Magic links (clickable on any device, with live polling on the original tab)
  - Numeric email codes
  - Self-service registration, account selection, and a consent screen with per-client/scope contracts
- **Pluggable persistence** — SQLite, PostgreSQL, or SQL Server via EF Core
- **JWT or opaque access tokens**, HMAC-hashed at rest, with key-rotation support
- **Horizontally scalable** — all state (login sessions, authorization state, authorization codes,
  consent) lives in the shared database, so you can run multiple instances behind a load balancer
- Runs out of the box: signing keys and the database are created automatically on first run

## Quick start

Requirements: .NET 9 SDK.

```bash
# from the repository root
dotnet run --project Luma.Server --launch-profile https
```

On first run Luma will:

1. Generate a development RSA signing keypair under `Luma.Server/Keys/` (if missing).
2. Create the SQLite database `auth.db` (if missing).

The server listens on `https://localhost:7105` (and `http://localhost:5089`). Open
`https://localhost:7105/.well-known/openid-configuration` to confirm it’s up.

> The shipped `luma.config.json` contains **development** HMAC and signing keys and a sample client
> secret. Replace all of them before deploying (see [Configuration](#configuration)).

### Sample clients

| client_id          | type         | secret (plain)     | PKCE     |
| ------------------ | ------------ | ------------------ | -------- |
| `luma-self-hosted` | confidential | `luma-dev-secret`  | optional |
| `luma-spa`         | public       | — (none)           | required |

Both are registered with redirect URI `https://localhost/callback` and resource `https://localhost`.

## How the login flow works

```
/authorize ──► (no session) ──► /login ──► /choose-method ─┬─► /verify-code ──┐
     ▲                                                      └─► /link-sent ────┤  (magic link, polled)
     │                                                                         ▼
     └──────────── (existing session, SSO) ───────────────►  consent needed? ─┬─► /consent ─► redirect to client with ?code
                                                                              └─► (already consented) redirect with ?code
```

- The `/authorize` endpoint validates the request, stores the authorization state, and drops a
  short-lived state-id cookie.
- If there’s no active login session it sends the user to `/login`; otherwise it reuses the session
  (SSO) but still enforces consent for any client/scope the user hasn’t approved.
- After authentication a login-session cookie is issued and the user is returned to the client with
  an authorization `code`.

## Testing the pages by hand (browser)

The interactive UI is the part you’ll want to click through. A few things make this easy:

1. **Trust the dev certificate once** so the browser doesn’t warn:
   `dotnet dev-certs https --trust`.
2. **Watch the server console.** With `Email.DeliveryMethod: "Logging"` (the default), every magic
   link and numeric code is printed to the console instead of being emailed — that’s where you read
   them during testing.
3. **The final redirect goes to `https://localhost/callback`,** which nothing is listening on, so the
   browser will show a “can’t connect” page **at a URL containing `?code=…&state=…`**. That code in
   the address bar *is* the successful result. (If you’d rather see a real page, add a redirect URI
   you control — e.g. `https://oauth.pstmn.io/v1/callback` for Postman — to the client in
   `luma.config.json` and use that as `redirect_uri`.)

Start each scenario by pasting an `/authorize` URL into the browser:

```
https://localhost:7105/authorize?response_type=code&client_id=luma-self-hosted&redirect_uri=https%3A%2F%2Flocalhost%2Fcallback&scope=openid%20email&state=test&resource=https%3A%2F%2Flocalhost
```

| Feature | How to test |
| --- | --- |
| **Register a new user** | Open the `/authorize` URL, enter an email that doesn’t exist yet → you land on the **Create account** page. Fill it in → you continue to “choose a method”. |
| **Numeric code login** | Choose **Email me a 6-digit code**, read the code from the **server console**, enter it. |
| **Magic link login (same device)** | Choose **Email me a magic link**, copy the link from the console, open it in a **new tab**. That tab shows “You’re verified”; the original tab is polling and continues automatically. |
| **Magic link login (cross-device)** | Same as above, but open the link in a different browser/incognito/phone. The original tab still completes on its own. |
| **Consent screen** | The first time a user authorizes a given client, the **consent** page lists the requested scopes. Approve → you’re redirected with a `code`. |
| **Consent is remembered** | Run the same `/authorize` URL again — you go straight to the `code` with no consent prompt (a consent contract was stored). |
| **Force re-consent** | Add `&prompt=consent` to the `/authorize` URL — the consent page shows again. |
| **Force re-login** | Add `&prompt=login` — your session is dropped and you must sign in again. |
| **Select account** | Add `&prompt=select_account` — choose “Continue as …” or “Use a different account”. |
| **Silent auth** | Add `&prompt=none`. With no session you’re redirected back with `error=login_required`; with a session but unapproved scopes, `error=consent_required`. |
| **PKCE (public client)** | Use `client_id=luma-spa` and add `&code_challenge=<S256 challenge>&code_challenge_method=S256`. The token exchange then requires the matching `code_verifier`. |
| **Logout** | Visit `https://localhost:7105/logout?post_logout_redirect_uri=https://localhost/signout-callback-oidc`. Your session cookie is cleared and you’re redirected (only to a registered post-logout URI). |
| **Profile** | After signing in, visit `https://localhost:7105/profile` to see the current account and sign out. |
| **Scales across instances** | Start a flow, restart the server (or run a second instance against the same database) mid-flow, then continue — it works, because state and codes live in the database, not in memory. |

After you copy a `code` out of the address bar, exchange it for tokens with the curl call in the next
section.

## Testing it end to end

A confidential-client run with `curl` (use `-k` for the dev certificate). The interactive pages use
HTTPS-only cookies, so test over `https://localhost:7105`.

**1. Machine-to-machine (`client_credentials`):**

```bash
curl -k -X POST https://localhost:7105/token \
  -d grant_type=client_credentials \
  -d client_id=luma-self-hosted \
  -d client_secret=luma-dev-secret \
  -d resource=https://localhost \
  -d scope=email
```

**2. Interactive authorization code:** open the URL below in a browser, sign in with any email
(a numeric code or magic link is written to the **server console** when `Email.DeliveryMethod` is
`Logging`), approve consent, and you’ll be redirected to `https://localhost/callback?code=…`.

```
https://localhost:7105/authorize?response_type=code&client_id=luma-self-hosted&redirect_uri=https%3A%2F%2Flocalhost%2Fcallback&scope=openid%20email&state=abc123&resource=https%3A%2F%2Flocalhost
```

**3. Exchange the code for tokens:**

```bash
curl -k -X POST https://localhost:7105/token \
  -d grant_type=authorization_code \
  -d code=THE_CODE_FROM_THE_REDIRECT \
  -d redirect_uri=https://localhost/callback \
  -d client_id=luma-self-hosted \
  -d client_secret=luma-dev-secret
```

**4. Call UserInfo, refresh, introspect, revoke:**

```bash
curl -k https://localhost:7105/userinfo -H "Authorization: Bearer ACCESS_TOKEN"

curl -k -X POST https://localhost:7105/token \
  -d grant_type=refresh_token -d refresh_token=REFRESH_TOKEN \
  -d client_id=luma-self-hosted -d client_secret=luma-dev-secret

curl -k -X POST https://localhost:7105/introspect \
  -d token=ACCESS_TOKEN -d client_id=luma-self-hosted -d client_secret=luma-dev-secret

curl -k -X POST https://localhost:7105/revoke \
  -d token=ACCESS_TOKEN -d client_id=luma-self-hosted -d client_secret=luma-dev-secret
```

Public clients (`luma-spa`) must add `code_challenge`/`code_challenge_method=S256` to `/authorize`
and `code_verifier` to the token request; they send no client secret.

## Endpoints

| Method   | Path                                        | Purpose                                  |
| -------- | ------------------------------------------- | ---------------------------------------- |
| GET      | `/authorize`                                | Start the authorization flow             |
| POST     | `/token`                                    | Token endpoint (all grants)              |
| GET/POST | `/userinfo`                                 | OIDC UserInfo                            |
| POST     | `/introspect`                               | Token introspection (confidential)       |
| POST     | `/revoke`                                   | Token revocation (confidential)          |
| POST     | `/par`                                      | Pushed Authorization Request             |
| GET      | `/logout`                                   | End session, optional post-logout redirect |
| GET      | `/jwks`                                      | JSON Web Key Set                         |
| GET      | `/.well-known/openid-configuration`         | OIDC discovery                           |
| GET      | `/.well-known/oauth-authorization-server`   | OAuth 2.0 metadata                       |
| GET/POST | `/login`, `/choose-method`, `/verify-code`, `/link-sent`, `/magic`, `/consent`, `/select-account`, `/register`, `/profile` | Interactive UI |

## Configuration

All configuration lives in `Luma.Server/luma.config.json` (JSON with comments allowed) and can be
overridden by environment variables.

- **Database** — `Provider` (`sqlite`, `postgres`, `sqlserver`) and `ConnectionString`.
- **Email** — `DeliveryMethod` is `Logging` (writes codes/links to the log; dev only) or `Smtp`
  (set `Smtp.Host`/`Port`/`Username`/`Password`).
- **OAuth** — `SupportedScopes`, `ParExpirationSeconds`, `AuthorizationCode.ValidForSeconds`, and the
  `Clients` array.
- **Tokens** — lifetimes/sizes for magic links, numeric codes, access tokens (`Jwt` or `Opaque`), and
  refresh tokens.
- **Keys**
  - `Hmac` — HMAC keys used to hash tokens/sessions at rest. Provide via config or the
    `LUMA_HMACSHA256_KEY_<id>` / `LUMA_HMACSHA256_DEFAULT_KEY_ID` environment variables.
  - `Jwt` — signing algorithm (`RS256` or `ES256`), default key id, and PEM file paths. Missing PEM
    files are generated on first run for local development.

### Client fields

Each entry in `OAuth.Clients` accepts: `ClientId`, `IsConfidential`, `ClientSecretSHA256_Base64`
(the **Base64 of the raw SHA-256 bytes** of the secret), `DisplayName`, `DefaultRedirectUri` /
`RedirectUris`, `DefaultResource` / `Resources`, `AllowedGrantTypes`, `DefaultScope` /
`AllowedScopes`, and `DefaultPostLogoutRedirectUri` / `PostLogoutRedirectUris`.

To compute a secret hash:

```bash
printf '%s' 'your-secret' | openssl dgst -sha256 -binary | openssl base64
```

### Running multiple instances

Luma is stateless at the process level — login sessions, authorization state, authorization codes,
and consent are all kept in the database. To scale horizontally:

- Point every instance at the **same** `postgres` or `sqlserver` database (SQLite is single-node).
- Give every instance the **same HMAC and JWT keys** (so cookies and tokens issued by one instance
  validate on another). Use the `LUMA_HMACSHA256_KEY_<id>` / `LUMA_HMACSHA256_DEFAULT_KEY_ID` /
  `LUMA_JWT_DEFAULT_KEY_ID` environment variables or a shared key volume rather than per-instance
  generated keys.
- Put the instances behind a load balancer. Sticky sessions are **not** required.

Authorization-code redemption is atomic (an interlocked database delete), so a code can be exchanged
exactly once even when concurrent requests land on different instances. Expired authorization state
and codes are swept periodically by a background service on each instance.

> Very high-throughput deployments may prefer a dedicated cache (e.g. Redis) for the short-lived
> authorization state/code stores to reduce write load on the primary database. The current
> implementation uses the relational database to avoid an extra dependency; the
> `IAuthorizationCodeProvider` / `IAuthorizationCodeStateProvider` interfaces are the seam to swap in
> such a backend.

### Production checklist

- Replace the development HMAC key(s) in `Keys.Hmac` (or supply via environment variables).
- Replace the auto-generated signing keys in `Keys.Jwt` with managed keys, shared across instances.
- Set real client secrets and `RedirectUris`.
- Set `Email.DeliveryMethod` to `Smtp` and configure the SMTP server.
- Use a production database (`postgres` or `sqlserver`); SQLite is for single-node/local use.

## License

**Luma Auth** is licensed under the **Elastic License 2.0**.

You may:

-   Use, copy, modify, and distribute Luma Auth for free, including in commercial projects.
-   Self-host it privately or within your own infrastructure.

You may not:

-   Offer Luma Auth itself as a **hosted or managed service** (e.g., “LumaAuth Cloud”).
-   Remove license notices or trademarks.

See the [LICENSE](./LICENSE) file for full terms.
