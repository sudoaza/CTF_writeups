# meshgate

Status: BLOCKED (unsolved). Web — an enterprise file-sync gateway ("Meshgate gateway 3.2.1",
Flask, Python 3.12.14, behind nginx) with a self-hosted OIDC IdP and an admin "update center"
that ships releases. Key idea: the flag is gated behind an admin-only release-publish capability
(attested corporate SSO + a bootstrap token), and every path to those secrets requires the app
source, which no primitive can read.

## Recon
- App: Flask "Meshgate gateway 3.2.1", Python 3.12.14, nginx front; internal worker on
  `127.0.0.1:8001` (`INTERNAL_URL` env), port 5000 also live; K8s env (10.30.0.1).
- OIDC self-hosted IdP at `/idp/*` (RS256, `kid=meshgate-idp-2026`), `client_id=meshgate-gw`;
  token endpoint needs `client_secret` (unknown).
- `/api/help` = full API reference. Notable endpoints:
  - `POST /auth/sso/federated` -> activate service capability from attested Corp SSO id_token
    (form field `id_token`); requires step-up attestation first.
  - `POST /auth/sso/attest/start` -> `{min_interval_s, nonce, round, rounds_required:1}`; the
    step needs an opaque "attestation token".
  - `POST /api/release/stage` -> 403 "release-publish capability required".
  - `GET /admin/session/adopt?t=<console bootstrap token>` -> adopt an admin session.
  - `GET /admin/status/health` -> edge-cached, worker-revalidated, `{console_token}` banner slot
    (admin only).
  - `GET /api/experiments` -> feature flags; `POST /api/experiments {flag,enabled}` overrides
    any flag incl `admin_console_preview`.
  - `GET /api/support/bundle` -> env leak; FLAG + GPG_KEY redacted.
  - `GET /api/unfurl?url=` -> http-only SSRF (title+snippet); `GET /import?url=` -> http-only
    SSRF (byte count).
- `/api/directory` -> real names/emails: admin Dana Whitaker (`d.whitaker@meshgate.corp`),
  jordan Jordan Okafor (`j.okafor@meshgate.corp`), releasebot Release Bot
  (`releasebot@meshgate.corp`). Avatar = md5(email).

## Analysis
- Observation: `/idp/register` has mass assignment — a `groups` field is stored and emitted in
  userinfo (`groups=admins`). Hypothesis: registering `groups=admins` grants admin.
  Confirmation: the gateway role stays "user" for all OIDC users; groups/email/sub are not
  mapped to role. Mass assignment is inert.
- Observation: `/api/experiments` lets a regular user override ANY feature flag. Hypothesis:
  enable `admin_console_preview` / release-publish. Confirmation: all flags inert — no effect on
  whoami/health/channels/stats/release-stage; `/api/release/stage` still 403.
- Observation: `/api/unfurl` is an http-only SSRF that reaches the cluster. Hypothesis: use it
  to read internal secrets/source or hit the IdP token endpoint. Confirmation: no file/gopher
  schemes; loopback not privileged; the IdP is in-app (`127.0.0.1:8001/idp`) but its token
  endpoint needs `client_secret`; K8s API/metadata and CTF-own domains time out (egress
  blocked). No separate IdP or update-mirror service exists on the cluster.
- The gate chain: release-publish requires `POST /auth/sso/federated` with a valid RS256
  id_token (needs `client_secret`) PLUS a step-up attestation token (unknown derivation), or an
  admin session adopted via a console bootstrap token. All three secrets live in app source, not
  env (the env leak only redacts FLAG + GPG_KEY).

## What we tried
1. Mass assignment: `/idp/register` with `groups=admins` (and
   role/roles/is_admin/admin/permissions/capabilities/scope/scopes/entitlements/plan/tier/
   release_publish/publish) -> only `groups` survives; `whoami` role stays "user";
   `/api/release/stage` stays 403.
2. JWT/federated: `alg=none`/HS256 rejected ("alg not allowed", RS256 only); RS256/PS256 only
   with fixed JWKS (no jku/x5u/kid fetch); token endpoint returns `invalid_client` for every
   grant (client_secret unknown).
3. Attestation: opaque string compare; not JWT/nonce/TOTP/HOTP/HMAC(nonce, 10k-word secret)/
   sha/md5/blake; no replay.
4. Console token: `/admin/session/adopt?t=` guesses -> "invalid or expired console bootstrap";
   no length/format oracle; `{console_token}` never observed in edge-cache (worker renders
   non-admin "(no banner)").
5. SSRF: `/api/unfurl` + `/import` reach example.com and sibling pods (10.30.x:5000) but not
   K8s API (10.30.0.1:443)/metadata (169.254.169.254)/CTF-own domains (timeout); http-only, no
   file read.
6. Env/source: `/api/support/bundle` redacts FLAG + GPG_KEY; no other secret keys; no
   source-map/debug/source leak; Flask session secret not in rockyou 14M.
7. SCIM/webhook/share: `/scim/v2/*` always "admin only" (session role, Bearer ignored); webhook
   stores a URL but fires only `file.shared` (no file-creation path); `/api/share` 404
   everywhere.

## Blocker
`client_secret` (id_token signing), the attestation secret, and the console bootstrap token all
live in the app source, which is unreachable: there is no file-read primitive, the http-only
SSRF cannot read source, the JWT verifier is strict (RS256/PS256, fixed JWKS), and the IdP is
properly configured. Open question: a subtle logic bug (or an egress/file-read primitive) that
yields any one of the three secrets or an admin session.

## Lessons
- Mass assignment that stores but does not map a field (`groups=admins`) is a trap — always
  check whether the trusted field is actually consumed by authorization, not just echoed.
- Feature-flag endpoints that "override any flag" must be tested for actual effect; inert flags
  look like a win but are a dead end.
- An http-only SSRF reads other HTTP services, not files/source; if the secret lives in app
  source you need a file-read or error-traceback primitive, not SSRF.
