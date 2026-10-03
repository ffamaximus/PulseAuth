# Changelog

## 1.3.0 — security release

This release fixes several security issues found in a review of 1.2.5. **Upgrading is strongly
recommended.** No database migration is required.

### Security fixes
- **Open redirect** in `/connect/authorize` and `/connect/endsession`: redirects now only go to URIs
  registered for an identified client. `/connect/endsession` accepts `id_token_hint`.
- **Signing keys**: `AddDeveloperSigningCredential()` now persists the key (`pulseauth-tempkey.pem`)
  instead of generating a new one on every start. New `AddSigningCredential(...)` (certificate /
  RSA / ECDSA) and `AddValidationKey(...)` for key rotation. JWKS supports EC keys.
- **Authorization codes and refresh tokens can no longer be redeemed twice** concurrently
  (atomic consumption before issuing tokens).
- **Refresh token reuse detection**: a rotated refresh token presented again after the grace period
  revokes its whole rotation family (RFC 9700). Configurable grace period for concurrent refreshes
  (`RefreshTokenReuseGracePeriod`, default 10 s) and retention of consumed tokens
  (`ConsumedRefreshTokenRetention`, default 7 days).
- **Codes and refresh tokens are stored hashed** (SHA-256) by the EF stores. Rows written by older
  versions keep working until they expire.
- `offline_access` is only granted to clients with `AllowOfflineAccess = true` for every grant type;
  `client_credentials` never returns a refresh token.
- `client_credentials` requires a confidential client (`ClientSecretHash`).
- `/connect/userinfo` only accepts access tokens (not ID tokens). Access tokens use `typ: at+jwt`.
- User claims can no longer override protocol claims (`sub`, `scope`, `client_id`, ...).
- Facebook token exchange: `app_id` is mandatory and must match; `appsecret_proof` is sent;
  the profile must match the token's user.
- Refresh is rejected (and the user's refresh tokens revoked) when the user no longer exists, is
  locked out or can no longer sign in (`IUserAuthenticationService.IsActiveAsync`).

### Hardening
- `/connect/revocation` authenticates the client and only revokes that client's tokens (RFC 7009).
- Malformed `Authorization: Basic` headers and non-form bodies return `invalid_client` /
  `invalid_request` instead of HTTP 500.
- Built-in CORS for SPAs driven by `Client.AllowedCorsOrigins` (`EnableCors`, default on).
- Optional rate limiting of token / userinfo / revocation endpoints (`RateLimitPolicy`).
- Optional logout CSRF protection (`RequireLogoutConfirmation`); `/connect/endsession` accepts POST.
- PKCE `plain` disabled by default (`AllowPlainPkce`).
- Background cleanup of expired codes and refresh tokens (`EnableTokenCleanup`, hourly).
- Google token exchange only keeps the e-mail when `email_verified` is true.
- Identity auto-provisioning: unique user names for duplicate display names; an existing account with
  the same e-mail is never merged silently (`invalid_grant` with a clear message); profile claims are stored.
- Access / ID token `exp` now honour per-client lifetimes and always match `expires_in`.
- `auth_time` is only emitted when known (password / social grants), no longer faked as "now".
- Discovery publishes the issuer exactly as configured (a trailing `/` no longer breaks validation),
  lists the supported grant types and only S256 for PKCE.
- `Client.Claims` are added to `client_credentials` access tokens.
- Security-relevant events are logged (rejected token requests, reuse detection, revocations).
- Tests (`tests/PulseAuth.Tests` for the endpoints, `tests/PulseAuth.EntityFramework.Tests` for the
  EF Core stores on SQLite) and a GitHub Actions CI workflow.

### Behaviour changes to review when upgrading
- `post_logout_redirect_uri` is ignored unless `client_id` or `id_token_hint` is sent.
- `AddDeveloperSigningCredential()` writes a key file to the current directory (falls back to an
  in-memory key with a warning when the location is read-only). Add it to `.gitignore`.
- Clients that obtain refresh tokens with the **password** or **social** grants now need
  `AllowOfflineAccess = true` (previously only `AllowedScopes` was checked).
- A `client_credentials` client without `ClientSecretHash` is now rejected with `unauthorized_client`.
- Refresh token reuse outside the grace period signs the user out of that session. With
  `RefreshTokenReuseGracePeriod = TimeSpan.Zero`, concurrent refreshes (several tabs) count as reuse.
- `RemoveExpiredAsync` keeps consumed refresh tokens for `ConsumedRefreshTokenRetention`.
- `/connect/userinfo` returns repeated claim types (e.g. several roles) as arrays.
- `/connect/revocation` now requires `client_id` (and the secret for confidential clients).
- Clients sending `code_challenge_method=plain` are rejected unless `AllowPlainPkce = true`.
- Access tokens now live `Client.AccessTokenLifetime` (default 3600 s) — the value that `expires_in`
  already reported — instead of `PulseAuthOptions.DefaultAccessTokenLifetime`. Set the client value
  (or 0 to use the global default) if you relied on the global setting.
- Code-flow ID tokens no longer contain `auth_time`.

### API changes
- New: `IAuthorizationCodeStore.TryConsumeAsync`, `IRefreshTokenStore.TryConsumeAsync`,
  `IRefreshTokenStore.RevokeFamilyAsync`, `IUserAuthenticationService.IsActiveAsync`. They have
  default implementations, so custom stores keep compiling, but they should be overridden to get
  atomicity, grace period, precise family revocation and active-user checks.
- New helpers: `GrantKeyHelper`, `RefreshTokenFamily`, `StaticKeyMaterialService`.
- `RsaKeyMaterialService` constructor changed; `AuthorizeValidationResult.Success` has a new optional
  parameter (recompile code that calls it).
