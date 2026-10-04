# Changelog

## 1.4.0

### New features
- **Consent screen**: `Client.RequireConsent` is now enforced. `IConsentInteractionService` gives the
  consent page the request details and grants (all or some scopes, remembered or one-time) or denies
  it. Consents are stored in `IConsentStore` (in-memory / EF) and can be listed and revoked.
- **`prompt` and `max_age`** on the authorize endpoint: `none` (`login_required` / `consent_required`),
  `login`, `consent`.
- **Reference (opaque) access tokens** (`Client.AccessTokenType = Reference`), revocable at any time.
- **Introspection endpoint** `/connect/introspect` (RFC 7662) for JWT, reference and refresh tokens;
  `Client.AllowIntrospection` for APIs. Published in discovery.
- **Security stamp validation**: a password change / "sign out everywhere" invalidates refresh tokens
  (`IUserAuthenticationService.GetSecurityStampAsync`, `ValidateSecurityStampOnRefresh`).
- CORS origin checks are cached by the EF client store (`CorsOriginCacheDuration`, default 1 min).

### OpenID Connect conformance (Basic OP pre-check)
Fixes found while preparing the OpenID Foundation conformance suite (`oidcc-basic-certification-test-plan`):
- ID tokens from the code flow carry **`auth_time`** (time of the user's sign-in), kept unchanged on refresh.
- **Authorization code reuse** revokes the refresh tokens issued with that code (and their rotations).
- The authorize endpoint accepts **POST**; a missing `response_type` returns `invalid_request`;
  `request` / `request_uri` are rejected with `request_not_supported` / `request_uri_not_supported`;
  OpenID requests must always send `redirect_uri`.
- UserInfo accepts **POST** and the token in the form body (`access_token`); errors carry a
  `WWW-Authenticate: Bearer error="invalid_token"` challenge.
- Token responses send `Cache-Control: no-store` / `Pragma: no-cache`.
- Discovery publishes `response_modes_supported`, `claims_parameter_supported`,
  `request_parameter_supported` and `request_uri_parameter_supported` (`false`; the default when
  omitted is `true`) and a fuller `claims_supported`.
- New option `IgnoreUnknownScopes` (default `false`): unknown scopes are dropped instead of failing.
- Consumed authorization codes are kept until they expire (needed to detect reuse).
- New sample `samples/PulseAuth.ConformanceHost` + guide to run the suite.

### ⚠️ Database migration required (EF stores)
New tables `PulseAuth_ReferenceTokens` and `PulseAuth_Consents`, new columns
`PulseAuth_RefreshTokens.UserStamp`, `PulseAuth_RefreshTokens.AuthTime`,
`PulseAuth_AuthorizationCodes.AuthTime`, `PulseAuth_Clients.AccessTokenType` and
`PulseAuth_Clients.AllowIntrospection` (all nullable or with defaults; existing data keeps working):

```bash
dotnet ef migrations add PulseAuth_1_4_0 --context <YourDbContext>
dotnet ef database update --context <YourDbContext>
```

### API changes
- `IPulseAuthDbContext` has two new `DbSet`s (`ReferenceTokens`, `Consents`); `PulseAuthDbContext` and
  `PulseAuthIdentityDbContext<TUser>` already include them. Custom implementations must add them.
- New abstractions: `IReferenceTokenStore`, `IConsentStore`, `IConsentInteractionService`,
  `AccessTokenValidator`. `IUserAuthenticationService.GetSecurityStampAsync` has a default
  implementation (feature off for custom user services until implemented).

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
