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

### API changes
- New: `IAuthorizationCodeStore.TryConsumeAsync`, `IRefreshTokenStore.TryConsumeAsync`,
  `IRefreshTokenStore.RevokeFamilyAsync`, `IUserAuthenticationService.IsActiveAsync`. They have
  default implementations, so custom stores keep compiling, but they should be overridden to get
  atomicity, grace period, precise family revocation and active-user checks.
- New helpers: `GrantKeyHelper`, `RefreshTokenFamily`, `StaticKeyMaterialService`.
- `RsaKeyMaterialService` constructor changed; `AuthorizeValidationResult.Success` has a new optional
  parameter (recompile code that calls it).
