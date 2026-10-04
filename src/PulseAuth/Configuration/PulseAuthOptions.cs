namespace PulseAuth.Configuration;

/// <summary>
/// Top-level configuration options for PulseAuth.
/// </summary>
public class PulseAuthOptions
{
    /// <summary>
    /// Configuration section name for binding these options.
    /// * Must match the section name used in appsettings.json, e.g. "PulseAuth": { ... }
    /// </summary>
    public const string SectionName = "PulseAuth";

    /// <summary>
    /// The issuer (iss) claim value in JWTs.
    /// Must be the public base URL of the authorization server, e.g. "https://auth.myapp.com".
    /// </summary>
    public string Issuer { get; set; } = "https://localhost";

    /// <summary>
    /// Default audience (aud) for access tokens when no explicit audience is set.
    /// Defaults to the requesting client_id when null.
    /// </summary>
    public string? DefaultAudience { get; set; }

    /// <summary>Default access token lifetime in seconds. Default: 3600 (1 hour).</summary>
    public int DefaultAccessTokenLifetime { get; set; } = 3600;

    /// <summary>Default refresh token lifetime in seconds. Default: 2592000 (30 days).</summary>
    public int DefaultRefreshTokenLifetime { get; set; } = 2592000;

    /// <summary>Default ID token lifetime in seconds. Default: 300 (5 minutes).</summary>
    public int DefaultIdentityTokenLifetime { get; set; } = 300;

    /// <summary>
    /// Path of the login page in the host application.
    /// The authorize endpoint redirects here when the user is not authenticated.
    /// Default: "/Account/Login"
    /// </summary>
    public string LoginPath { get; set; } = "/Account/Login";

    /// <summary>
    /// Path of the logout page in the host application.
    /// Default: "/Account/Logout"
    /// </summary>
    public string LogoutPath { get; set; } = "/Account/Logout";

    /// <summary>
    /// Path of the consent page in the host application.
    /// Default: "/Consent"
    /// </summary>
    public string ConsentPath { get; set; } = "/Consent";

    /// <summary>
    /// Path of the error page.
    /// Default: "/Home/Error"
    /// </summary>
    public string ErrorPath { get; set; } = "/Home/Error";

    /// <summary>
    /// Base path prefix for PulseAuth endpoints.
    /// Default: "/connect" → endpoints become /connect/authorize, /connect/token, etc.
    /// </summary>
    public string RoutePrefix { get; set; } = "/connect";

    /// <summary>
    /// Name of the cookie used to track the PulseAuth interactive session.
    /// </summary>
    public string CookieName { get; set; } = "PulseAuth.Session";

    /// <summary>
    /// When true, refresh tokens are rotated on each use (recommended).
    /// </summary>
    public bool RotateRefreshTokens { get; set; } = true;

    /// <summary>
    /// Grace period during which an already-rotated refresh token is still accepted
    /// (only when <see cref="RotateRefreshTokens"/> is true). Covers legitimate races,
    /// e.g. an SPA open in several tabs refreshing at the same time, or a retry after a
    /// network error. Each request inside the window receives its own new refresh token.
    /// Default: 10 seconds. Set to <see cref="TimeSpan.Zero"/> for strict one-time use.
    /// </summary>
    public TimeSpan RefreshTokenReuseGracePeriod { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// How long consumed (rotated or revoked) refresh tokens are kept by
    /// <c>IRefreshTokenStore.RemoveExpiredAsync</c>. While a consumed token is kept, presenting
    /// it again is detected as <b>reuse</b> and the whole token family is revoked. After this
    /// period the token is deleted and a replay is simply rejected as unknown.
    /// Default: 7 days.
    /// </summary>
    public TimeSpan ConsumedRefreshTokenRetention { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// When true, <c>/connect/endsession</c> requests without a valid <c>id_token_hint</c> for the
    /// signed-in user are not executed directly: the user is redirected to <see cref="LogoutPath"/>
    /// with a <c>returnUrl</c> to confirm. Your logout page must sign the user out (POST +
    /// antiforgery) and then redirect to <c>returnUrl</c> (local redirect). Protects against logout CSRF.
    /// Default: false (backward compatible).
    /// </summary>
    public bool RequireLogoutConfirmation { get; set; } = false;

    /// <summary>
    /// Allows the PKCE <c>plain</c> method. Disabled by default: <c>plain</c> offers no protection
    /// if the authorization request is observed, and OAuth 2.1 only allows S256.
    /// </summary>
    public bool AllowPlainPkce { get; set; } = false;

    /// <summary>
    /// Runs a background job that periodically calls <c>RemoveExpiredAsync</c> on the
    /// authorization code and refresh token stores. Default: true.
    /// </summary>
    public bool EnableTokenCleanup { get; set; } = true;

    /// <summary>Interval of the token cleanup job. Default: 1 hour.</summary>
    public TimeSpan TokenCleanupInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Name of an ASP.NET Core rate limiting policy (<c>AddRateLimiter</c>) applied to the token,
    /// revocation and userinfo endpoints. Requires <c>app.UseRateLimiter()</c>. Default: none.
    /// </summary>
    public string? RateLimitPolicy { get; set; }

    /// <summary>
    /// Answers CORS requests to the token, userinfo and revocation endpoints for origins listed in
    /// a client's <c>AllowedCorsOrigins</c> (discovery and JWKS are public and allow any origin).
    /// Default: true. Disable it if you handle CORS for these endpoints yourself.
    /// </summary>
    public bool EnableCors { get; set; } = true;

    /// <summary>
    /// How long the answer to "is this origin allowed?" is cached by stores that support it
    /// (EF store). Default: 1 minute. <see cref="TimeSpan.Zero"/> disables the cache.
    /// </summary>
    public TimeSpan CorsOriginCacheDuration { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Rejects a refresh token (and revokes the user's tokens for that client) when the user's
    /// security stamp changed since it was issued — e.g. after a password change.
    /// Requires <c>IUserAuthenticationService.GetSecurityStampAsync</c> (implemented by PulseAuth.Identity).
    /// Default: true.
    /// </summary>
    public bool ValidateSecurityStampOnRefresh { get; set; } = true;

    /// <summary>
    /// Lifetime of consents the user asked to remember. <c>null</c> (default) = until revoked.
    /// </summary>
    public TimeSpan? RememberedConsentLifetime { get; set; }

    /// <summary>
    /// Scopes that are always included in the discovery document.
    /// </summary>
    public IList<string> SupportedScopes { get; set; } = ["openid", "profile", "email", "offline_access"];

    /// <summary>
    /// When <c>true</c>, requested scopes the server does not know at all (not in
    /// <see cref="SupportedScopes"/> and not allowed for the client) are silently dropped, as
    /// OIDC Core §3.1.2.1 recommends ("scope values that are not understood SHOULD be ignored"),
    /// instead of failing the request with <c>invalid_scope</c>. Known scopes the client is not
    /// allowed to use are always rejected. Default: <c>false</c> (strict).
    /// </summary>
    public bool IgnoreUnknownScopes { get; set; } = false;
}
