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
    /// Scopes that are always included in the discovery document.
    /// </summary>
    public IList<string> SupportedScopes { get; set; } = ["openid", "profile", "email", "offline_access"];
}
