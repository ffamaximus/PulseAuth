namespace PulseAuth.Models;

/// <summary>
/// Represents an OAuth2 client application registered in PulseAuth.
/// </summary>
public class Client
{
    /// <summary>Unique identifier for the client (client_id).</summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Hashed secret for confidential clients. Null for public clients (SPAs, mobile apps).
    /// </summary>
    public string? ClientSecretHash { get; set; }

    /// <summary>Human-readable name shown on the consent screen.</summary>
    public string ClientName { get; set; } = default!;

    /// <summary>Optional description shown on the consent screen.</summary>
    public string? Description { get; set; }

    /// <summary>URI for the client logo shown on the consent screen.</summary>
    public string? LogoUri { get; set; }

    /// <summary>Grant types this client is allowed to use.</summary>
    public ICollection<string> AllowedGrantTypes { get; set; } = new List<string>();

    /// <summary>Allowed redirect URIs after authorization. Exact match required.</summary>
    public ICollection<string> RedirectUris { get; set; } = new List<string>();

    /// <summary>Allowed URIs to redirect after logout.</summary>
    public ICollection<string> PostLogoutRedirectUris { get; set; } = new List<string>();

    /// <summary>Scopes the client is allowed to request.</summary>
    public ICollection<string> AllowedScopes { get; set; } = new List<string>();

    /// <summary>
    /// Browser origins (e.g. <c>https://app.example.com</c>) allowed to call the token, userinfo and
    /// revocation endpoints (CORS). Requires <c>PulseAuthOptions.EnableCors</c> (default true).
    /// </summary>
    public ICollection<string> AllowedCorsOrigins { get; set; } = new List<string>();

    /// <summary>Whether PKCE is required (recommended for all public clients).</summary>
    public bool RequirePkce { get; set; } = true;

    /// <summary>Whether the client can request refresh tokens (offline_access scope).</summary>
    public bool AllowOfflineAccess { get; set; } = false;

    /// <summary>
    /// Reserved for a future consent screen. <b>Not enforced yet</b>: setting it has no effect
    /// in this version, so do not rely on it to obtain user consent.
    /// </summary>
    public bool RequireConsent { get; set; } = false;

    /// <summary>Whether this client is enabled.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Access token lifetime in seconds. Default: 3600 (1 hour).</summary>
    public int AccessTokenLifetime { get; set; } = 3600;

    /// <summary>Refresh token lifetime in seconds. Default: 2592000 (30 days).</summary>
    public int RefreshTokenLifetime { get; set; } = 2592000;

    /// <summary>Authorization code lifetime in seconds. Default: 300 (5 minutes).</summary>
    public int AuthorizationCodeLifetime { get; set; } = 300;

    /// <summary>ID token lifetime in seconds. Default: 300 (5 minutes).</summary>
    public int IdentityTokenLifetime { get; set; } = 300;

    /// <summary>
    /// Claims added to access tokens issued with the <c>client_credentials</c> grant
    /// (e.g. tenant, service role). Protocol claims (sub, scope, client_id, ...) are ignored.
    /// </summary>
    public IDictionary<string, string> Claims { get; set; } = new Dictionary<string, string>();
}
