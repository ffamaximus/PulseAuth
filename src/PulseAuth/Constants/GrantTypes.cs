namespace PulseAuth.Constants;

/// <summary>OAuth2 grant type constants.</summary>
public static class GrantTypes
{
    /// <summary>
    /// Authorization Code flow — the most common and secure flow for server-side applications. 
    /// </summary>
    public const string AuthorizationCode = "authorization_code";

    /// <summary>
    /// Client Credentials flow — for machine-to-machine communication without user context. 
    /// </summary>
    public const string ClientCredentials = "client_credentials";

    /// <summary>
    /// Refresh Token flow — used to obtain new access tokens using a valid refresh token.
    /// </summary>
    public const string RefreshToken      = "refresh_token";

    /// <summary>
    /// Implicit flow — deprecated in OAuth 2.1, kept for legacy compatibility.
    /// </summary>
    public const string Implicit          = "implicit";
    /// <summary>Resource Owner Password — deprecated in OAuth 2.1, kept for legacy compatibility.</summary>
    public const string Password          = "password";

    /// <summary>
    /// Google ID Token exchange — present a Google-issued ID token to receive PulseAuth tokens.
    /// Use this with the Google Sign-In SDK on React/Angular SPAs.
    /// </summary>
    public const string GoogleIdToken     = "urn:ietf:params:oauth:grant-type:google_id_token";

    /// <summary>
    /// Facebook Access Token exchange — present a Facebook access token to receive PulseAuth tokens.
    /// Use this with the Facebook Login SDK on React/Angular SPAs.
    /// </summary>
    public const string FacebookAccessToken = "urn:ietf:params:oauth:grant-type:facebook_access_token";

    /// <summary>
    /// Predefined sets of grant types for common scenarios.
    /// </summary>
    public static IReadOnlyList<string> Code                    => [AuthorizationCode];

    /// <summary>
    /// Client Credentials flow is often used alone, but can be combined with Authorization Code for hybrid scenarios (e.g., a service that both issues tokens to users and has machine-to-machine clients).
    /// </summary>
    public static IReadOnlyList<string> ClientCredentialsOnly   => [ClientCredentials];

    /// <summary>
    /// Combines Authorization Code and Client Credentials for scenarios where both user authentication and machine-to-machine communication are needed.
    /// </summary>
    public static IReadOnlyList<string> CodeAndClientCredentials => [AuthorizationCode, ClientCredentials];
    /// <summary>
    /// Combines Authorization Code and Refresh Token for scenarios where long-lived sessions are needed without requiring the user to re-authenticate frequently.
    /// </summary>
    public static IReadOnlyList<string> All                     => [AuthorizationCode, ClientCredentials, RefreshToken];
}
