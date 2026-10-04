namespace PulseAuth.Models;

/// <summary>
/// Represents a one-time-use authorization code issued during the Authorization Code flow.
/// </summary>
public class AuthorizationCode
{
    /// <summary>The opaque authorization code value sent to the client.</summary>
    public string Code { get; set; } = default!;

    /// <summary>The client that requested this code.</summary>
    public string ClientId { get; set; } = default!;

    /// <summary>Subject identifier (user ID) for whom the code was issued.</summary>
    public string SubjectId { get; set; } = default!;

    /// <summary>PKCE code challenge (S256 or plain).</summary>
    public string? CodeChallenge { get; set; }

    /// <summary>PKCE code challenge method: "S256" or "plain".</summary>
    public string? CodeChallengeMethod { get; set; }

    /// <summary>Scopes authorized.</summary>
    public IEnumerable<string> Scopes { get; set; } = [];

    /// <summary>The redirect_uri the client used in the authorize request.</summary>
    public string? RedirectUri { get; set; }

    /// <summary>OIDC nonce value to include in the ID token.</summary>
    public string? Nonce { get; set; }

    /// <summary>Session ID for single-logout support.</summary>
    public string? SessionId { get; set; }

    /// <summary>When the code was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When the code expires.</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>Whether the code has already been exchanged.</summary>
    public bool IsConsumed { get; set; }

    /// <summary>
    /// When the user authenticated (1.4.0+). Emitted as the <c>auth_time</c> claim of the ID token
    /// (required by OIDC when <c>max_age</c> is used). Null when unknown.
    /// </summary>
    public DateTime? AuthTime { get; set; }
}
