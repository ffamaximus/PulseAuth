namespace PulseAuth.Models;

/// <summary>An opaque access token (see <see cref="AccessTokenType.Reference"/>).</summary>
public class ReferenceToken
{
    /// <summary>The handle given to the client (stores persist only a hash of it).</summary>
    public string Handle { get; set; } = default!;

    /// <summary>Client the token was issued to.</summary>
    public string ClientId { get; set; } = default!;

    /// <summary>Subject (user id, or client id for client_credentials).</summary>
    public string SubjectId { get; set; } = default!;

    /// <summary>The signed JWT with all the token's claims, returned by introspection.</summary>
    public string Jwt { get; set; } = default!;

    /// <summary>Creation time (UTC).</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Expiration time (UTC).</summary>
    public DateTime ExpiresAt { get; set; }
}
