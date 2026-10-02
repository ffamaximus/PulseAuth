namespace PulseAuth.Models;

/// <summary>
/// Represents a refresh token that can be exchanged for a new access token.
/// </summary>
public class RefreshToken
{
    /// <summary>The opaque refresh token value.</summary>
    public string Token { get; set; } = default!;

    /// <summary>The client that owns this refresh token.</summary>
    public string ClientId { get; set; } = default!;

    /// <summary>Subject identifier (user ID).</summary>
    public string SubjectId { get; set; } = default!;

    /// <summary>Scopes granted.</summary>
    public IEnumerable<string> Scopes { get; set; } = [];

    /// <summary>When this token was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this token expires.</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>Whether this token has been consumed (one-time-use rotation).</summary>
    public bool IsConsumed { get; set; }

    /// <summary>The token that was consumed to create this one (for rotation chain).</summary>
    public string? PreviousTokenId { get; set; }

    /// <summary>
    /// True when the token was consumed by rotation less than <paramref name="gracePeriod"/> ago,
    /// so a concurrent/retried request presenting it may still be accepted.
    /// </summary>
    /// <remarks>
    /// Rotation stores <c>ExpiresAt = consumedAt + gracePeriod</c>; revocation sets
    /// <c>ExpiresAt = now</c>. Therefore a consumed token whose expiry lies in
    /// <c>[now, now + gracePeriod]</c> was rotated within the window — revoked tokens never match.
    /// </remarks>
    public bool IsWithinReuseGracePeriod(TimeSpan gracePeriod, DateTime utcNow)
        => IsConsumed &&
           gracePeriod > TimeSpan.Zero &&
           ExpiresAt > utcNow &&
           ExpiresAt <= utcNow + gracePeriod;
}
