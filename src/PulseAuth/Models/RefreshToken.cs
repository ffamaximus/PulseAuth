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

    /// <summary>
    /// Id of the refresh token that was rotated to create this one
    /// (<see cref="ComputeTokenId"/> of the previous token — never the raw value).
    /// Links rotations into a family so reuse of an old token can revoke the whole chain.
    /// </summary>
    public string? PreviousTokenId { get; set; }

    /// <summary>
    /// Hash of the user's security stamp when the token was issued (see
    /// <c>IUserAuthenticationService.GetSecurityStampAsync</c>). If the stamp changes — password
    /// change, "sign out everywhere", 2FA reset — the token is rejected on the next refresh.
    /// </summary>
    public string? UserStamp { get; set; }

    /// <summary>
    /// When the user originally authenticated (1.4.0+). Carried across rotations so ID tokens
    /// issued on refresh keep the original <c>auth_time</c> (OIDC Core §12.2).
    /// </summary>
    public DateTime? AuthTime { get; set; }

    /// <summary>
    /// Claims requested with the OIDC <c>claims</c> parameter (1.4.0+), carried across rotations so
    /// refreshed access / ID tokens keep releasing them; serialized <see cref="Helpers.ClaimsRequest"/>.
    /// </summary>
    public string? ClaimsRequest { get; set; }

    /// <summary>
    /// Stable, non-reversible identifier of a refresh token value: base64url(SHA-256(token)).
    /// Used to link rotations (<see cref="PreviousTokenId"/>) without storing secrets.
    /// </summary>
    public static string ComputeTokenId(string token)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

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
