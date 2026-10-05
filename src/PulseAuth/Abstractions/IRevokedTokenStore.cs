namespace PulseAuth.Abstractions;

/// <summary>
/// Deny-list of revoked JWT access tokens, keyed by their <c>jti</c> (1.4.0+). JWT access tokens are
/// self-contained, so revoking one only works where this list is consulted: PulseAuth's own UserInfo
/// and introspection endpoints. APIs that validate JWTs locally do not see it — use reference tokens
/// or introspection where immediate revocation matters.
/// </summary>
public interface IRevokedTokenStore
{
    /// <summary>Marks the token id as revoked until <paramref name="expiresAt"/> (the token's own expiry).</summary>
    Task RevokeAsync(string tokenId, DateTime expiresAt, CancellationToken ct = default);

    /// <summary>True when the token id has been revoked and the entry has not expired.</summary>
    Task<bool> IsRevokedAsync(string tokenId, CancellationToken ct = default);

    /// <summary>Removes entries whose tokens have expired anyway. Called periodically for cleanup.</summary>
    Task RemoveExpiredAsync(CancellationToken ct = default);
}
