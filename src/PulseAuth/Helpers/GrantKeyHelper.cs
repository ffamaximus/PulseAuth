using PulseAuth.Models;

namespace PulseAuth.Helpers;

/// <summary>
/// Converts authorization codes and refresh tokens into the keys used to persist them.
/// </summary>
/// <remarks>
/// <para>
/// Persistent stores must never keep usable grants in clear text: anyone with read access to the
/// database (a backup, a replica, a SQL injection elsewhere) could otherwise redeem them. Stores
/// save <see cref="ToStorageKey"/> = <c>"sha256:" + base64url(SHA-256(value))</c> and look values up
/// by recomputing it. The value itself is only known to the client that received it.
/// </para>
/// <para>
/// Rows written by PulseAuth ≤ 1.2.x stored the raw value. <see cref="LegacyCandidates"/> lets a
/// store keep accepting those until they expire, so upgrading does not sign anybody out.
/// </para>
/// </remarks>
public static class GrantKeyHelper
{
    /// <summary>Prefix that marks a hashed storage key.</summary>
    public const string HashPrefix = "sha256:";

    /// <summary>Returns the storage key for a code / refresh token value.</summary>
    public static string ToStorageKey(string value)
        => HashPrefix + RefreshToken.ComputeTokenId(value);

    /// <summary>
    /// Returns the keys a stored row may have for <paramref name="value"/>:
    /// the hashed key (current format) and the raw value (rows written by PulseAuth ≤ 1.2.x).
    /// </summary>
    public static (string Hashed, string Legacy) LegacyCandidates(string value)
        => (ToStorageKey(value), value);

    /// <summary>
    /// Returns the token id (<see cref="RefreshToken.ComputeTokenId"/>) of a stored row from its key,
    /// for both hashed and legacy (raw) keys. Used to follow <see cref="RefreshToken.PreviousTokenId"/>.
    /// </summary>
    public static string TokenIdFromStorageKey(string storageKey)
        => storageKey.StartsWith(HashPrefix, StringComparison.Ordinal)
            ? storageKey[HashPrefix.Length..]
            : RefreshToken.ComputeTokenId(storageKey);
}
