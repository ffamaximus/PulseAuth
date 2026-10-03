namespace PulseAuth.Models;

/// <summary>Format of the access tokens issued to a client.</summary>
public enum AccessTokenType
{
    /// <summary>
    /// Self-contained signed JWT (RFC 9068). APIs validate it locally with the JWKS; it cannot be
    /// revoked before it expires.
    /// </summary>
    Jwt = 0,

    /// <summary>
    /// Opaque reference token (random handle). APIs validate it by calling the introspection
    /// endpoint (RFC 7662); it can be revoked at any time (revocation endpoint, logout, user
    /// blocked, password change).
    /// </summary>
    Reference = 1,
}
