using System.Security.Claims;

namespace PulseAuth.Abstractions;

/// <summary>
/// Creates JWT access tokens and ID tokens.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Creates a signed JWT access token.
    /// </summary>
    /// <param name="subjectId">User ID (sub claim). Pass clientId for client_credentials.</param>
    /// <param name="clientId">The requesting client.</param>
    /// <param name="scopes">Scopes granted.</param>
    /// <param name="additionalClaims">Extra claims to embed in the token.</param>
    /// <param name="ct"></param>
    Task<string> CreateAccessTokenAsync(
        string subjectId,
        string clientId,
        IEnumerable<string> scopes,
        IEnumerable<Claim>? additionalClaims = null,
        CancellationToken ct = default);

    /// <summary>
    /// Creates a signed JWT ID token (OIDC). Returns null if the openid scope is not included.
    /// </summary>
    /// <param name="subjectId">User ID.</param>
    /// <param name="clientId">Audience of the ID token.</param>
    /// <param name="nonce">OIDC nonce from the authorization request.</param>
    /// <param name="scopes">Authorized scopes (determines which profile claims to include).</param>
    /// <param name="additionalClaims"></param>
    /// <param name="ct"></param>
    Task<string?> CreateIdTokenAsync(
        string subjectId,
        string clientId,
        string? nonce,
        IEnumerable<string> scopes,
        IEnumerable<Claim>? additionalClaims = null,
        CancellationToken ct = default);
}
