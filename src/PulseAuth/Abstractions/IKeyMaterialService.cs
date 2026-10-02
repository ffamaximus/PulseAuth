using Microsoft.IdentityModel.Tokens;

namespace PulseAuth.Abstractions;

/// <summary>
/// Provides cryptographic key material for signing and validating tokens.
/// Built-in implementations: <c>RsaKeyMaterialService</c> (developer key persisted to a PEM file,
/// via <c>AddDeveloperSigningCredential()</c>) and <c>StaticKeyMaterialService</c>
/// (certificate / RSA / ECDSA key, via <c>AddSigningCredential(...)</c>, with rotation support
/// through <c>AddValidationKey(...)</c>). All server instances must share the same signing key.
/// </summary>
public interface IKeyMaterialService
{
    /// <summary>Returns the signing credentials used to sign JWTs.</summary>
    Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default);

    /// <summary>Returns validation keys (public keys) used to verify JWT signatures.</summary>
    Task<IEnumerable<SecurityKey>> GetValidationKeysAsync(CancellationToken ct = default);

    /// <summary>Returns the JWKS (JSON Web Key Set) for the /.well-known/jwks endpoint.</summary>
    Task<JsonWebKeySet> GetPublicKeysAsync(CancellationToken ct = default);
}
