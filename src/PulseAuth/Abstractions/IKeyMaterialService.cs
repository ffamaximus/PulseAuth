using Microsoft.IdentityModel.Tokens;

namespace PulseAuth.Abstractions;

/// <summary>
/// Provides cryptographic key material for signing and validating tokens.
/// The default implementation generates an in-memory RSA-2048 key pair.
/// Replace with a persistent implementation (e.g. Azure Key Vault) for production.
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
