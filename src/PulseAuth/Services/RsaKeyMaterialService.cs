using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;

namespace PulseAuth.Services;

/// <summary>
/// In-memory RSA-2048 key material service.
/// Generates a new key pair on startup — suitable for development and single-instance deployments.
/// For multi-instance or production deployments, replace with a persistent key service
/// (e.g., backed by Azure Key Vault, AWS KMS or a database).
/// </summary>
public sealed class RsaKeyMaterialService : IKeyMaterialService, IDisposable
{
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _key;
    private readonly SigningCredentials _signingCredentials;
    private readonly JsonWebKeySet _jwks;

    /// <summary>
    /// Initializes a new instance of the <see cref="RsaKeyMaterialService"/> class.
    /// </summary>
    /// <param name="options"></param>
    public RsaKeyMaterialService(IOptions<PulseAuthOptions> options)
    {
        _rsa = RSA.Create(2048);
        _key = new RsaSecurityKey(_rsa)
        {
            KeyId = GenerateKeyId()
        };

        _signingCredentials = new SigningCredentials(_key, SecurityAlgorithms.RsaSha256);

        // Build the public JWKS (only expose the public portion)
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_key);
        // Remove private key parameters before exposing
        jwk.D = null; jwk.DP = null; jwk.DQ = null; jwk.P = null; jwk.Q = null; jwk.QI = null;

        _jwks = new JsonWebKeySet();
        _jwks.Keys.Add(jwk);
    }

    /// <summary>
    /// Retrieves the signing credentials containing the RSA private key for signing JWTs.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default)
        => Task.FromResult(_signingCredentials);

    /// <summary>
    /// Retrieves the validation keys containing the RSA public key for verifying JWT signatures.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task<IEnumerable<SecurityKey>> GetValidationKeysAsync(CancellationToken ct = default)
        => Task.FromResult<IEnumerable<SecurityKey>>([_key]);

    /// <summary>
    /// Retrieves the JSON Web Key Set (JWKS) containing the public keys for clients to verify JWT signatures.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task<JsonWebKeySet> GetPublicKeysAsync(CancellationToken ct = default)
        => Task.FromResult(_jwks);

    /// <summary>
    /// Generates a unique Key ID (kid) for the RSA key. This is used in the JWT header to indicate which key was used to sign the token, allowing clients to select the correct public key from the JWKS for verification. The method generates a random GUID, converts it to a Base64 string, and formats it to be URL-safe and concise (16 characters). This ensures that each key has a unique identifier while keeping the kid reasonably short for use in JWT headers.
    /// </summary>
    /// <returns></returns>
    private static string GenerateKeyId()
        => Convert.ToBase64String(Guid.NewGuid().ToByteArray())
                  .Replace("+", "-").Replace("/", "_").TrimEnd('=')[..16];

    /// <summary>
    /// Disposes the RSA key material service, releasing any resources held by the RSA instance.
    /// </summary>
    public void Dispose() => _rsa.Dispose();
}
