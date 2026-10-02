using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;

namespace PulseAuth.Services;

/// <summary>
/// <see cref="IKeyMaterialService"/> backed by key material supplied at startup
/// (an X.509 certificate, an RSA/ECDSA key loaded from Key Vault, a file, etc.).
/// </summary>
/// <remarks>
/// <para>
/// All instances of the authorization server must be configured with the SAME signing
/// key so tokens issued by one instance validate on the others and survive restarts.
/// </para>
/// <para>
/// <b>Key rotation:</b> publish the next key first as an additional validation key,
/// wait for caches to refresh (at least one access-token lifetime), then promote it to
/// signing key and keep the previous one as validation key until all tokens signed with
/// it have expired. Validation keys appear in the JWKS but are never used to sign.
/// </para>
/// </remarks>
public class StaticKeyMaterialService : IKeyMaterialService
{
    private readonly SigningCredentials _signingCredentials;
    private readonly IReadOnlyList<SecurityKey> _validationKeys;
    private readonly JsonWebKeySet _jwks;

    /// <summary>
    /// Creates the service with a signing credential and optional extra validation keys
    /// (e.g. the previous or next key during a rotation).
    /// </summary>
    public StaticKeyMaterialService(
        SigningCredentials signingCredentials,
        IEnumerable<SecurityKey>? additionalValidationKeys = null)
    {
        ArgumentNullException.ThrowIfNull(signingCredentials);

        KeyMaterialHelper.EnsureKeyId(signingCredentials.Key);

        var keys = new List<SecurityKey> { signingCredentials.Key };
        foreach (var key in additionalValidationKeys ?? [])
        {
            KeyMaterialHelper.EnsureKeyId(key);
            if (keys.Any(k => string.Equals(k.KeyId, key.KeyId, StringComparison.Ordinal)))
                continue; // same key registered twice
            keys.Add(key);
        }

        _signingCredentials = signingCredentials;
        _validationKeys     = keys.AsReadOnly();

        _jwks = new JsonWebKeySet();
        _jwks.Keys.Add(KeyMaterialHelper.ToPublicJwk(signingCredentials.Key, signingCredentials.Algorithm));
        foreach (var key in keys.Skip(1))
            _jwks.Keys.Add(KeyMaterialHelper.ToPublicJwk(key, KeyMaterialHelper.DefaultAlgorithm(key)));
    }

    /// <inheritdoc />
    public Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default)
        => Task.FromResult(_signingCredentials);

    /// <inheritdoc />
    public Task<IEnumerable<SecurityKey>> GetValidationKeysAsync(CancellationToken ct = default)
        => Task.FromResult<IEnumerable<SecurityKey>>(_validationKeys);

    /// <inheritdoc />
    public Task<JsonWebKeySet> GetPublicKeysAsync(CancellationToken ct = default)
        => Task.FromResult(_jwks);
}
