using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace PulseAuth.Services;

/// <summary>
/// Helpers shared by the key material services: public JWK export, deterministic
/// key ids (RFC 7638 thumbprints) and default algorithm selection.
/// </summary>
internal static class KeyMaterialHelper
{
    /// <summary>
    /// Converts an X.509 certificate into a signing-capable <see cref="SecurityKey"/>.
    /// RSA certificates become <see cref="X509SecurityKey"/>; EC certificates become
    /// <see cref="ECDsaSecurityKey"/>. The key id is the certificate thumbprint.
    /// </summary>
    public static SecurityKey FromCertificate(X509Certificate2 certificate, bool requirePrivateKey)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (requirePrivateKey && !certificate.HasPrivateKey)
            throw new InvalidOperationException(
                $"Certificate '{certificate.Subject}' ({certificate.Thumbprint}) has no private key and cannot be used for signing.");

        if (certificate.GetRSAPublicKey() is not null)
            return new X509SecurityKey(certificate);

        var ecdsa = requirePrivateKey ? certificate.GetECDsaPrivateKey() : certificate.GetECDsaPublicKey();
        if (ecdsa is not null)
            return new ECDsaSecurityKey(ecdsa) { KeyId = certificate.Thumbprint };

        throw new NotSupportedException(
            $"Certificate '{certificate.Subject}' uses an unsupported key type. Only RSA and ECDSA are supported.");
    }

    /// <summary>Returns a sensible JWS algorithm for the key (RS256 / ES256 / ES384 / ES512).</summary>
    public static string DefaultAlgorithm(SecurityKey key) => key switch
    {
        ECDsaSecurityKey ec => ec.KeySize switch
        {
            <= 256 => SecurityAlgorithms.EcdsaSha256,
            <= 384 => SecurityAlgorithms.EcdsaSha384,
            _      => SecurityAlgorithms.EcdsaSha512,
        },
        _ => SecurityAlgorithms.RsaSha256,
    };

    /// <summary>
    /// Assigns a deterministic key id (base64url RFC 7638 JWK thumbprint) when the key
    /// has none, so every instance that loads the same key publishes the same <c>kid</c>.
    /// </summary>
    public static void EnsureKeyId(SecurityKey key)
    {
        if (!string.IsNullOrEmpty(key.KeyId))
            return;

        var jwk = ToPublicJwk(key, algorithm: null);
        key.KeyId = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
    }

    /// <summary>
    /// Builds a JWK that contains ONLY public key material, suitable for the JWKS endpoint.
    /// </summary>
    public static JsonWebKey ToPublicJwk(SecurityKey key, string? algorithm)
    {
        JsonWebKey jwk = key switch
        {
            X509SecurityKey x509 => FromPublicCertificate(x509.Certificate, x509.KeyId),
            RsaSecurityKey  rsa  => JsonWebKeyConverter.ConvertFromRSASecurityKey(
                                        new RsaSecurityKey(ExportRsaPublic(rsa)) { KeyId = rsa.KeyId }),
            ECDsaSecurityKey ec  => JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
                                        new ECDsaSecurityKey(ECDsa.Create(ec.ECDsa.ExportParameters(false))) { KeyId = ec.KeyId }),
            _ => throw new NotSupportedException(
                     $"Key type '{key.GetType().Name}' is not supported. Use RSA or ECDSA keys."),
        };

        // Defence in depth: never publish private parameters.
        jwk.D = null; jwk.DP = null; jwk.DQ = null; jwk.P = null; jwk.Q = null; jwk.QI = null;

        jwk.Use = JsonWebKeyUseNames.Sig;
        if (!string.IsNullOrEmpty(algorithm))
            jwk.Alg = algorithm;

        return jwk;
    }

    private static JsonWebKey FromPublicCertificate(X509Certificate2 certificate, string? keyId)
    {
        var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
            return JsonWebKeyConverter.ConvertFromRSASecurityKey(
                new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = keyId });

        var ecdsa = certificate.GetECDsaPublicKey()
                    ?? throw new NotSupportedException("Only RSA and ECDSA certificates are supported.");
        return JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
            new ECDsaSecurityKey(ECDsa.Create(ecdsa.ExportParameters(false))) { KeyId = keyId });
    }

    private static RSAParameters ExportRsaPublic(RsaSecurityKey key)
    {
        if (key.Rsa is not null)
            return key.Rsa.ExportParameters(false);

        return new RSAParameters
        {
            Modulus  = key.Parameters.Modulus,
            Exponent = key.Parameters.Exponent,
        };
    }
}
