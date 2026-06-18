using System.Security.Cryptography;
using System.Text;

namespace PulseAuth.Helpers;

/// <summary>
/// Helper for generating and hashing client secrets.
/// </summary>
public static class ClientSecretHelper
{
    /// <summary>
    /// Generates a cryptographically-random client secret.
    /// Store the plaintext value securely — it is shown only once.
    /// </summary>
    public static string GenerateSecret(int byteLength = 32)
    {
        var bytes = new byte[byteLength];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    /// <summary>
    /// Returns the SHA-256 hex hash of a plaintext secret.
    /// Store this hash in the <see cref="Models.Client.ClientSecretHash"/> property.
    /// </summary>
    public static string HashSecret(string secret)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();

    /// <summary>
    /// Generates a secret and its hash in a single call.
    /// </summary>
    public static (string PlainText, string Hash) GenerateAndHash()
    {
        var secret = GenerateSecret();
        return (secret, HashSecret(secret));
    }
}
