using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;

namespace PulseAuth.Services;

/// <summary>
/// Developer RSA-2048 key material service.
/// </summary>
/// <remarks>
/// <para>
/// When a key file path is supplied (the default for
/// <c>AddDeveloperSigningCredential()</c>), the key is created once and persisted as a
/// PKCS#8 PEM file, so tokens keep validating after a restart and every instance that
/// shares the file signs with the same key and publishes the same <c>kid</c>.
/// </para>
/// <para>
/// Without a path, a new in-memory key is generated on every start (all previously
/// issued tokens become invalid and multi-instance deployments break).
/// </para>
/// <para>
/// NOT intended for production: the private key sits unencrypted on disk. Use
/// <c>AddSigningCredential(...)</c> with a certificate / Key Vault key instead.
/// </para>
/// </remarks>
public sealed class RsaKeyMaterialService : IKeyMaterialService, IDisposable
{
    /// <summary>Default file name used by <c>AddDeveloperSigningCredential()</c>.</summary>
    public const string DefaultKeyFileName = "pulseauth-tempkey.pem";

    private readonly RSA _rsa;
    private readonly StaticKeyMaterialService _inner;

    /// <summary>
    /// Initializes a new instance of the <see cref="RsaKeyMaterialService"/> class.
    /// </summary>
    /// <param name="keyFilePath">
    /// Path of the PEM file where the key is persisted. If the file exists the key is
    /// loaded from it; otherwise a new key is generated and written. <c>null</c> keeps
    /// the key in memory only (regenerated on every start).
    /// </param>
    /// <param name="logger">Optional logger.</param>
    public RsaKeyMaterialService(string? keyFilePath = null, ILogger<RsaKeyMaterialService>? logger = null)
    {
        if (string.IsNullOrWhiteSpace(keyFilePath))
        {
            _rsa = RSA.Create(2048);
            logger?.LogWarning(
                "PulseAuth is using an EPHEMERAL in-memory signing key. Tokens become invalid on restart " +
                "and will not validate across multiple instances. Do not use this in production.");
        }
        else
        {
            var fullPath = Path.GetFullPath(keyFilePath);
            _rsa = LoadOrCreate(fullPath, out var outcome, out var writeError);

            if (outcome == KeyFileOutcome.NotPersisted)
            {
                // e.g. read-only container file system: keep working like previous versions.
                logger?.LogWarning(writeError,
                    "PulseAuth could not persist the developer signing key to '{Path}'. Falling back to an " +
                    "EPHEMERAL in-memory key: tokens become invalid on restart and will not validate across " +
                    "instances. Configure a writable path, or use AddSigningCredential(...).", fullPath);
            }
            else
            {
                logger?.LogWarning(
                    "PulseAuth is using a developer signing key {Action} '{Path}'. The private key is stored " +
                    "unencrypted; keep the file out of source control and use AddSigningCredential(...) in production.",
                    outcome == KeyFileOutcome.Created ? "created at" : "loaded from", fullPath);
            }
        }

        var key = new RsaSecurityKey(_rsa);
        _inner  = new StaticKeyMaterialService(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
    }

    /// <inheritdoc />
    public Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default)
        => _inner.GetSigningCredentialsAsync(ct);

    /// <inheritdoc />
    public Task<IEnumerable<SecurityKey>> GetValidationKeysAsync(CancellationToken ct = default)
        => _inner.GetValidationKeysAsync(ct);

    /// <inheritdoc />
    public Task<JsonWebKeySet> GetPublicKeysAsync(CancellationToken ct = default)
        => _inner.GetPublicKeysAsync(ct);

    /// <inheritdoc />
    public void Dispose() => _rsa.Dispose();

    // ── Persistence ──────────────────────────────────────────────────────────

    private enum KeyFileOutcome { Loaded, Created, NotPersisted }

    private static RSA LoadOrCreate(string path, out KeyFileOutcome outcome, out Exception? writeError)
    {
        writeError = null;

        // An existing file is always used. If it is unreadable or corrupt we fail fast
        // instead of silently switching keys.
        if (File.Exists(path))
        {
            outcome = KeyFileOutcome.Loaded;
            return LoadFromPem(path);
        }

        var rsa      = RSA.Create(2048);
        var tempPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            // Write to a temp file first, then move it into place atomically, so other
            // instances never observe a half-written key file.
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

                using var writer = new StreamWriter(stream);
                writer.Write(rsa.ExportPkcs8PrivateKeyPem());
            }

            try
            {
                File.Move(tempPath, path, overwrite: false);
            }
            catch (IOException) when (File.Exists(path))
            {
                // Lost the race: another instance created the key first — use theirs.
                TryDelete(tempPath);
                rsa.Dispose();
                outcome = KeyFileOutcome.Loaded;
                return LoadFromPem(path);
            }

            outcome = KeyFileOutcome.Created;
            return rsa;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or NotSupportedException)
        {
            // Read-only / restricted file system: do not crash the host, keep an in-memory key
            // (same behaviour as previous versions).
            TryDelete(tempPath);
            writeError = ex;
            outcome    = KeyFileOutcome.NotPersisted;
            return rsa;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // best effort
        }
    }

    private static RSA LoadFromPem(string path)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(File.ReadAllText(path));
            return rsa;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            throw new InvalidOperationException(
                $"The PulseAuth signing key file '{path}' is not a valid RSA PEM private key.", ex);
        }
    }
}
