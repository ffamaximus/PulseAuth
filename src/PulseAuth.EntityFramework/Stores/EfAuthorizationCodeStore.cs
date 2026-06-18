using Microsoft.EntityFrameworkCore;
using PulseAuth.Abstractions;
using PulseAuth.EntityFramework.DbContext;
using PulseAuth.EntityFramework.Entities;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Stores;

/// <summary>
/// Entity Framework Core implementation of <see cref="IAuthorizationCodeStore"/>. This store uses a database to persist authorization codes, making it suitable for multi-instance deployments and production environments. The implementation includes methods to store new authorization codes, retrieve existing codes by their code string, mark codes as consumed, and remove expired or consumed codes from the database. The store relies on the <see cref="PulseAuthDbContext"/> to interact with the underlying database, and it uses asynchronous operations to ensure scalability and responsiveness.
/// </summary>
public class EfAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly PulseAuthDbContext _db;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfAuthorizationCodeStore"/> class with the specified database context. The database context is used to perform CRUD operations on the authorization code entities stored in the database. This constructor is typically called by dependency injection when you register the store in your application's service container. Make sure to configure the <see cref="PulseAuthDbContext"/> properly in your application to ensure that it can connect to your database and manage the authorization code entities effectively.
    /// </summary>
    /// <param name="db"></param>
    public EfAuthorizationCodeStore(PulseAuthDbContext db) => _db = db;

    /// <summary>
    /// Stores a new authorization code in the database. This method creates a new <see cref="AuthorizationCodeEntity"/> based on the provided <see cref="AuthorizationCode"/> model and saves it to the database. The stored information includes the client ID, subject ID, scopes, code challenge details, redirect URI, nonce, session ID, creation time, and expiration time. This allows the authorization code to be retrieved and validated later during the token exchange process.
    /// </summary>
    /// <param name="code"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task StoreAsync(AuthorizationCode code, CancellationToken ct = default)
    {
        _db.AuthorizationCodes.Add(new AuthorizationCodeEntity
        {
            Key                 = code.Code,
            ClientId            = code.ClientId,
            SubjectId           = code.SubjectId,
            Scopes              = string.Join(" ", code.Scopes),
            CodeChallenge       = code.CodeChallenge,
            CodeChallengeMethod = code.CodeChallengeMethod,
            RedirectUri         = code.RedirectUri,
            Nonce               = code.Nonce,
            SessionId           = code.SessionId,
            CreatedAt           = code.CreatedAt,
            ExpiresAt           = code.ExpiresAt,
        });
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Finds an authorization code by its code string. This method queries the database for an authorization code entity that matches the provided code string. If a matching entity is found, it is converted into an <see cref="AuthorizationCode"/> model and returned. If no matching entity is found, the method returns null. This allows the application to retrieve the details of an authorization code during the token exchange process and validate it against the expected values.
    /// </summary>
    /// <param name="code"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task<AuthorizationCode?> FindByCodeAsync(string code, CancellationToken ct = default)
    {
        var e = await _db.AuthorizationCodes
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Key == code, ct);

        if (e is null) return null;

        return new AuthorizationCode
        {
            Code                = e.Key,
            ClientId            = e.ClientId,
            SubjectId           = e.SubjectId,
            Scopes              = e.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            CodeChallenge       = e.CodeChallenge,
            CodeChallengeMethod = e.CodeChallengeMethod,
            RedirectUri         = e.RedirectUri,
            Nonce               = e.Nonce,
            SessionId           = e.SessionId,
            CreatedAt           = e.CreatedAt,
            ExpiresAt           = e.ExpiresAt,
            IsConsumed          = e.IsConsumed,
        };
    }

    /// <summary>
    /// Marks an authorization code as consumed. This method updates the database record for the specified authorization code to indicate that it has been consumed. This prevents the same authorization code from being used multiple times, which is a critical security measure in the OAuth2 authorization code flow. The method uses an efficient update operation to set the IsConsumed flag to true for the matching code string.
    /// </summary>
    /// <param name="code"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task ConsumeAsync(string code, CancellationToken ct = default)
    {
        await _db.AuthorizationCodes
            .Where(c => c.Key == code)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.IsConsumed, true), ct);
    }

    /// <summary>
    /// Removes expired and consumed authorization codes from the database. This method should be called periodically (e.g., via a background service) to clean up old codes and prevent the database from growing indefinitely. It deletes all authorization code records that have either expired (i.e., their ExpiresAt timestamp is in the past) or have been marked as consumed. This helps maintain the performance and efficiency of the database by removing unnecessary records.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var cutoff = DateTime.UtcNow;
        await _db.AuthorizationCodes
            .Where(c => c.ExpiresAt < cutoff || c.IsConsumed)
            .ExecuteDeleteAsync(ct);
    }
}
