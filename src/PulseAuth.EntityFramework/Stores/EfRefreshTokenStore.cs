using Microsoft.EntityFrameworkCore;
using PulseAuth.Abstractions;
using PulseAuth.EntityFramework.Abstractions;
using PulseAuth.EntityFramework.Entities;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Stores;

/// <summary>
/// Entity Framework Core implementation of <see cref="IRefreshTokenStore"/>. This class provides methods to store, retrieve, consume, and revoke refresh tokens using a database context. It uses the <see cref="IPulseAuthDbContext"/> to interact with the underlying database and perform CRUD operations on the refresh token entities. This implementation is suitable for production use in scenarios where you want to persist refresh tokens across application restarts and share them across multiple instances of your application. Make sure to configure the database context properly and apply any necessary migrations to create the required tables for storing refresh tokens.
/// </summary>
public class EfRefreshTokenStore : IRefreshTokenStore
{
    private readonly IPulseAuthDbContext _db;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfRefreshTokenStore"/> class with the specified database context.
    /// </summary>
    /// <param name="db"></param>
    public EfRefreshTokenStore(IPulseAuthDbContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    /// <summary>
    /// Stores a new refresh token in the database. This method takes a <see cref="RefreshToken"/> object as input and creates a corresponding <see cref="RefreshTokenEntity"/> to be saved in the database. The properties of the refresh token, such as the token string, client ID, subject ID, scopes, creation time, expiration time, and previous token ID (if any), are mapped to the entity before being added to the database context. After adding the new entity, the method calls DbContext.SaveChangesAsync to persist the changes to the database. This allows the application to keep track of issued refresh tokens and manage their lifecycle effectively.
    /// </summary>
    /// <param name="token"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task StoreAsync(RefreshToken token, CancellationToken ct = default)
    {
        _db.RefreshTokens.Add(new RefreshTokenEntity
        {
            Key             = token.Token,
            ClientId        = token.ClientId,
            SubjectId       = token.SubjectId,
            Scopes          = string.Join(" ", token.Scopes),
            CreatedAt       = token.CreatedAt,
            ExpiresAt       = token.ExpiresAt,
            PreviousTokenId = token.PreviousTokenId,
        });
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Finds a refresh token by its token string. This method queries the database for a refresh token entity that matches the provided token string. If a matching entity is found, it is mapped back to a <see cref="RefreshToken"/> object, which is then returned. If no matching entity is found, the method returns null. The method uses asynchronous database operations to ensure non-blocking calls and supports cancellation through the provided cancellation token. This allows the application to retrieve refresh tokens efficiently while maintaining responsiveness.
    /// </summary>
    /// <param name="token"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task<RefreshToken?> FindByTokenAsync(string token, CancellationToken ct = default)
    {
        var e = await _db.RefreshTokens
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Key == token, ct);

        if (e is null) return null;

        return new RefreshToken
        {
            Token           = e.Key,
            ClientId        = e.ClientId,
            SubjectId       = e.SubjectId,
            Scopes          = e.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            CreatedAt       = e.CreatedAt,
            ExpiresAt       = e.ExpiresAt,
            IsConsumed      = e.IsConsumed,
            PreviousTokenId = e.PreviousTokenId,
        };
    }

    /// <summary>
    /// Marks a refresh token as consumed. This method updates the database record for the refresh token that matches the provided token string, setting its IsConsumed property to true. This indicates that the token has been used and should not be accepted for future token refresh requests. The method uses an efficient update operation that directly modifies the relevant record in the database without needing to load it into memory first. This approach helps maintain performance while ensuring that consumed tokens are properly tracked and invalidated in the system.
    /// </summary>
    /// <param name="token"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task ConsumeAsync(string token, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        await _db.RefreshTokens
            .Where(t => t.Key == token)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.IsConsumed, true)
                // Revoked tokens must never fall inside the rotation reuse grace window.
                .SetProperty(t => t.ExpiresAt, t => t.ExpiresAt > now ? now : t.ExpiresAt), ct);
    }

    /// <summary>
    /// Atomically consumes the token using a single conditional UPDATE
    /// (<c>WHERE Key = @token AND IsConsumed = 0</c>). Returns <c>true</c> only if this
    /// call flipped the flag; concurrent requests with the same value get <c>false</c>.
    /// </summary>
    public async Task<bool> TryConsumeAsync(string token, TimeSpan reuseGracePeriod, CancellationToken ct = default)
    {
        int affected;
        if (reuseGracePeriod > TimeSpan.Zero)
        {
            // Record the rotation time in ExpiresAt (no schema change needed).
            var graceUntil = DateTime.UtcNow.Add(reuseGracePeriod);
            affected = await _db.RefreshTokens
                .Where(t => t.Key == token && !t.IsConsumed)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(t => t.IsConsumed, true)
                    .SetProperty(t => t.ExpiresAt, graceUntil), ct);
        }
        else
        {
            affected = await _db.RefreshTokens
                .Where(t => t.Key == token && !t.IsConsumed)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.IsConsumed, true), ct);
        }

        return affected == 1;
    }

    /// <summary>
    /// Revokes all refresh tokens for a given subject ID and client ID. This method updates all refresh token records in the database that match the specified subject ID and client ID, marking them as consumed by setting their IsConsumed property to true. This is typically used in scenarios such as user logout or account compromise, where you want to invalidate all existing refresh tokens for a user and client combination to prevent unauthorized access. The method performs a bulk update operation to efficiently mark all relevant tokens as consumed without needing to load them into memory first, ensuring that the revocation process is fast and effective.
    /// </summary>
    /// <param name="subjectId"></param>
    /// <param name="clientId"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task RevokeBySubjectAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        await _db.RefreshTokens
            .Where(t => t.SubjectId == subjectId && t.ClientId == clientId &&
                        (!t.IsConsumed || t.ExpiresAt > now))
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.IsConsumed, true)
                .SetProperty(t => t.ExpiresAt, t => t.ExpiresAt > now ? now : t.ExpiresAt), ct);
    }

    /// <summary>
    /// Removes expired and consumed refresh tokens from the database. This method queries the database for refresh token records that have either expired (i.e., their ExpiresAt property is less than the current UTC time) or have been marked as consumed (i.e., their IsConsumed property is true). It then deletes these records from the database to clean up old tokens and free up storage space. This method can be called periodically, such as through a background service or scheduled task, to ensure that the database does not retain unnecessary token records and remains efficient in managing refresh tokens over time.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var cutoff = DateTime.UtcNow;
        await _db.RefreshTokens
            .Where(t => t.ExpiresAt < cutoff || t.IsConsumed)
            .ExecuteDeleteAsync(ct);
    }
}
