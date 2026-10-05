using System.Collections.Concurrent;
using System.Security.Claims;
using PulseAuth.Abstractions;
using PulseAuth.Models;

namespace PulseAuth.Tests.Infrastructure;

/// <summary>In-memory user store for tests. User "alice" / password "pw".</summary>
public sealed class FakeUserService(BlockedUsers blocked, SecurityStamps stamps) : IUserAuthenticationService
{
    public const string UserId   = "alice";
    public const string Password = "pw";

    private static UserInfo Alice() => new()
    {
        SubjectId = UserId,
        Username  = UserId,
        Name      = "Alice",
        Locale    = "es-CO",
        ZoneInfo  = "America/Bogota",
        UpdatedAt = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        Address   = new UserAddress { Locality = "Bogotá", Country = "CO" },
        AdditionalClaims =
        [
            new Claim("sub", "mallory"),     // must never override the real subject
            new Claim("scope", "admin"),     // must never extend scopes
            new Claim("role", "a"),
            new Claim("role", "b"),
        ],
    };

    public Task<UserInfo?> ValidateCredentialsAsync(string username, string password, CancellationToken ct = default)
        => Task.FromResult(username == UserId && password == Password ? Alice() : null);

    public Task<UserInfo?> GetUserByIdAsync(string subjectId, CancellationToken ct = default)
        => Task.FromResult(subjectId == UserId ? Alice() : null);

    public Task<bool> IsActiveAsync(string subjectId, CancellationToken ct = default)
        => Task.FromResult(subjectId == UserId && !blocked.Contains(subjectId));

    public Task<string?> GetSecurityStampAsync(string subjectId, CancellationToken ct = default)
        => Task.FromResult<string?>(subjectId == UserId ? stamps.Get(subjectId) : null);

    public Task<UserInfo?> FindByExternalProviderAsync(string provider, string externalId, CancellationToken ct = default)
        => Task.FromResult<UserInfo?>(Alice());

    public Task<UserInfo> AutoProvisionUserAsync(string provider, string externalId, IEnumerable<Claim> externalClaims, CancellationToken ct = default)
        => Task.FromResult(Alice());
}

/// <summary>Per-test-host list of blocked users (tests run in parallel).</summary>
public sealed class BlockedUsers
{
    private readonly ConcurrentDictionary<string, bool> _users = new();
    public void Block(string subjectId) => _users[subjectId] = true;
    public bool Contains(string subjectId) => _users.ContainsKey(subjectId);
}

/// <summary>Per-test-host security stamps (change one to simulate a password change).</summary>
public sealed class SecurityStamps
{
    private readonly ConcurrentDictionary<string, string> _stamps = new();
    public string Get(string subjectId) => _stamps.GetOrAdd(subjectId, _ => Guid.NewGuid().ToString());
    public void Change(string subjectId) => _stamps[subjectId] = Guid.NewGuid().ToString();
}
