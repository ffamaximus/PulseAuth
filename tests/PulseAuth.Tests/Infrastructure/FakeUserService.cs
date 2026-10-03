using System.Collections.Concurrent;
using System.Security.Claims;
using PulseAuth.Abstractions;
using PulseAuth.Models;

namespace PulseAuth.Tests.Infrastructure;

/// <summary>In-memory user store for tests. User "alice" / password "pw".</summary>
public sealed class FakeUserService(BlockedUsers blocked) : IUserAuthenticationService
{
    public const string UserId   = "alice";
    public const string Password = "pw";

    private static UserInfo Alice() => new()
    {
        SubjectId = UserId,
        Username  = UserId,
        Name      = "Alice",
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
