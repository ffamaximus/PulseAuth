using Microsoft.EntityFrameworkCore;
using PulseAuth.EntityFramework.Entities;
using PulseAuth.EntityFramework.Stores;
using PulseAuth.EntityFramework.Tests.Infrastructure;
using PulseAuth.Helpers;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Tests;

public class AuthorizationCodeStoreTests
{
    private static AuthorizationCode NewCode(string value, DateTime? expiresAt = null) => new()
    {
        Code                = value,
        ClientId            = "spa",
        SubjectId           = "alice",
        Scopes              = ["openid", "profile"],
        CodeChallenge       = "challenge",
        CodeChallengeMethod = "S256",
        RedirectUri         = "https://app.example/cb",
        Nonce               = "n-123",
        CreatedAt           = DateTime.UtcNow,
        ExpiresAt           = expiresAt ?? DateTime.UtcNow.AddMinutes(5),
    };

    [Fact]
    public async Task Store_PersistsOnlyAHash_AndFindRoundTripsAllFields()
    {
        using var db = new SqliteTestDatabase();
        await using (var ctx = db.CreateContext())
            await new EfAuthorizationCodeStore(ctx).StoreAsync(NewCode("raw-code-value"));

        await using var read = db.CreateContext();
        var row = await read.AuthorizationCodes.AsNoTracking().SingleAsync();
        Assert.StartsWith(GrantKeyHelper.HashPrefix, row.Key);
        Assert.DoesNotContain("raw-code-value", row.Key);

        var found = await new EfAuthorizationCodeStore(read).FindByCodeAsync("raw-code-value");
        Assert.NotNull(found);
        Assert.Equal("raw-code-value", found!.Code);
        Assert.Equal("spa", found.ClientId);
        Assert.Equal("alice", found.SubjectId);
        Assert.Equal(new[] { "openid", "profile" }, found.Scopes.ToArray());
        Assert.Equal("challenge", found.CodeChallenge);
        Assert.Equal("S256", found.CodeChallengeMethod);
        Assert.Equal("https://app.example/cb", found.RedirectUri);
        Assert.Equal("n-123", found.Nonce);
        Assert.False(found.IsConsumed);

        Assert.Null(await new EfAuthorizationCodeStore(read).FindByCodeAsync("another-code"));
    }

    [Fact]
    public async Task TryConsume_SucceedsOnlyOnce()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = new EfAuthorizationCodeStore(ctx);
        await store.StoreAsync(NewCode("code-1"));

        Assert.True(await store.TryConsumeAsync("code-1"));
        Assert.False(await store.TryConsumeAsync("code-1"));
        Assert.True((await store.FindByCodeAsync("code-1"))!.IsConsumed);
        Assert.False(await store.TryConsumeAsync("unknown"));
    }

    [Fact]
    public async Task TryConsume_ConcurrentRequests_ExactlyOneWins()
    {
        using var db = new SqliteTestDatabase();
        await using (var ctx = db.CreateContext())
            await new EfAuthorizationCodeStore(ctx).StoreAsync(NewCode("contended"));

        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(async _ =>
        {
            await using var ctx = db.CreateContext();   // one connection per "request"
            return await new EfAuthorizationCodeStore(ctx).TryConsumeAsync("contended");
        }));

        Assert.Equal(1, results.Count(r => r));
    }

    [Fact]
    public async Task LegacyPlainTextRow_IsStillFoundAndConsumable()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        ctx.AuthorizationCodes.Add(new AuthorizationCodeEntity
        {
            Key = "legacy-code", ClientId = "spa", SubjectId = "alice", Scopes = "openid",
            CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddMinutes(5),
        });
        await ctx.SaveChangesAsync();

        var store = new EfAuthorizationCodeStore(ctx);
        Assert.NotNull(await store.FindByCodeAsync("legacy-code"));
        Assert.True(await store.TryConsumeAsync("legacy-code"));
        Assert.False(await store.TryConsumeAsync("legacy-code"));
    }

    [Fact]
    public async Task RemoveExpired_DeletesExpiredAndConsumedCodes()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = new EfAuthorizationCodeStore(ctx);
        await store.StoreAsync(NewCode("valid"));
        await store.StoreAsync(NewCode("expired", DateTime.UtcNow.AddMinutes(-1)));
        await store.StoreAsync(NewCode("consumed"));
        await store.TryConsumeAsync("consumed");

        await store.RemoveExpiredAsync();

        Assert.NotNull(await store.FindByCodeAsync("valid"));
        Assert.Null(await store.FindByCodeAsync("expired"));
        Assert.Null(await store.FindByCodeAsync("consumed"));
    }
}
