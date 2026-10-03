using Microsoft.EntityFrameworkCore;
using PulseAuth.EntityFramework.Entities;
using PulseAuth.EntityFramework.Tests.Infrastructure;
using PulseAuth.Helpers;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Tests;

public class RefreshTokenStoreTests
{
    private static RefreshToken NewToken(
        string value, string subject = "alice", string client = "spa",
        string? previousTokenId = null, DateTime? expiresAt = null) => new()
    {
        Token           = value,
        ClientId        = client,
        SubjectId       = subject,
        Scopes          = ["openid", "offline_access"],
        CreatedAt       = DateTime.UtcNow,
        ExpiresAt       = expiresAt ?? DateTime.UtcNow.AddDays(30),
        PreviousTokenId = previousTokenId,
    };

    [Fact]
    public async Task Store_PersistsOnlyAHash_AndFindReturnsThePresentedValue()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = db.RefreshTokenStore(ctx);
        await store.StoreAsync(NewToken("raw-refresh-token", previousTokenId: "prev-id"));

        var row = await ctx.RefreshTokens.AsNoTracking().SingleAsync();
        Assert.Equal(GrantKeyHelper.ToStorageKey("raw-refresh-token"), row.Key);
        Assert.DoesNotContain("raw-refresh-token", row.Key);

        var found = await store.FindByTokenAsync("raw-refresh-token");
        Assert.NotNull(found);
        Assert.Equal("raw-refresh-token", found!.Token);
        Assert.Equal("alice", found.SubjectId);
        Assert.Equal("spa", found.ClientId);
        Assert.Equal("prev-id", found.PreviousTokenId);
        Assert.Equal(new[] { "openid", "offline_access" }, found.Scopes.ToArray());
    }

    [Fact]
    public async Task TryConsume_WithGracePeriod_RecordsRotationTime()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = db.RefreshTokenStore(ctx);
        await store.StoreAsync(NewToken("rt"));

        Assert.True(await store.TryConsumeAsync("rt", TimeSpan.FromSeconds(10)));
        Assert.False(await store.TryConsumeAsync("rt", TimeSpan.FromSeconds(10)));

        var consumed = (await store.FindByTokenAsync("rt"))!;
        Assert.True(consumed.IsConsumed);
        Assert.True(consumed.ExpiresAt <= DateTime.UtcNow.AddSeconds(11));
        Assert.True(consumed.IsWithinReuseGracePeriod(TimeSpan.FromSeconds(10), DateTime.UtcNow));
        Assert.False(consumed.IsWithinReuseGracePeriod(TimeSpan.FromSeconds(10), DateTime.UtcNow.AddSeconds(11)));
    }

    [Fact]
    public async Task TryConsume_ConcurrentRequests_ExactlyOneWins()
    {
        using var db = new SqliteTestDatabase();
        await using (var ctx = db.CreateContext())
            await db.RefreshTokenStore(ctx).StoreAsync(NewToken("contended"));

        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(async _ =>
        {
            await using var ctx = db.CreateContext();   // one connection per "request"
            return await db.RefreshTokenStore(ctx).TryConsumeAsync("contended", TimeSpan.FromSeconds(10));
        }));

        Assert.Equal(1, results.Count(r => r));
    }

    [Fact]
    public async Task Revoke_NeverFallsInsideTheGraceWindow()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = db.RefreshTokenStore(ctx);
        await store.StoreAsync(NewToken("revoked"));
        await store.StoreAsync(NewToken("rotated-then-revoked"));
        await store.TryConsumeAsync("rotated-then-revoked", TimeSpan.FromSeconds(10));

        await store.ConsumeAsync("revoked");
        await store.ConsumeAsync("rotated-then-revoked");

        var grace = TimeSpan.FromSeconds(10);
        var now   = DateTime.UtcNow.AddMilliseconds(10);
        Assert.False((await store.FindByTokenAsync("revoked"))!.IsWithinReuseGracePeriod(grace, now));
        Assert.False((await store.FindByTokenAsync("rotated-then-revoked"))!.IsWithinReuseGracePeriod(grace, now));
    }

    [Fact]
    public async Task RevokeBySubject_OnlyAffectsThatUserAndClient()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = db.RefreshTokenStore(ctx);
        await store.StoreAsync(NewToken("alice-spa"));
        await store.StoreAsync(NewToken("alice-other-client", client: "mobile"));
        await store.StoreAsync(NewToken("bob-spa", subject: "bob"));

        await store.RevokeBySubjectAsync("alice", "spa");

        Assert.True((await store.FindByTokenAsync("alice-spa"))!.IsConsumed);
        Assert.False((await store.FindByTokenAsync("alice-other-client"))!.IsConsumed);
        Assert.False((await store.FindByTokenAsync("bob-spa"))!.IsConsumed);
    }

    [Fact]
    public async Task RevokeFamily_RevokesAncestorsDescendantsAndForks_ButNotOtherSessions()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = db.RefreshTokenStore(ctx);
        var grace = TimeSpan.FromSeconds(10);

        // Root written by PulseAuth <= 1.2.x: raw value as key (legacy row)
        ctx.RefreshTokens.Add(new RefreshTokenEntity
        {
            Key = "root", ClientId = "spa", SubjectId = "alice", Scopes = "openid offline_access",
            CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddDays(30),
        });
        await ctx.SaveChangesAsync();

        await store.TryConsumeAsync("root", grace);
        await store.StoreAsync(NewToken("t1",  previousTokenId: RefreshToken.ComputeTokenId("root")));
        await store.TryConsumeAsync("t1", grace);
        await store.StoreAsync(NewToken("t2a", previousTokenId: RefreshToken.ComputeTokenId("t1")));
        await store.StoreAsync(NewToken("t2b", previousTokenId: RefreshToken.ComputeTokenId("t1"))); // grace fork
        await store.TryConsumeAsync("t2a", grace);
        await store.StoreAsync(NewToken("t3",  previousTokenId: RefreshToken.ComputeTokenId("t2a")));
        await store.StoreAsync(NewToken("other-session"));                                          // same user, other login
        await store.StoreAsync(NewToken("bob", subject: "bob"));

        // An attacker replays t1 (intermediate token)
        var reused  = (await store.FindByTokenAsync("t1"))!;
        var revoked = await store.RevokeFamilyAsync(reused);

        // still-usable members of the family: root/t1/t2a (inside grace) + t2b + t3
        Assert.Equal(5, revoked);
        foreach (var token in new[] { "root", "t1", "t2a", "t2b", "t3" })
        {
            var rt = (await store.FindByTokenAsync(token))!;
            Assert.True(rt.IsConsumed);
            Assert.False(rt.IsWithinReuseGracePeriod(grace, DateTime.UtcNow.AddMilliseconds(10)));
        }
        Assert.False((await store.FindByTokenAsync("other-session"))!.IsConsumed);
        Assert.False((await store.FindByTokenAsync("bob"))!.IsConsumed);
    }

    [Fact]
    public async Task RemoveExpired_KeepsConsumedTokensForTheRetentionPeriod()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = db.RefreshTokenStore(ctx, o => o.ConsumedRefreshTokenRetention = TimeSpan.FromDays(7));
        var now = DateTime.UtcNow;

        await store.StoreAsync(NewToken("valid"));
        await store.StoreAsync(NewToken("expired", expiresAt: now.AddMinutes(-1)));
        await store.StoreAsync(NewToken("consumed-recently", expiresAt: now.AddDays(-1)));
        await store.StoreAsync(NewToken("consumed-long-ago", expiresAt: now.AddDays(-8)));
        await ctx.RefreshTokens
            .Where(t => t.Key == GrantKeyHelper.ToStorageKey("consumed-recently") ||
                        t.Key == GrantKeyHelper.ToStorageKey("consumed-long-ago"))
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.IsConsumed, true));

        await store.RemoveExpiredAsync();

        Assert.NotNull(await store.FindByTokenAsync("valid"));
        Assert.Null(await store.FindByTokenAsync("expired"));
        Assert.NotNull(await store.FindByTokenAsync("consumed-recently"));   // reuse still detectable
        Assert.Null(await store.FindByTokenAsync("consumed-long-ago"));
    }

    [Fact]
    public async Task LegacyPlainTextRow_IsStillFoundAndRotatable()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        ctx.RefreshTokens.Add(new RefreshTokenEntity
        {
            Key = "legacy-refresh", ClientId = "spa", SubjectId = "alice", Scopes = "openid",
            CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddDays(1),
        });
        await ctx.SaveChangesAsync();
        var store = db.RefreshTokenStore(ctx);

        Assert.NotNull(await store.FindByTokenAsync("legacy-refresh"));
        Assert.True(await store.TryConsumeAsync("legacy-refresh", TimeSpan.Zero));
        Assert.False(await store.TryConsumeAsync("legacy-refresh", TimeSpan.Zero));
    }
}
