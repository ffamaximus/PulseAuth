using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using PulseAuth.EntityFramework.Entities;
using PulseAuth.EntityFramework.Stores;
using PulseAuth.EntityFramework.Tests.Infrastructure;
using PulseAuth.Helpers;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Tests;

public class ReferenceTokenAndConsentStoreTests
{
    private static ReferenceToken NewReference(string handle, string subject = "alice", string client = "spa", DateTime? expiresAt = null) => new()
    {
        Handle = handle, ClientId = client, SubjectId = subject, Jwt = "header.payload.signature",
        CreatedAt = DateTime.UtcNow, ExpiresAt = expiresAt ?? DateTime.UtcNow.AddHours(1),
    };

    [Fact]
    public async Task ReferenceTokens_StoredHashed_FindRemoveAndCleanup()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = new EfReferenceTokenStore(ctx);

        await store.StoreAsync(NewReference("handle-1"));
        await store.StoreAsync(NewReference("handle-2"));
        await store.StoreAsync(NewReference("bob-handle", subject: "bob"));
        await store.StoreAsync(NewReference("expired", expiresAt: DateTime.UtcNow.AddMinutes(-1)));

        var row = await ctx.ReferenceTokens.AsNoTracking().FirstAsync(t => t.SubjectId == "bob");
        Assert.Equal(GrantKeyHelper.ToStorageKey("bob-handle"), row.Key);

        var found = await store.FindAsync("handle-1");
        Assert.NotNull(found);
        Assert.Equal("handle-1", found!.Handle);
        Assert.Equal("header.payload.signature", found.Jwt);

        await store.RemoveAsync("handle-1");
        Assert.Null(await store.FindAsync("handle-1"));

        await store.RemoveBySubjectAsync("alice", "spa");
        Assert.Null(await store.FindAsync("handle-2"));
        Assert.NotNull(await store.FindAsync("bob-handle"));

        await store.RemoveExpiredAsync();
        Assert.Null(await store.FindAsync("expired"));
        Assert.NotNull(await store.FindAsync("bob-handle"));
    }

    [Fact]
    public async Task Consents_AreUpserted_OnePerUserAndClient()
    {
        using var db = new SqliteTestDatabase();
        await using (var ctx = db.CreateContext())
        {
            var store = new EfConsentStore(ctx);
            await store.StoreAsync(new Consent { SubjectId = "alice", ClientId = "app", Scopes = ["openid"], Remember = true });
            await store.StoreAsync(new Consent { SubjectId = "alice", ClientId = "app", Scopes = ["openid", "profile"], Remember = false,
                                                 ExpiresAt = DateTime.UtcNow.AddMinutes(5) });
            await store.StoreAsync(new Consent { SubjectId = "alice", ClientId = "other", Scopes = ["openid"] });
        }

        await using var read = db.CreateContext();
        var readStore = new EfConsentStore(read);
        Assert.Equal(2, await read.Consents.CountAsync());

        var consent = await readStore.GetAsync("alice", "app");
        Assert.NotNull(consent);
        Assert.Equal(new[] { "openid", "profile" }, consent!.Scopes.ToArray());
        Assert.False(consent.Remember);
        Assert.True(consent.Covers(["profile"]));
        Assert.False(consent.Covers(["email"]));

        Assert.Equal(2, (await readStore.GetBySubjectAsync("alice")).Count);

        await readStore.RemoveAsync("alice", "app");
        Assert.Null(await readStore.GetAsync("alice", "app"));
        Assert.NotNull(await readStore.GetAsync("alice", "other"));
    }

    [Fact]
    public async Task RefreshToken_UserStamp_RoundTrips()
    {
        using var db = new SqliteTestDatabase();
        await using var ctx = db.CreateContext();
        var store = db.RefreshTokenStore(ctx);
        await store.StoreAsync(new RefreshToken
        {
            Token = "rt", ClientId = "spa", SubjectId = "alice", Scopes = ["openid"],
            ExpiresAt = DateTime.UtcNow.AddDays(1), UserStamp = "stamp-hash",
        });

        Assert.Equal("stamp-hash", (await store.FindByTokenAsync("rt"))!.UserStamp);
    }

    [Fact]
    public async Task Client_NewFields_AreMapped_AndCorsAnswerIsCached()
    {
        using var db = new SqliteTestDatabase();
        await using (var ctx = db.CreateContext())
        {
            ctx.Clients.Add(new ClientEntity
            {
                ClientId = "api", ClientName = "API", AccessTokenType = (int)AccessTokenType.Reference, AllowIntrospection = true,
                CorsOrigins = [new() { Origin = "https://app.example" }],
            });
            await ctx.SaveChangesAsync();
        }

        using var cache = new MemoryCache(new MemoryCacheOptions());
        await using (var ctx = db.CreateContext())
        {
            var store  = new EfClientStore(ctx, cache, SqliteTestDatabase.Options(o => o.CorsOriginCacheDuration = TimeSpan.FromMinutes(5)));
            var client = await store.FindClientByIdAsync("api");
            Assert.Equal(AccessTokenType.Reference, client!.AccessTokenType);
            Assert.True(client.AllowIntrospection);
            Assert.True(await store.IsOriginAllowedAsync("https://app.example"));

            // remove the origin: the cached answer is used until it expires
            await ctx.ClientCorsOrigins.ExecuteDeleteAsync();
            Assert.True(await store.IsOriginAllowedAsync("https://app.example"));
        }

        await using (var ctx = db.CreateContext())
        {
            // without cache the change is visible immediately
            Assert.False(await new EfClientStore(ctx).IsOriginAllowedAsync("https://app.example"));
        }
    }
}
