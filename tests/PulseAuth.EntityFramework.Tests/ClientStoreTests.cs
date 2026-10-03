using PulseAuth.EntityFramework.Entities;
using PulseAuth.EntityFramework.Stores;
using PulseAuth.EntityFramework.Tests.Infrastructure;

namespace PulseAuth.EntityFramework.Tests;

public class ClientStoreTests
{
    private static async Task SeedAsync(SqliteTestDatabase db)
    {
        await using var ctx = db.CreateContext();
        ctx.Clients.Add(new ClientEntity
        {
            ClientId = "spa", ClientName = "SPA", ClientSecretHash = "hash", AllowOfflineAccess = true,
            AccessTokenLifetime = 900, RequirePkce = true,
            GrantTypes     = [new() { GrantType = "authorization_code" }, new() { GrantType = "refresh_token" }],
            RedirectUris   = [new() { RedirectUri = "https://app.example/cb" }],
            PostLogoutUris = [new() { PostLogoutUri = "https://app.example/bye" }],
            AllowedScopes  = [new() { Scope = "openid" }, new() { Scope = "offline_access" }],
            CorsOrigins    = [new() { Origin = "https://app.example" }, new() { Origin = "https://admin.example/" }],
            Claims         = [new() { Type = "tenant", Value = "acme" }],
        });
        ctx.Clients.Add(new ClientEntity
        {
            ClientId = "disabled", ClientName = "Disabled", Enabled = false,
            CorsOrigins = [new() { Origin = "https://disabled.example" }],
        });
        await ctx.SaveChangesAsync();
    }

    [Fact]
    public async Task FindClientById_MapsAllCollections()
    {
        using var db = new SqliteTestDatabase();
        await SeedAsync(db);
        await using var ctx = db.CreateContext();

        var client = await new EfClientStore(ctx).FindClientByIdAsync("spa");

        Assert.NotNull(client);
        Assert.Equal("SPA", client!.ClientName);
        Assert.Equal("hash", client.ClientSecretHash);
        Assert.True(client.AllowOfflineAccess);
        Assert.Equal(900, client.AccessTokenLifetime);
        Assert.Equal(2, client.AllowedGrantTypes.Count);
        Assert.Contains("https://app.example/cb", client.RedirectUris);
        Assert.Contains("https://app.example/bye", client.PostLogoutRedirectUris);
        Assert.Contains("offline_access", client.AllowedScopes);
        Assert.Equal(2, client.AllowedCorsOrigins.Count);
        Assert.Equal("acme", client.Claims["tenant"]);
    }

    [Fact]
    public async Task FindClientById_DisabledOrUnknown_ReturnsNull()
    {
        using var db = new SqliteTestDatabase();
        await SeedAsync(db);
        await using var ctx = db.CreateContext();
        var store = new EfClientStore(ctx);

        Assert.Null(await store.FindClientByIdAsync("disabled"));
        Assert.Null(await store.FindClientByIdAsync("unknown"));
    }

    [Theory]
    [InlineData("https://app.example", true)]
    [InlineData("https://app.example/", true)]       // trailing slash tolerated
    [InlineData("https://admin.example", true)]      // stored with trailing slash
    [InlineData("https://disabled.example", false)]  // client disabled
    [InlineData("https://evil.example", false)]
    public async Task IsOriginAllowed(string origin, bool expected)
    {
        using var db = new SqliteTestDatabase();
        await SeedAsync(db);
        await using var ctx = db.CreateContext();

        Assert.Equal(expected, await new EfClientStore(ctx).IsOriginAllowedAsync(origin));
    }
}
