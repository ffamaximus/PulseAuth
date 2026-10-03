using System.Net;
using PulseAuth.Tests.Infrastructure;
using static PulseAuth.Tests.Infrastructure.PulseAuthTestHost;

namespace PulseAuth.Tests;

public class RefreshTokenTests
{
    private static async Task<string> NewRefreshTokenAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await ReadJsonAsync(response)).GetProperty("refresh_token").GetString()!;
    }

    [Fact]
    public async Task ConcurrentRefreshes_InsideGracePeriod_AllSucceed()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var rt = (await host.CodeFlowAsync(http)).GetProperty("refresh_token").GetString()!;

        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => RefreshAsync(http, rt)));

        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
    }

    [Fact]
    public async Task StrictMode_ConcurrentRefreshes_OnlyOneSucceeds()
    {
        await using var host = await StartAsync(o => o.RefreshTokenReuseGracePeriod = TimeSpan.Zero);
        using var http = host.CreateClient();
        var rt = (await host.CodeFlowAsync(http)).GetProperty("refresh_token").GetString()!;

        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => RefreshAsync(http, rt)));

        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
    }

    [Fact]
    public async Task ReuseOfIntermediateToken_AfterGracePeriod_RevokesWholeFamily()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var r0 = (await host.CodeFlowAsync(http)).GetProperty("refresh_token").GetString()!;
        var r1 = await NewRefreshTokenAsync(await RefreshAsync(http, r0));
        var r2 = await NewRefreshTokenAsync(await RefreshAsync(http, r1));

        // an independent session of the same user must not be affected
        using var otherDevice = host.CreateClient();
        var other = (await host.CodeFlowAsync(otherDevice)).GetProperty("refresh_token").GetString()!;

        await Task.Delay(TimeSpan.FromSeconds(2.5)); // > grace period (2 s in tests)

        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(http, r1)).StatusCode);   // replay
        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(http, r2)).StatusCode);   // victim's current token revoked
        Assert.Equal(HttpStatusCode.OK, (await RefreshAsync(otherDevice, other)).StatusCode); // other session OK
    }

    [Fact]
    public async Task BlockedUser_CannotRefresh()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);
        var response = await PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "password", ["client_id"] = SpaClientId,
            ["username"] = FakeUserService.UserId, ["password"] = FakeUserService.Password,
            ["scope"] = "openid offline_access",
        });
        var rt = await NewRefreshTokenAsync(response);

        host.BlockUser(FakeUserService.UserId);

        var refresh = await RefreshAsync(http, rt);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
    }

    [Fact]
    public async Task Revocation_RequiresOwningClient()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var rt = (await host.CodeFlowAsync(http)).GetProperty("refresh_token").GetString()!;

        var anonymous = await PostFormAsync(http, "/connect/revocation", new() { ["token"] = rt });
        Assert.Equal("invalid_client", (await ReadJsonAsync(anonymous)).GetProperty("error").GetString());

        var otherClient = await PostFormAsync(http, "/connect/revocation", new() { ["token"] = rt, ["client_id"] = "spa-no-offline" });
        Assert.Equal(HttpStatusCode.OK, otherClient.StatusCode);
        var stillValid = await RefreshAsync(http, rt);
        Assert.Equal(HttpStatusCode.OK, stillValid.StatusCode);
        rt = await NewRefreshTokenAsync(stillValid);

        var owner = await PostFormAsync(http, "/connect/revocation", new() { ["token"] = rt, ["client_id"] = SpaClientId });
        Assert.Equal(HttpStatusCode.OK, owner.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(http, rt)).StatusCode);
    }
}
