using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using PulseAuth.Tests.Infrastructure;
using static PulseAuth.Tests.Infrastructure.PulseAuthTestHost;

namespace PulseAuth.Tests;

public class ReferenceTokenAndIntrospectionTests
{
    private static async Task<JsonElement> PasswordGrantAsync(HttpClient http, string clientId, string? secret, string scope)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "password", ["client_id"] = clientId,
            ["username"] = FakeUserService.UserId, ["password"] = FakeUserService.Password, ["scope"] = scope,
        };
        if (secret is not null) form["client_secret"] = secret;
        var response = await PostFormAsync(http, "/connect/token", form);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadJsonAsync(response);
    }

    private static async Task<JsonElement> IntrospectAsync(HttpClient http, string token, string clientId, string secret, string? hint = null)
    {
        var form = new Dictionary<string, string> { ["token"] = token, ["client_id"] = clientId, ["client_secret"] = secret };
        if (hint is not null) form["token_type_hint"] = hint;
        var response = await PostFormAsync(http, "/connect/introspect", form);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadJsonAsync(response);
    }

    [Fact]
    public async Task ReferenceToken_IsOpaque_WorksWithUserInfo_AndIntrospection()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);
        var tokens = await PasswordGrantAsync(http, ReferenceClientId, ReferenceClientSecret, "openid profile api");
        var handle = tokens.GetProperty("access_token").GetString()!;

        Assert.DoesNotContain(".", handle); // not a JWT

        using var api = host.CreateClient(withCookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", handle);
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync("/connect/userinfo")).StatusCode);

        var result = await IntrospectAsync(http, handle, ApiClientId, ApiClientSecret);
        Assert.True(result.GetProperty("active").GetBoolean());
        Assert.Equal(FakeUserService.UserId, result.GetProperty("sub").GetString());
        Assert.Equal(ReferenceClientId, result.GetProperty("client_id").GetString());
        Assert.Equal("openid profile api", result.GetProperty("scope").GetString());
        Assert.Equal("access_token", result.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task ReferenceToken_CanBeRevoked()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);
        var handle = (await PasswordGrantAsync(http, ReferenceClientId, ReferenceClientSecret, "api")).GetProperty("access_token").GetString()!;

        var revoke = await PostFormAsync(http, "/connect/revocation", new()
        {
            ["token"] = handle, ["client_id"] = ReferenceClientId, ["client_secret"] = ReferenceClientSecret,
        });
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);

        Assert.False((await IntrospectAsync(http, handle, ApiClientId, ApiClientSecret)).GetProperty("active").GetBoolean());
        using var api = host.CreateClient(withCookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", handle);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync("/connect/userinfo")).StatusCode);
    }

    [Fact]
    public async Task Introspection_JwtAccessToken_And_CallerRules()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var jwt = (await host.CodeFlowAsync(http)).GetProperty("access_token").GetString()!;

        // API with AllowIntrospection sees tokens of any client
        Assert.True((await IntrospectAsync(http, jwt, ApiClientId, ApiClientSecret)).GetProperty("active").GetBoolean());

        // a confidential client WITHOUT AllowIntrospection cannot see other clients' tokens
        Assert.False((await IntrospectAsync(http, jwt, ReferenceClientId, ReferenceClientSecret)).GetProperty("active").GetBoolean());

        // garbage
        Assert.False((await IntrospectAsync(http, "not-a-token", ApiClientId, ApiClientSecret)).GetProperty("active").GetBoolean());

        // unauthenticated / public callers are rejected
        var anonymous = await PostFormAsync(http, "/connect/introspect", new() { ["token"] = jwt });
        Assert.Equal("invalid_client", (await ReadJsonAsync(anonymous)).GetProperty("error").GetString());
        var publicClient = await PostFormAsync(http, "/connect/introspect", new() { ["token"] = jwt, ["client_id"] = SpaClientId });
        Assert.Equal("invalid_client", (await ReadJsonAsync(publicClient)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Introspection_RefreshToken_OnlyForOwningClient()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);
        var rt = (await PasswordGrantAsync(http, ReferenceClientId, ReferenceClientSecret, "offline_access")).GetProperty("refresh_token").GetString()!;

        var own = await IntrospectAsync(http, rt, ReferenceClientId, ReferenceClientSecret, hint: "refresh_token");
        Assert.True(own.GetProperty("active").GetBoolean());
        Assert.Equal("refresh_token", own.GetProperty("token_type").GetString());

        Assert.False((await IntrospectAsync(http, rt, ApiClientId, ApiClientSecret, hint: "refresh_token")).GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task SecurityStampChange_InvalidatesRefreshAndReferenceTokens()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);
        var tokens = await PasswordGrantAsync(http, ReferenceClientId, ReferenceClientSecret, "api offline_access");
        var handle = tokens.GetProperty("access_token").GetString()!;
        var rt     = tokens.GetProperty("refresh_token").GetString()!;

        host.ChangeSecurityStamp(FakeUserService.UserId); // e.g. password changed

        var refresh = await PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "refresh_token", ["refresh_token"] = rt,
            ["client_id"] = ReferenceClientId, ["client_secret"] = ReferenceClientSecret,
        });
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
        Assert.False((await IntrospectAsync(http, handle, ApiClientId, ApiClientSecret)).GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task SecurityStampUnchanged_RefreshWorks()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);
        var rt = (await PasswordGrantAsync(http, ReferenceClientId, ReferenceClientSecret, "offline_access")).GetProperty("refresh_token").GetString()!;

        var refresh = await PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "refresh_token", ["refresh_token"] = rt,
            ["client_id"] = ReferenceClientId, ["client_secret"] = ReferenceClientSecret,
        });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }

    [Fact]
    public async Task Discovery_AdvertisesIntrospectionAndPrompt()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);
        var discovery = await ReadJsonAsync(await http.GetAsync("/.well-known/openid-configuration"));

        Assert.EndsWith("/connect/introspect", discovery.GetProperty("introspection_endpoint").GetString());
        Assert.Contains("consent", discovery.GetProperty("prompt_values_supported").EnumerateArray().Select(e => e.GetString()));
    }
}
