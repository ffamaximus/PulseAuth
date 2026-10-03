using System.Net;
using System.Net.Http.Headers;
using System.Text;
using PulseAuth.Tests.Infrastructure;
using static PulseAuth.Tests.Infrastructure.PulseAuthTestHost;

namespace PulseAuth.Tests;

public class TokenEndpointTests
{
    [Fact]
    public async Task AuthorizationCode_ConcurrentRedemption_OnlyOneSucceeds()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var verifier  = Base64Url(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorize = await http.GetAsync($"/connect/authorize?client_id={SpaClientId}&response_type=code&redirect_uri={SpaRedirectUri}" +
                                            $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256");
        var code = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(authorize.Headers.Location!.Query)["code"].ToString();

        var attempts = Enumerable.Range(0, 20).Select(_ => PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "authorization_code", ["client_id"] = SpaClientId, ["code"] = code,
            ["code_verifier"] = verifier, ["redirect_uri"] = SpaRedirectUri,
        }));
        var results = await Task.WhenAll(attempts);

        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
    }

    [Fact]
    public async Task ClientCredentials_PublicClient_IsRejected()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);

        var response = await PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = "svc-public", ["scope"] = "api",
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("unauthorized_client", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task ClientCredentials_NoRefreshToken_ClientClaimsIncluded_SubNotOverridable()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ServiceClientId}:{ServiceClientSecret}")));

        var response = await PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "client_credentials", ["scope"] = "api offline_access",
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.False(json.TryGetProperty("refresh_token", out _));
        var (_, payload) = DecodeJwt(json.GetProperty("access_token").GetString()!);
        Assert.Equal(ServiceClientId, payload.GetProperty("sub").GetString());
        Assert.Equal("acme", payload.GetProperty("tenant").GetString());
    }

    [Fact]
    public async Task Password_WithoutAllowOfflineAccess_NoRefreshToken()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);

        var response = await PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "password", ["client_id"] = "spa-no-offline",
            ["username"] = FakeUserService.UserId, ["password"] = FakeUserService.Password,
            ["scope"] = "openid offline_access",
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False((await ReadJsonAsync(response)).TryGetProperty("refresh_token", out _));
    }

    [Fact]
    public async Task MalformedBasicHeader_Returns401NotServerError()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);
        http.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Basic %%%notbase64");

        var response = await PostFormAsync(http, "/connect/token", new() { ["grant_type"] = "client_credentials" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task JsonBody_Returns400NotServerError()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);

        var response = await http.PostAsync("/connect/token",
            new StringContent("{\"grant_type\":\"client_credentials\"}", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task AccessToken_HasAtJwtType_AndExpMatchesExpiresIn_AndUserClaimsCannotOverrideProtocolClaims()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var tokens = await host.CodeFlowAsync(http);

        var (header, payload) = DecodeJwt(tokens.GetProperty("access_token").GetString()!);
        Assert.Equal("at+jwt", header.GetProperty("typ").GetString());
        Assert.Equal(FakeUserService.UserId, payload.GetProperty("sub").GetString());
        Assert.Equal("openid profile offline_access", payload.GetProperty("scope").GetString());
        Assert.Equal(tokens.GetProperty("expires_in").GetInt64(),
                     payload.GetProperty("exp").GetInt64() - payload.GetProperty("iat").GetInt64());
    }
}
