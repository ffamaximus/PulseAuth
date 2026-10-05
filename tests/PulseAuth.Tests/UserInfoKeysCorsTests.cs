using System.Net;
using System.Net.Http.Headers;
using PulseAuth.Tests.Infrastructure;
using static PulseAuth.Tests.Infrastructure.PulseAuthTestHost;

namespace PulseAuth.Tests;

public class UserInfoKeysCorsTests
{
    [Fact]
    public async Task UserInfo_AcceptsAccessToken_RejectsIdToken_AndKeepsRealSubject()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var tokens = await host.CodeFlowAsync(http);

        using var api = host.CreateClient(withCookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        var ok = await api.GetAsync("/connect/userinfo");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var json = await ReadJsonAsync(ok);
        Assert.Equal(FakeUserService.UserId, json.GetProperty("sub").GetString());
        Assert.Equal(2, json.GetProperty("role").GetArrayLength());

        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("id_token").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync("/connect/userinfo")).StatusCode);

        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "not.a.jwt");
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync("/connect/userinfo")).StatusCode);
    }

    [Fact]
    public async Task DeveloperKey_IsPersisted_SameKidAfterRestart_NoPrivateParametersInJwks()
    {
        var keyFile = Path.Combine(Path.GetTempPath(), $"pulseauth-test-{Guid.NewGuid():N}.pem");
        try
        {
            string kid;
            await using (var first = await StartAsync(keyFile: keyFile))
            {
                using var http = first.CreateClient(withCookies: false);
                var jwks = await ReadJsonAsync(await http.GetAsync("/.well-known/jwks"));
                var key  = jwks.GetProperty("keys")[0];
                kid = key.GetProperty("kid").GetString()!;
                foreach (var privateParam in new[] { "d", "p", "q", "dp", "dq", "qi" })
                    Assert.False(key.TryGetProperty(privateParam, out _));
            }

            Assert.True(File.Exists(keyFile));

            await using var second = await StartAsync(keyFile: keyFile);
            using var http2 = second.CreateClient(withCookies: false);
            var jwks2 = await ReadJsonAsync(await http2.GetAsync("/.well-known/jwks"));
            Assert.Equal(kid, jwks2.GetProperty("keys")[0].GetProperty("kid").GetString());
        }
        finally
        {
            File.Delete(keyFile);
        }
    }

    [Fact]
    public async Task Cors_AllowedOriginOnly()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);

        var allowed = new HttpRequestMessage(HttpMethod.Options, "/connect/token");
        allowed.Headers.Add("Origin", SpaOrigin);
        allowed.Headers.Add("Access-Control-Request-Method", "POST");
        var preflight = await http.SendAsync(allowed);
        Assert.Equal(HttpStatusCode.NoContent, preflight.StatusCode);
        Assert.Equal(SpaOrigin, preflight.Headers.GetValues("Access-Control-Allow-Origin").Single());

        var denied = new HttpRequestMessage(HttpMethod.Options, "/connect/token");
        denied.Headers.Add("Origin", "https://evil.example");
        denied.Headers.Add("Access-Control-Request-Method", "POST");
        Assert.False((await http.SendAsync(denied)).Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Discovery_IssuerMatchesTokens_AndAdvertisesS256Only()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var discovery = await ReadJsonAsync(await http.GetAsync("/.well-known/openid-configuration"));
        var tokens    = await host.CodeFlowAsync(http);
        var (_, payload) = DecodeJwt(tokens.GetProperty("access_token").GetString()!);

        Assert.Equal(discovery.GetProperty("issuer").GetString(), payload.GetProperty("iss").GetString());
        var methods = discovery.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Equal("S256", Assert.Single(methods));
    }
}
