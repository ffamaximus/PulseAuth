using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using PulseAuth.Tests.Infrastructure;
using static PulseAuth.Tests.Infrastructure.PulseAuthTestHost;

namespace PulseAuth.Tests;

/// <summary>
/// Behaviours checked by the OpenID Foundation "Basic OP" conformance plan
/// (oidcc-basic-certification-test-plan). Kept as regression tests so the official
/// suite keeps passing.
/// </summary>
public class OidcConformanceTests
{
    private static (string Verifier, string Challenge) NewPkce()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        return (verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static Dictionary<string, string?> AuthorizeParams(string challenge, string scope = "openid profile offline_access") => new()
    {
        ["client_id"] = SpaClientId, ["response_type"] = "code", ["redirect_uri"] = SpaRedirectUri,
        ["scope"] = scope, ["code_challenge"] = challenge, ["code_challenge_method"] = "S256", ["state"] = "st",
    };

    private static Dictionary<string, string> RedirectQuery(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(SpaRedirectUri + "?", location);
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])
            .ToDictionary(kv => kv.Key, kv => kv.Value.ToString());
    }

    private static Task<HttpResponseMessage> ExchangeAsync(HttpClient http, string code, string verifier)
        => PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "authorization_code", ["client_id"] = SpaClientId, ["code"] = code,
            ["code_verifier"] = verifier, ["redirect_uri"] = SpaRedirectUri,
        });

    // ── Authorization endpoint ───────────────────────────────────────────────

    [Fact]
    public async Task Authorize_Post_IsSupported()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);
        var (verifier, challenge) = NewPkce();

        var response = await http.PostAsync("/connect/authorize",
            new FormUrlEncodedContent(AuthorizeParams(challenge).ToDictionary(kv => kv.Key, kv => kv.Value!)));

        var query = RedirectQuery(response);
        Assert.Equal("st", query["state"]);
        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(http, query["code"], verifier)).StatusCode);
    }

    [Fact]
    public async Task Authorize_MissingResponseType_IsInvalidRequest()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var p = AuthorizeParams(NewPkce().Challenge);
        p.Remove("response_type");
        var query = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", p)));

        Assert.Equal("invalid_request", query["error"]);
        Assert.Equal("st", query["state"]);
    }

    [Theory]
    [InlineData("request", "eyJhbGciOiJub25lIn0.e30.", "request_not_supported")]
    [InlineData("request_uri", "https://rp.example/req.jwt", "request_uri_not_supported")]
    public async Task Authorize_RequestObjects_AreRejectedAsUnsupported(string parameter, string value, string expectedError)
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var p = AuthorizeParams(NewPkce().Challenge);
        p[parameter] = value;
        var query = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", p)));

        Assert.Equal(expectedError, query["error"]);
        Assert.False(query.ContainsKey("code"));
    }

    [Fact]
    public async Task Authorize_OpenIdWithoutRedirectUri_IsRejectedWithoutRedirect()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var p = AuthorizeParams(NewPkce().Challenge);
        p.Remove("redirect_uri");
        var response = await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", p));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task UnknownScopes_RejectedByDefault_IgnoredWhenConfigured_KnownButNotAllowedAlwaysRejected()
    {
        foreach (var ignore in new[] { false, true })
        {
            await using var host = await StartAsync(o => o.IgnoreUnknownScopes = ignore);
            using var http = host.CreateClient();
            await LoginAsync(http);

            var unknown = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize",
                AuthorizeParams(NewPkce().Challenge, scope: "openid profile address"))));
            Assert.Equal(ignore, unknown.ContainsKey("code"));
            if (!ignore)
                Assert.Equal("invalid_scope", unknown["error"]);

            // "email" is a supported scope, but the client is not allowed to request it.
            var notAllowed = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize",
                AuthorizeParams(NewPkce().Challenge, scope: "openid email"))));
            Assert.Equal("invalid_scope", notAllowed["error"]);
        }
    }

    // ── Token endpoint ───────────────────────────────────────────────────────

    [Fact]
    public async Task IdToken_HasAuthTime_AndRefreshKeepsTheOriginalValue()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var tokens   = await host.CodeFlowAsync(http);
        var authTime = DecodeJwt(tokens.GetProperty("id_token").GetString()!).Payload.GetProperty("auth_time").GetInt64();
        Assert.True(authTime >= before - 5 && authTime <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 1);

        await Task.Delay(1100);
        var refreshed = await ReadJsonAsync(await RefreshAsync(http, tokens.GetProperty("refresh_token").GetString()!));
        var refreshedIdToken = DecodeJwt(refreshed.GetProperty("id_token").GetString()!).Payload;
        Assert.Equal(authTime, refreshedIdToken.GetProperty("auth_time").GetInt64());
    }

    [Fact]
    public async Task TokenResponses_AreNotCacheable()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);

        var error = await PostFormAsync(http, "/connect/token", new() { ["grant_type"] = "authorization_code", ["client_id"] = SpaClientId });
        Assert.True(error.Headers.CacheControl?.NoStore == true);
        Assert.Contains("no-cache", error.Headers.Pragma.ToString());
    }

    [Fact]
    public async Task AuthorizationCodeReuse_IsRejected_AndRevokesTheIssuedRefreshToken()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);
        var (verifier, challenge) = NewPkce();

        var code  = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", AuthorizeParams(challenge))))["code"];
        var first = await ReadJsonAsync(await ExchangeAsync(http, code, verifier));
        var refreshToken = first.GetProperty("refresh_token").GetString()!;

        var replay = await ExchangeAsync(http, code, verifier);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal("invalid_grant", (await ReadJsonAsync(replay)).GetProperty("error").GetString());

        // The refresh token obtained with the replayed code no longer works.
        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(http, refreshToken)).StatusCode);
    }

    [Fact]
    public async Task AuthorizationCodeReuse_RevokesRotatedDescendantsToo()
    {
        await using var host = await StartAsync(o => o.RefreshTokenReuseGracePeriod = TimeSpan.Zero);
        using var http = host.CreateClient();
        await LoginAsync(http);
        var (verifier, challenge) = NewPkce();

        var code    = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", AuthorizeParams(challenge))))["code"];
        var first   = await ReadJsonAsync(await ExchangeAsync(http, code, verifier));
        var rotated = await ReadJsonAsync(await RefreshAsync(http, first.GetProperty("refresh_token").GetString()!));

        await ExchangeAsync(http, code, verifier);   // replay

        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(http, rotated.GetProperty("refresh_token").GetString()!)).StatusCode);
    }

    // ── UserInfo endpoint ────────────────────────────────────────────────────

    [Fact]
    public async Task UserInfo_SupportsPostWithHeaderAndFormBody()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var accessToken = (await host.CodeFlowAsync(http)).GetProperty("access_token").GetString()!;

        using var anonymous = host.CreateClient(withCookies: false);

        var viaBody = await PostFormAsync(anonymous, "/connect/userinfo", new() { ["access_token"] = accessToken });
        Assert.Equal(HttpStatusCode.OK, viaBody.StatusCode);
        Assert.Equal(FakeUserService.UserId, (await ReadJsonAsync(viaBody)).GetProperty("sub").GetString());

        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        Assert.Equal(HttpStatusCode.OK, (await anonymous.SendAsync(request)).StatusCode);

        // Both methods at once is a malformed request (RFC 6750 §2).
        var both = new HttpRequestMessage(HttpMethod.Post, "/connect/userinfo")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["access_token"] = accessToken }),
        };
        both.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        Assert.Equal(HttpStatusCode.BadRequest, (await anonymous.SendAsync(both)).StatusCode);
    }

    [Fact]
    public async Task UserInfo_Errors_CarryABearerChallenge()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);

        var missing = await http.GetAsync("/connect/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal("Bearer", missing.Headers.WwwAuthenticate.ToString());

        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-token");
        var invalid = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
        Assert.Contains("error=\"invalid_token\"", invalid.Headers.WwwAuthenticate.ToString());
    }

    // ── Discovery ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Discovery_DeclaresUnsupportedRequestFeatures()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient(withCookies: false);

        var doc = await ReadJsonAsync(await http.GetAsync("/.well-known/openid-configuration"));

        Assert.False(doc.GetProperty("request_parameter_supported").GetBoolean());
        Assert.False(doc.GetProperty("request_uri_parameter_supported").GetBoolean());   // defaults to true if omitted
        Assert.False(doc.GetProperty("claims_parameter_supported").GetBoolean());
        Assert.Equal("query", doc.GetProperty("response_modes_supported")[0].GetString());
        Assert.Contains("auth_time", doc.GetProperty("claims_supported").EnumerateArray().Select(e => e.GetString()));
    }
}
