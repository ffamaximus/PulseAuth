using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
                AuthorizeParams(NewPkce().Challenge, scope: "openid profile unknown_scope"))));
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
    public async Task AuthorizationCodeReuse_IsRejected_AndRevokesTheIssuedTokens()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);
        var (verifier, challenge) = NewPkce();

        var code  = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", AuthorizeParams(challenge))))["code"];
        var first = await ReadJsonAsync(await ExchangeAsync(http, code, verifier));
        var refreshToken = first.GetProperty("refresh_token").GetString()!;
        var accessToken  = first.GetProperty("access_token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await UserInfoStatusAsync(http, accessToken)));

        var replay = await ExchangeAsync(http, code, verifier);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal("invalid_grant", (await ReadJsonAsync(replay)).GetProperty("error").GetString());

        // The refresh token and the (JWT) access token obtained with the replayed code no longer work.
        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(http, refreshToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoStatusAsync(http, accessToken)));
    }

    private static async Task<HttpStatusCode> UserInfoStatusAsync(HttpClient http, string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return (await http.SendAsync(request)).StatusCode;
    }

    [Fact]
    public async Task JwtAccessToken_CanBeRevoked_OnlyByItsClient()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var accessToken = (await host.CodeFlowAsync(http)).GetProperty("access_token").GetString()!;

        // Another client cannot revoke it (still 200, RFC 7009 §2.2, but the token keeps working)
        Assert.Equal(HttpStatusCode.OK, (await PostFormAsync(http, "/connect/revocation",
            new() { ["token"] = accessToken, ["client_id"] = ConsentClientId })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, await UserInfoStatusAsync(http, accessToken));

        Assert.Equal(HttpStatusCode.OK, (await PostFormAsync(http, "/connect/revocation",
            new() { ["token"] = accessToken, ["client_id"] = SpaClientId, ["token_type_hint"] = "access_token" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await UserInfoStatusAsync(http, accessToken));

        var introspection = await ReadJsonAsync(await PostFormAsync(http, "/connect/introspect", new()
        {
            ["token"] = accessToken, ["client_id"] = ApiClientId, ["client_secret"] = ApiClientSecret,
        }));
        Assert.False(introspection.GetProperty("active").GetBoolean());
    }

    // ── Request objects ──────────────────────────────────────────────────────

    private static string UnsignedRequestObject(object payload, string alg = "none")
        => Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { alg })))
           + "." + Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload))) + ".";

    [Fact]
    public async Task UnsignedRequestObject_WhenEnabled_ParametersSupersedeTheQuery()
    {
        await using var host = await StartAsync(o => o.AllowUnsignedRequestObjects = true);
        using var http = host.CreateClient();
        await LoginAsync(http);
        var (verifier, challenge) = NewPkce();

        var doc = await ReadJsonAsync(await http.GetAsync("/.well-known/openid-configuration"));
        Assert.True(doc.GetProperty("request_parameter_supported").GetBoolean());
        Assert.Equal("none", doc.GetProperty("request_object_signing_alg_values_supported")[0].GetString());

        // redirect_uri, state, nonce and PKCE only in the request object; the query redirect_uri is ignored.
        var p = new Dictionary<string, string?>
        {
            ["client_id"] = SpaClientId, ["response_type"] = "code", ["scope"] = "openid",
            ["redirect_uri"] = "https://evil.example/cb",
            ["request"] = UnsignedRequestObject(new
            {
                client_id = SpaClientId, response_type = "code", scope = "openid profile",
                redirect_uri = SpaRedirectUri, state = "from-object", nonce = "n-object",
                code_challenge = challenge, code_challenge_method = "S256", max_age = 3600,
            }),
        };
        var query = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", p)));
        Assert.Equal("from-object", query["state"]);

        var tokens  = await ReadJsonAsync(await ExchangeAsync(http, query["code"], verifier));
        var idToken = DecodeJwt(tokens.GetProperty("id_token").GetString()!).Payload;
        Assert.Equal("n-object", idToken.GetProperty("nonce").GetString());
        Assert.Contains("profile", tokens.GetProperty("scope").GetString());
    }

    [Theory]
    [InlineData("RS256", "spa")]          // signed objects are not supported
    [InlineData("none", "consent-app")]   // client_id must match the query
    public async Task UnsignedRequestObject_Invalid_IsInvalidRequestObject(string alg, string objectClientId)
    {
        await using var host = await StartAsync(o => o.AllowUnsignedRequestObjects = true);
        using var http = host.CreateClient();
        await LoginAsync(http);

        var p = AuthorizeParams(NewPkce().Challenge);
        p["request"] = UnsignedRequestObject(new { client_id = objectClientId, response_type = "code" }, alg);
        var query = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", p)));
        Assert.Equal("invalid_request_object", query["error"]);
        Assert.False(query.ContainsKey("code"));
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

    [Fact]
    public async Task AuthorizationCodeReuse_RevokesReferenceAccessTokens()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);
        var (verifier, challenge) = NewPkce();

        var p = AuthorizeParams(challenge, scope: "openid profile");
        p["client_id"] = ReferenceCodeClientId;
        p["redirect_uri"] = ReferenceCodeRedirectUri;
        var location = (await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", p))).Headers.Location!.ToString();
        var code = QueryHelpers.ParseQuery(location[location.IndexOf('?')..])["code"].ToString();

        Task<HttpResponseMessage> Exchange() => PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "authorization_code", ["client_id"] = ReferenceCodeClientId, ["code"] = code,
            ["code_verifier"] = verifier, ["redirect_uri"] = ReferenceCodeRedirectUri,
        });

        var handle = (await ReadJsonAsync(await Exchange())).GetProperty("access_token").GetString()!;
        Assert.DoesNotContain(".", handle);   // opaque reference token

        HttpRequestMessage UserInfo()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", handle);
            return request;
        }

        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync(UserInfo())).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Exchange()).StatusCode);              // replay
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(UserInfo())).StatusCode);
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

    [Fact]
    public async Task UserInfo_ProfileScope_ReturnsStandardProfileClaims_UpdatedAtAsNumber()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var accessToken = (await host.CodeFlowAsync(http, scope: "openid profile")).GetProperty("access_token").GetString()!;

        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var info = await ReadJsonAsync(await http.SendAsync(request));

        Assert.Equal("es-CO", info.GetProperty("locale").GetString());
        Assert.Equal("America/Bogota", info.GetProperty("zoneinfo").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Number, info.GetProperty("updated_at").ValueKind);
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds(), info.GetProperty("updated_at").GetInt64());
        Assert.False(info.TryGetProperty("nickname", out _));   // unset claims are omitted
    }

    [Fact]
    public async Task IdToken_ScopeClaims_CanBeLimitedToUserInfo()
    {
        foreach (var include in new[] { true, false })
        {
            await using var host = await StartAsync(o => o.IncludeScopeClaimsInIdToken = include);
            using var http = host.CreateClient();
            var tokens  = await host.CodeFlowAsync(http, scope: "openid profile");
            var idToken = DecodeJwt(tokens.GetProperty("id_token").GetString()!).Payload;

            Assert.Equal(include, idToken.TryGetProperty("name", out _));
            Assert.True(idToken.TryGetProperty("role", out _));        // application claims always included

            var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString()!);
            Assert.Equal("Alice", (await ReadJsonAsync(await http.SendAsync(request))).GetProperty("name").GetString());
        }
    }

    [Fact]
    public async Task Acr_FromDefaultAcr_InIdToken_AndPublishedInDiscovery()
    {
        await using (var plain = await StartAsync())
        {
            using var http = plain.CreateClient();
            var idToken = DecodeJwt((await plain.CodeFlowAsync(http)).GetProperty("id_token").GetString()!).Payload;
            Assert.False(idToken.TryGetProperty("acr", out _));
            Assert.False((await ReadJsonAsync(await http.GetAsync("/.well-known/openid-configuration")))
                .TryGetProperty("acr_values_supported", out _));
        }

        await using var host = await StartAsync(o => { o.AcrValuesSupported = ["1", "2"]; o.DefaultAcr = "1"; });
        using var client = host.CreateClient();
        var token = DecodeJwt((await host.CodeFlowAsync(client)).GetProperty("id_token").GetString()!).Payload;
        Assert.Equal("1", token.GetProperty("acr").GetString());

        var doc = await ReadJsonAsync(await client.GetAsync("/.well-known/openid-configuration"));
        Assert.Equal(["1", "2"], doc.GetProperty("acr_values_supported").EnumerateArray().Select(e => e.GetString()).ToArray());
    }

    [Fact]
    public async Task AddressScope_ReturnsAddressObject_InUserInfo_AndIdTokenWhenConfigured()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var tokens = await host.CodeFlowAsync(http, scope: "openid address");

        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString()!);
        var address = (await ReadJsonAsync(await http.SendAsync(request))).GetProperty("address");
        Assert.Equal(System.Text.Json.JsonValueKind.Object, address.ValueKind);
        Assert.Equal("Bogotá", address.GetProperty("locality").GetString());
        Assert.Equal("CO", address.GetProperty("country").GetString());
        Assert.False(address.TryGetProperty("postal_code", out _));   // unset members are omitted

        // IncludeScopeClaimsInIdToken (default true): also in the ID token, as a JSON object
        var idAddress = DecodeJwt(tokens.GetProperty("id_token").GetString()!).Payload.GetProperty("address");
        Assert.Equal(System.Text.Json.JsonValueKind.Object, idAddress.ValueKind);
        Assert.Equal("CO", idAddress.GetProperty("country").GetString());

        // without the scope, no address
        using var other = host.CreateClient();
        var plain = await host.CodeFlowAsync(other, scope: "openid profile");
        var request2 = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request2.Headers.Authorization = new AuthenticationHeaderValue("Bearer", plain.GetProperty("access_token").GetString()!);
        Assert.False((await ReadJsonAsync(await other.SendAsync(request2))).TryGetProperty("address", out _));
    }

    private static async Task<JsonElement> UserInfoAsync(HttpClient http, string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadJsonAsync(response);
    }

    [Fact]
    public async Task ClaimsParameter_ReleasesRequestedClaims_OnlyForAllowedScopes_AndSurvivesRefresh()
    {
        await using var host = await StartAsync(o => o.IncludeScopeClaimsInIdToken = false);
        using var http = host.CreateClient();
        await LoginAsync(http);
        var (verifier, challenge) = NewPkce();

        // scope = openid only; "name" (profile) and "address" are allowed for the client, "email" is not.
        var p = AuthorizeParams(challenge, scope: "openid offline_access");
        p["claims"] = """{"userinfo":{"name":{"essential":true},"email":null},"id_token":{"address":null,"locale":null}}""";
        var code = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", p)))["code"];
        var tokens = await ReadJsonAsync(await ExchangeAsync(http, code, verifier));

        var info = await UserInfoAsync(http, tokens.GetProperty("access_token").GetString()!);
        Assert.Equal("Alice", info.GetProperty("name").GetString());
        Assert.False(info.TryGetProperty("email", out _));          // client may not use the email scope
        Assert.False(info.TryGetProperty("locale", out _));         // only requested for the ID token

        var idToken = DecodeJwt(tokens.GetProperty("id_token").GetString()!).Payload;
        Assert.Equal("CO", idToken.GetProperty("address").GetProperty("country").GetString());
        Assert.Equal("es-CO", idToken.GetProperty("locale").GetString());
        Assert.False(idToken.TryGetProperty("name", out _));

        // After a refresh the request still applies
        var refreshed = await ReadJsonAsync(await RefreshAsync(http, tokens.GetProperty("refresh_token").GetString()!));
        Assert.Equal("Alice", (await UserInfoAsync(http, refreshed.GetProperty("access_token").GetString()!)).GetProperty("name").GetString());
        Assert.Equal("es-CO", DecodeJwt(refreshed.GetProperty("id_token").GetString()!).Payload.GetProperty("locale").GetString());
    }

    [Fact]
    public async Task ClaimsParameter_InvalidJson_IsInvalidRequest()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var p = AuthorizeParams(NewPkce().Challenge);
        p["claims"] = "[not json";
        var query = RedirectQuery(await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", p)));
        Assert.Equal("invalid_request", query["error"]);
    }

    [Fact]
    public async Task UserClaims_CannotForgeTheUserInfoClaimsList()
    {
        // "userinfo_claims" is reserved: a user/admin-editable claim can never extend what UserInfo releases.
        Assert.Contains(PulseAuth.Services.DefaultTokenService.UserInfoClaimsClaimType,
                        PulseAuth.Services.DefaultTokenService.ReservedClaimTypes);
        await Task.CompletedTask;
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
        Assert.True(doc.GetProperty("claims_parameter_supported").GetBoolean());
        Assert.Equal("query", doc.GetProperty("response_modes_supported")[0].GetString());
        Assert.Contains("auth_time", doc.GetProperty("claims_supported").EnumerateArray().Select(e => e.GetString()));
    }
}
