using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PulseAuth.Configuration;
using PulseAuth.Constants;
using PulseAuth.Extensions;
using PulseAuth.Helpers;
using PulseAuth.Models;

namespace PulseAuth.Tests.Infrastructure;

/// <summary>
/// Starts a real PulseAuth server on a random local port (no extra test packages required).
/// </summary>
public sealed class PulseAuthTestHost : IAsyncDisposable
{
    public const string SpaClientId    = "spa";
    public const string SpaRedirectUri = "https://app.example/cb";
    public const string SpaLogoutUri   = "https://app.example/bye?x=1";
    public const string SpaOrigin      = "https://app.example";
    public const string ServiceClientId     = "svc";
    public const string ServiceClientSecret = "s3cret";
    public const string ConsentClientId     = "consent-app";
    public const string ConsentRedirectUri  = "https://consent.example/cb";
    public const string ReferenceClientId     = "ref-app";
    public const string ReferenceClientSecret = "ref-secret";
    public const string ReferenceCodeClientId    = "ref-spa";
    public const string ReferenceCodeRedirectUri = "https://ref-spa.example/cb";
    public const string ApiClientId     = "orders-api";
    public const string ApiClientSecret = "api-secret";

    private readonly WebApplication _app;

    public Uri BaseAddress { get; }

    private PulseAuthTestHost(WebApplication app, Uri baseAddress)
    {
        _app        = app;
        BaseAddress = baseAddress;
    }

    public static async Task<PulseAuthTestHost> StartAsync(
        Action<PulseAuthOptions>? configure = null,
        string? keyFile = null)
    {
        var port    = GetFreePort();
        var issuer  = $"http://127.0.0.1:{port}";
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls(issuer);

        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
        builder.Services.AddSingleton<BlockedUsers>();
        builder.Services.AddSingleton<SecurityStamps>();

        builder.Services
            .AddPulseAuth(o =>
            {
                o.Issuer = issuer;
                o.RefreshTokenReuseGracePeriod = TimeSpan.FromSeconds(2);
                o.EnableTokenCleanup = false;
                configure?.Invoke(o);
            })
            .AddDeveloperSigningCredential(persistKey: keyFile is not null, filename: keyFile)
            .AddUserAuthentication<FakeUserService>()
            .AddInMemoryClients(
            [
                new Client
                {
                    ClientId = SpaClientId, ClientName = SpaClientId,
                    AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken, GrantTypes.Password],
                    RedirectUris = [SpaRedirectUri],
                    PostLogoutRedirectUris = [SpaLogoutUri],
                    AllowedScopes = ["openid", "profile", "address", "offline_access"],
                    AllowOfflineAccess = true,
                    AllowedCorsOrigins = [SpaOrigin],
                },
                new Client
                {
                    ClientId = "spa-no-offline", ClientName = "spa-no-offline",
                    AllowedGrantTypes = [GrantTypes.Password, GrantTypes.RefreshToken],
                    AllowedScopes = ["openid", "offline_access"],
                    AllowOfflineAccess = false,
                },
                new Client
                {
                    ClientId = ServiceClientId, ClientName = ServiceClientId,
                    ClientSecretHash = ClientSecretHelper.HashSecret(ServiceClientSecret),
                    AllowedGrantTypes = [GrantTypes.ClientCredentials],
                    AllowedScopes = ["api", "offline_access"], AllowOfflineAccess = true,
                    Claims = new Dictionary<string, string> { ["tenant"] = "acme", ["sub"] = "evil" },
                },
                new Client
                {
                    ClientId = "svc-public", ClientName = "svc-public",
                    AllowedGrantTypes = [GrantTypes.ClientCredentials], AllowedScopes = ["api"],
                },
                new Client
                {
                    ClientId = ConsentClientId, ClientName = "Third-party app",
                    AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
                    RedirectUris = [ConsentRedirectUri],
                    AllowedScopes = ["openid", "profile", "offline_access"],
                    AllowOfflineAccess = true,
                    RequireConsent = true,
                },
                new Client
                {
                    ClientId = ReferenceClientId, ClientName = ReferenceClientId,
                    ClientSecretHash = ClientSecretHelper.HashSecret(ReferenceClientSecret),
                    AllowedGrantTypes = [GrantTypes.Password, GrantTypes.RefreshToken],
                    AllowedScopes = ["openid", "profile", "offline_access", "api"],
                    AllowOfflineAccess = true,
                    AccessTokenType = AccessTokenType.Reference,
                },
                new Client
                {
                    ClientId = ReferenceCodeClientId, ClientName = ReferenceCodeClientId,
                    AllowedGrantTypes = [GrantTypes.AuthorizationCode],
                    RedirectUris = [ReferenceCodeRedirectUri],
                    AllowedScopes = ["openid", "profile"],
                    AccessTokenType = AccessTokenType.Reference,
                },
                new Client
                {
                    ClientId = ApiClientId, ClientName = ApiClientId,
                    ClientSecretHash = ClientSecretHelper.HashSecret(ApiClientSecret),
                    AllowIntrospection = true,
                },
            ]);

        var app = builder.Build();
        app.UseAuthentication();
        app.MapGet("/test-login", async (HttpContext ctx, string sub) =>
        {
            await ctx.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", sub)], "test")));
            return Results.Ok();
        });
        // Minimal consent page API for tests (a real app renders a page + antiforgery)
        app.MapGet("/Consent", async (string returnUrl, PulseAuth.Services.IConsentInteractionService consent) =>
        {
            var request = await consent.GetConsentRequestAsync(returnUrl);
            return request is null ? Results.BadRequest() : Results.Ok(new { client = request.Client.ClientId, scopes = request.RequestedScopes });
        });
        app.MapPost("/Consent/grant", async (HttpContext ctx, string returnUrl, string? scopes, bool remember,
            PulseAuth.Services.IConsentInteractionService consent) =>
        {
            var user = (await ctx.AuthenticateAsync()).Principal!;
            var granted = scopes?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return Results.Ok(new { redirect = await consent.GrantConsentAsync(returnUrl, user, granted, remember) });
        });
        app.MapPost("/Consent/deny", async (string returnUrl, PulseAuth.Services.IConsentInteractionService consent)
            => Results.Ok(new { redirect = await consent.DenyConsentAsync(returnUrl) }));
        app.MapPost("/Consent/revoke", async (string clientId, PulseAuth.Services.IConsentInteractionService consent) =>
        {
            await consent.RevokeConsentAsync(FakeUserService.UserId, clientId);
            return Results.Ok();
        });
        app.MapPulseAuth();

        await app.StartAsync();
        return new PulseAuthTestHost(app, new Uri(issuer));
    }

    public string Issuer => BaseAddress.ToString().TrimEnd('/');

    /// <summary>Simulates a password change ("sign out everywhere").</summary>
    public void ChangeSecurityStamp(string subjectId) => _app.Services.GetRequiredService<SecurityStamps>().Change(subjectId);

    /// <summary>Marks a user as no longer active (deleted / locked out).</summary>
    public void BlockUser(string subjectId) => _app.Services.GetRequiredService<BlockedUsers>().Block(subjectId);

    public HttpClient CreateClient(bool withCookies = true)
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = withCookies };
        if (withCookies)
            handler.CookieContainer = new CookieContainer();
        return new HttpClient(handler) { BaseAddress = BaseAddress };
    }

    /// <summary>Signs "alice" in (cookie) on the given client.</summary>
    public static async Task LoginAsync(HttpClient http)
        => (await http.GetAsync($"/test-login?sub={FakeUserService.UserId}")).EnsureSuccessStatusCode();

    /// <summary>Runs the authorization code + PKCE flow and returns the token response.</summary>
    public async Task<JsonElement> CodeFlowAsync(HttpClient http, string scope = "openid profile offline_access")
    {
        await LoginAsync(http);
        var verifier  = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        var authorize = await http.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = SpaClientId, ["response_type"] = "code", ["redirect_uri"] = SpaRedirectUri,
            ["scope"] = scope, ["code_challenge"] = challenge, ["code_challenge_method"] = "S256",
        }));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var code = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query)["code"].ToString();

        var token = await PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "authorization_code", ["client_id"] = SpaClientId, ["code"] = code,
            ["code_verifier"] = verifier, ["redirect_uri"] = SpaRedirectUri,
        });
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        return await ReadJsonAsync(token);
    }

    public static Task<HttpResponseMessage> PostFormAsync(HttpClient http, string path, Dictionary<string, string> form)
        => http.PostAsync(path, new FormUrlEncodedContent(form));

    public static Task<HttpResponseMessage> RefreshAsync(HttpClient http, string refreshToken, string clientId = SpaClientId)
        => PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "refresh_token", ["client_id"] = clientId, ["refresh_token"] = refreshToken,
        });

    public static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
        => JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();

    /// <summary>Decodes a JWT without validating it: (header, payload).</summary>
    public static (JsonElement Header, JsonElement Payload) DecodeJwt(string jwt)
    {
        var parts = jwt.Split('.');
        static JsonElement Part(string p) =>
            JsonDocument.Parse(WebEncoders.Base64UrlDecode(p)).RootElement.Clone();
        return (Part(parts[0]), Part(parts[1]));
    }

    public static string Base64Url(byte[] bytes) => WebEncoders.Base64UrlEncode(bytes);

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    private static int GetFreePort()
    {
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
