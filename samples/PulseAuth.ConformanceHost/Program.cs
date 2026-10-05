// PulseAuth conformance host
// ──────────────────────────
// Minimal authorization server used to run the OpenID Foundation conformance suite
// ("OpenID Connect Core: Basic Certification Profile") against PulseAuth.
// See README.md in this folder. NOT a production template: fixed test user, auto-login,
// developer signing key.

using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;
using PulseAuth.Builders;
using PulseAuth.ConformanceHost;
using PulseAuth.Constants;
using PulseAuth.Extensions;
using PulseAuth.Helpers;
using PulseAuth.Models;

var builder = WebApplication.CreateBuilder(args);
var conf    = builder.Configuration.GetSection("Conformance");

var issuer        = conf["Issuer"]!.TrimEnd('/');
var suiteBaseUrl  = conf["SuiteBaseUrl"]!.TrimEnd('/');
var alias         = conf["Alias"]!;
var autoLogin     = conf.GetValue("AutoLogin", true);
var callback      = $"{suiteBaseUrl}/test/a/{alias}/callback";

// Behind a tunnel (cloudflared / ngrok) the request arrives over http: trust X-Forwarded-*
// so cookies and redirects use https. Test host only — never clear these lists in production.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownNetworks.Clear();
    o.KnownProxies.Clear();
});

Client ConformanceClient(string id, string secret) => new()
{
    ClientId          = id,
    ClientName        = id,
    ClientSecretHash  = ClientSecretHelper.HashSecret(secret),
    AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
    RedirectUris      = [callback],
    AllowedScopes     = ["openid", "profile", "email", "address", "phone", "offline_access"],
    AllowOfflineAccess = true,
    RequirePkce       = false,   // the Basic OP plan does not send PKCE
};

builder.Services
    .AddPulseAuth(o =>
    {
        o.Issuer          = issuer;
        o.SupportedScopes = ["openid", "profile", "email", "address", "phone", "offline_access"];
        // Unknown scopes are ignored instead of failing the request, as OIDC Core §3.1.2.1 recommends.
        o.IgnoreUnknownScopes = true;
        // profile / email / phone claims only from UserInfo (OIDC Core §5.4), not in the ID token.
        o.IncludeScopeClaimsInIdToken = false;
        // Single-factor login of the test user = ISO/IEC 29115 level "1" (set by the login below).
        o.AcrValuesSupported = ["1"];
        // Basic OP plan: unsigned request objects by value (oidcc-unsigned-request-object-…).
        o.AllowUnsignedRequestObjects = true;
    })
    .AddCookieAuthentication(o =>
    {
        o.LoginPath           = "/Account/Login";
        o.Cookie.Name         = "PulseAuth.Conformance";
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    })
    .AddDeveloperSigningCredential(persistKey: true,
        filename: Path.Combine(builder.Environment.ContentRootPath, "pulseauth-tempkey.pem"))
    .AddUserAuthentication<ConformanceUserService>()
    .AddInMemoryClients(
    [
        ConformanceClient("conformance-client-1", conf["Client1Secret"]!),
        ConformanceClient("conformance-client-2", conf["Client2Secret"]!),
    ]);

var app = builder.Build();

if (issuer.Contains("CHANGE-ME", StringComparison.Ordinal))
    app.Logger.LogWarning("Conformance:Issuer is not configured. Start the tunnel first and pass --Conformance:Issuer=https://<your-tunnel-host>");

app.UseForwardedHeaders();
app.UseAuthentication();
app.MapPulseAuth();

// ── Info page ──────────────────────────────────────────────────────────────
app.MapGet("/", () => Results.Text($"""
    PulseAuth conformance host

    Issuer         : {issuer}
    Discovery      : {issuer}/.well-known/openid-configuration
    Redirect URI   : {callback}
    Clients        : conformance-client-1, conformance-client-2 (client_secret_basic)
    Auto-login     : {autoLogin}

    Sign out (needed before "oidcc-prompt-none-not-logged-in"): {issuer}/Account/Logout
    """));

// ── Login (fixed test user) ───────────────────────────────────────────────
// With AutoLogin the user is signed in immediately, so the suite can run without typing anything.
// prompt=login / max_age still work: every visit here creates a NEW session (new auth_time).
app.MapGet("/Account/Login", async (HttpContext ctx, string? returnUrl, bool? confirm) =>
{
    var target = IsLocalUrl(returnUrl) ? returnUrl! : "/";

    if (!autoLogin && confirm != true)
    {
        var confirmUrl = $"/Account/Login?confirm=true&returnUrl={Uri.EscapeDataString(target)}";
        return Results.Content($"""
            <!doctype html><html><head><meta charset="utf-8"><title>PulseAuth - Login</title></head>
            <body style="font-family:sans-serif;max-width:32rem;margin:4rem auto">
              <h1>PulseAuth conformance login</h1>
              <p>Signs in the fixed test user <code>{ConformanceUserService.SubjectId}</code>.</p>
              <p><a id="login" href="{WebUtility.HtmlEncode(confirmUrl)}">Sign in</a></p>
            </body></html>
            """, "text/html");
    }

    // "acr" = authentication level achieved by this sign-in (single factor = "1").
    var identity = new ClaimsIdentity(
        [new Claim("sub", ConformanceUserService.SubjectId), new Claim("acr", "1")], "conformance");
    await ctx.SignInAsync(new ClaimsPrincipal(identity));
    return Results.Redirect(target);
});

app.MapGet("/Account/Logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync();
    return Results.Text("Signed out.");
});

app.Run();

static bool IsLocalUrl(string? url)
    => !string.IsNullOrEmpty(url) && url[0] == '/' &&
       (url.Length == 1 || (url[1] != '/' && url[1] != '\\'));
