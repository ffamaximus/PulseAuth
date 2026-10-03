using System.Net;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using PulseAuth.Tests.Infrastructure;
using static PulseAuth.Tests.Infrastructure.PulseAuthTestHost;

namespace PulseAuth.Tests;

public class ConsentAndPromptTests
{
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static string AuthorizeUrl(string clientId, string redirectUri, string scope = "openid profile", string? extra = null)
        => $"/connect/authorize?client_id={clientId}&response_type=code&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
           $"&scope={Uri.EscapeDataString(scope)}&code_challenge={Challenge}&code_challenge_method=S256&state=st{extra}";

    private static string ConsentAuthorize(string scope = "openid profile", string? extra = null)
        => AuthorizeUrl(ConsentClientId, ConsentRedirectUri, scope, extra);

    private static string ReturnUrlOf(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.ToString();   // relative URL
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])["returnUrl"].ToString();
    }

    private static async Task<string> GrantAsync(HttpClient http, string returnUrl, string? scopes = null, bool remember = true)
    {
        var url = $"/Consent/grant?returnUrl={Uri.EscapeDataString(returnUrl)}&remember={remember}" +
                  (scopes is null ? "" : $"&scopes={Uri.EscapeDataString(scopes)}");
        var response = await http.PostAsync(url, null);
        response.EnsureSuccessStatusCode();
        return (await ReadJsonAsync(response)).GetProperty("redirect").GetString()!;
    }

    [Fact]
    public async Task RequireConsent_RedirectsToConsentPage_ThenRemembersConsent()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var first = await http.GetAsync(ConsentAuthorize());
        Assert.StartsWith("/Consent?returnUrl=", first.Headers.Location!.ToString());

        var returnUrl = ReturnUrlOf(first);
        var info = await ReadJsonAsync(await http.GetAsync($"/Consent?returnUrl={Uri.EscapeDataString(returnUrl)}"));
        Assert.Equal(ConsentClientId, info.GetProperty("client").GetString());
        Assert.Equal(2, info.GetProperty("scopes").GetArrayLength());

        var continueUrl = await GrantAsync(http, returnUrl);
        var afterConsent = await http.GetAsync(continueUrl);
        Assert.StartsWith(ConsentRedirectUri + "?code=", afterConsent.Headers.Location!.ToString());

        // remembered: no consent page the next time
        var second = await http.GetAsync(ConsentAuthorize());
        Assert.StartsWith(ConsentRedirectUri + "?code=", second.Headers.Location!.ToString());

        // prompt=consent forces the page again
        var forced = await http.GetAsync(ConsentAuthorize(extra: "&prompt=consent"));
        Assert.StartsWith("/Consent?returnUrl=", forced.Headers.Location!.ToString());
        Assert.DoesNotContain("prompt", ReturnUrlOf(forced));
    }

    [Fact]
    public async Task Deny_ReturnsAccessDeniedToTheClient()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var returnUrl = ReturnUrlOf(await http.GetAsync(ConsentAuthorize()));
        var response  = await http.PostAsync($"/Consent/deny?returnUrl={Uri.EscapeDataString(returnUrl)}", null);
        var redirect  = (await ReadJsonAsync(response)).GetProperty("redirect").GetString()!;

        Assert.StartsWith(ConsentRedirectUri + "?", redirect);
        var query = QueryHelpers.ParseQuery(new Uri(redirect).Query);
        Assert.Equal("access_denied", query["error"].ToString());
        Assert.Equal("st", query["state"].ToString());
    }

    [Fact]
    public async Task GrantingASubset_IssuesOnlyTheGrantedScopes()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var returnUrl   = ReturnUrlOf(await http.GetAsync(ConsentAuthorize("openid profile offline_access")));
        var continueUrl = await GrantAsync(http, returnUrl, scopes: "offline_access"); // openid is always kept
        var redirect    = await http.GetAsync(continueUrl);
        var code        = QueryHelpers.ParseQuery(new Uri(redirect.Headers.Location!.ToString()).Query)["code"].ToString();

        // Exchange the code (PKCE verifier for the fixed test challenge is "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        var token = await PostFormAsync(http, "/connect/token", new()
        {
            ["grant_type"] = "authorization_code", ["client_id"] = ConsentClientId, ["code"] = code,
            ["code_verifier"] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", ["redirect_uri"] = ConsentRedirectUri,
        });
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        Assert.Equal("openid offline_access", (await ReadJsonAsync(token)).GetProperty("scope").GetString());
    }

    [Fact]
    public async Task OneTimeConsent_IsUsedOnlyOnce()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var continueUrl = await GrantAsync(http, ReturnUrlOf(await http.GetAsync(ConsentAuthorize())), remember: false);
        Assert.StartsWith(ConsentRedirectUri + "?code=", (await http.GetAsync(continueUrl)).Headers.Location!.ToString());

        Assert.StartsWith("/Consent?returnUrl=", (await http.GetAsync(ConsentAuthorize())).Headers.Location!.ToString());
    }

    [Fact]
    public async Task RevokeConsent_AsksAgain()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);
        await http.GetAsync(await GrantAsync(http, ReturnUrlOf(await http.GetAsync(ConsentAuthorize()))));

        await http.PostAsync($"/Consent/revoke?clientId={ConsentClientId}", null);

        Assert.StartsWith("/Consent?returnUrl=", (await http.GetAsync(ConsentAuthorize())).Headers.Location!.ToString());
    }

    [Fact]
    public async Task ConsentApi_RejectsForeignReturnUrls()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();

        foreach (var bad in new[] { "https://evil.com/connect/authorize?client_id=spa", "//evil.com/connect/authorize", "/somewhere/else?client_id=spa" })
            Assert.Equal(HttpStatusCode.BadRequest, (await http.GetAsync($"/Consent?returnUrl={Uri.EscapeDataString(bad)}")).StatusCode);
    }

    [Fact]
    public async Task PromptNone_WithoutConsent_ReturnsConsentRequired()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var response = await http.GetAsync(ConsentAuthorize(extra: "&prompt=none"));
        Assert.Contains("error=consent_required", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task PromptNone_NotSignedIn_ReturnsLoginRequired()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();

        var response = await http.GetAsync(AuthorizeUrl(SpaClientId, SpaRedirectUri, extra: "&prompt=none"));

        Assert.StartsWith(SpaRedirectUri + "?", response.Headers.Location!.ToString());
        Assert.Contains("error=login_required", response.Headers.Location!.ToString());
    }

    [Theory]
    [InlineData("&prompt=login")]
    [InlineData("&max_age=0")]
    public async Task PromptLogin_Or_MaxAge_ForceANewSignIn_WithoutLooping(string extra)
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);
        await Task.Delay(1100); // make the session older than max_age=0

        var response = await http.GetAsync(AuthorizeUrl(SpaClientId, SpaRedirectUri, extra: extra));

        var location = response.Headers.Location!.ToString();
        Assert.StartsWith("/Account/Login?returnUrl=", location);
        var returnUrl = ReturnUrlOf(response);
        Assert.DoesNotContain("prompt=login", returnUrl);
        Assert.DoesNotContain("max_age", returnUrl);
    }
}
