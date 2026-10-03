using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using PulseAuth.Tests.Infrastructure;
using static PulseAuth.Tests.Infrastructure.PulseAuthTestHost;

namespace PulseAuth.Tests;

/// <summary>Open-redirect protections on /connect/authorize and /connect/endsession.</summary>
public class AuthorizeAndLogoutTests
{
    [Fact]
    public async Task Authorize_UnknownClient_DoesNotRedirectToAttacker()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();

        var response = await http.GetAsync("/connect/authorize?client_id=nope&response_type=code&redirect_uri=https://evil.com/x");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task Authorize_UnregisteredRedirectUri_DoesNotRedirect()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();

        var response = await http.GetAsync($"/connect/authorize?client_id={SpaClientId}&response_type=code&redirect_uri=https://evil.com/x");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task Authorize_ErrorAfterRedirectValidation_IsReturnedToRegisteredUri()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();

        var response = await http.GetAsync($"/connect/authorize?client_id={SpaClientId}&response_type=token&redirect_uri={SpaRedirectUri}&state=s1");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(SpaRedirectUri + "?", location);
        var query = QueryHelpers.ParseQuery(new Uri(location).Query);
        Assert.Equal("unsupported_response_type", query["error"].ToString());
        Assert.Equal("s1", query["state"].ToString());
    }

    [Fact]
    public async Task Authorize_PlainPkce_RejectedByDefault()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        await LoginAsync(http);

        var response = await http.GetAsync($"/connect/authorize?client_id={SpaClientId}&response_type=code&redirect_uri={SpaRedirectUri}" +
                                           "&scope=openid&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789abcdefg&code_challenge_method=plain");

        Assert.Contains("error=invalid_request", response.Headers.Location!.ToString());
    }

    [Theory]
    [InlineData("/connect/endsession?post_logout_redirect_uri=https://evil.com")]
    [InlineData("/connect/endsession?post_logout_redirect_uri=https://evil.com&client_id=spa")]
    public async Task EndSession_UnverifiedRedirect_GoesToLocalLogoutPage(string url)
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();

        var response = await http.GetAsync(url);

        Assert.Equal("/Account/Logout", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task EndSession_RegisteredUri_RedirectsWithState()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();

        var response = await http.GetAsync($"/connect/endsession?client_id={SpaClientId}&post_logout_redirect_uri={Uri.EscapeDataString(SpaLogoutUri)}&state=st");

        Assert.Equal(SpaLogoutUri + "&state=st", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task EndSession_ForgedIdTokenHint_DoesNotRedirect()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();

        var response = await http.GetAsync($"/connect/endsession?id_token_hint=eyJhbGciOiJub25lIn0.eyJhdWQiOiJzcGEifQ.&post_logout_redirect_uri={Uri.EscapeDataString(SpaLogoutUri)}");

        Assert.DoesNotContain("app.example", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task EndSession_ValidIdTokenHint_IdentifiesClient()
    {
        await using var host = await StartAsync();
        using var http = host.CreateClient();
        var tokens = await host.CodeFlowAsync(http);

        var response = await http.GetAsync($"/connect/endsession?id_token_hint={tokens.GetProperty("id_token").GetString()}&post_logout_redirect_uri={Uri.EscapeDataString(SpaLogoutUri)}");

        Assert.Equal(SpaLogoutUri, response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task EndSession_RequireConfirmation_DoesNotSignOutFromALink()
    {
        await using var host = await StartAsync(o => o.RequireLogoutConfirmation = true);
        using var http = host.CreateClient();
        await LoginAsync(http);

        var response = await http.GetAsync($"/connect/endsession?client_id={SpaClientId}&post_logout_redirect_uri={Uri.EscapeDataString(SpaLogoutUri)}");

        Assert.StartsWith("/Account/Logout?returnUrl=", response.Headers.Location!.ToString());
        // still signed in: authorize issues a code without asking to log in
        var authorize = await http.GetAsync($"/connect/authorize?client_id={SpaClientId}&response_type=code&redirect_uri={SpaRedirectUri}" +
                                            "&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");
        Assert.StartsWith(SpaRedirectUri + "?code=", authorize.Headers.Location!.ToString());
    }
}
