using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles GET /connect/endsession (OIDC RP-Initiated Logout)
/// Signs out the user and redirects to post_logout_redirect_uri.
/// </summary>
internal static class EndSessionEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext                ctx,
        IOptions<PulseAuthOptions> optionsAccessor,
        IClientStore               clients,
        IRefreshTokenStore         refreshTokens,
        CancellationToken          ct)
    {
        var options               = optionsAccessor.Value;
        var q                     = ctx.Request.Query;
        var postLogoutRedirectUri = q["post_logout_redirect_uri"].ToString();
        var state                 = q["state"].ToString();
        var clientId              = q["client_id"].ToString();

        // Validate post_logout_redirect_uri against registered URIs
        if (!string.IsNullOrEmpty(postLogoutRedirectUri) && !string.IsNullOrEmpty(clientId))
        {
            var client = await clients.FindClientByIdAsync(clientId, ct);
            if (client is null ||
                !client.PostLogoutRedirectUris.Any(u =>
                    string.Equals(u, postLogoutRedirectUri, StringComparison.Ordinal)))
            {
                postLogoutRedirectUri = null; // ignore invalid URI
            }
        }

        // Sign out
        var authResult = await ctx.AuthenticateAsync();
        if (authResult.Succeeded && authResult.Principal is not null)
        {
            var subjectId = authResult.Principal.FindFirst("sub")?.Value
                         ?? authResult.Principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            // Revoke refresh tokens for this user across all clients
            if (!string.IsNullOrEmpty(subjectId) && !string.IsNullOrEmpty(clientId))
                await refreshTokens.RevokeBySubjectAsync(subjectId, clientId, ct);
        }

        await ctx.SignOutAsync();

        if (!string.IsNullOrEmpty(postLogoutRedirectUri))
        {
            var redirect = postLogoutRedirectUri;
            if (!string.IsNullOrEmpty(state))
                redirect += $"?state={Uri.EscapeDataString(state)}";
            return Results.Redirect(redirect);
        }

        return Results.Redirect(options.LogoutPath);
    }
}
