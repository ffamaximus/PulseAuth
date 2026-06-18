using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Models;
using PulseAuth.Validators;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles GET/POST /connect/authorize
/// Implements the OAuth2 Authorization Code flow with PKCE.
/// </summary>
internal static class AuthorizeEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext                  ctx,
        IOptions<PulseAuthOptions>   optionsAccessor,
        AuthorizeRequestValidator    validator,
        IAuthorizationCodeStore      codeStore,
        CancellationToken            ct)
    {
        var options = optionsAccessor.Value;
        var q       = ctx.Request.Query;

        var clientId           = q["client_id"].ToString();
        var responseType       = q["response_type"].ToString();
        var redirectUri        = q["redirect_uri"].ToString();
        var scope              = q["scope"].ToString();
        var state              = q["state"].ToString();
        var codeChallenge      = q["code_challenge"].ToString();
        var codeChallengeMethod = q["code_challenge_method"].ToString();
        var nonce              = q["nonce"].ToString();

        // 1. Validate the request parameters
        var validation = await validator.ValidateAsync(
            clientId, responseType, redirectUri, scope,
            codeChallenge, codeChallengeMethod, ct);

        if (!validation.IsValid)
            return BuildErrorRedirect(redirectUri, state, validation.Error!, validation.ErrorDesc!);

        var client = validation.Client!;

        // 2. Ensure the user is authenticated
        var authResult = await ctx.AuthenticateAsync();
        if (!authResult.Succeeded || authResult.Principal is null)
        {
            // Redirect to login page, passing back the full authorize URL as returnUrl
            var returnUrl = ctx.Request.Path + ctx.Request.QueryString;
            var loginUrl  = $"{options.LoginPath}?returnUrl={Uri.EscapeDataString(returnUrl)}";
            return Results.Redirect(loginUrl);
        }

        var subjectId = authResult.Principal.FindFirst("sub")?.Value
                     ?? authResult.Principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(subjectId))
            return BuildErrorRedirect(redirectUri, state, "server_error", "Could not determine user identity");

        // 3. Issue authorization code
        var authCode = new AuthorizationCode
        {
            Code                = GenerateCode(),
            ClientId            = client.ClientId,
            SubjectId           = subjectId,
            CodeChallenge       = string.IsNullOrEmpty(codeChallenge) ? null : codeChallenge,
            CodeChallengeMethod = string.IsNullOrEmpty(codeChallengeMethod) ? null : codeChallengeMethod,
            Scopes              = validation.RequestedScopes,
            RedirectUri         = string.IsNullOrEmpty(redirectUri) ? null : redirectUri,
            Nonce               = string.IsNullOrEmpty(nonce) ? null : nonce,
            CreatedAt           = DateTime.UtcNow,
            ExpiresAt           = DateTime.UtcNow.AddSeconds(client.AuthorizationCodeLifetime),
        };

        await codeStore.StoreAsync(authCode, ct);

        // 4. Redirect back to client
        var redirect = string.IsNullOrEmpty(redirectUri)
            ? client.RedirectUris.First()
            : redirectUri;

        var queryString = $"?code={Uri.EscapeDataString(authCode.Code)}";
        if (!string.IsNullOrEmpty(state))
            queryString += $"&state={Uri.EscapeDataString(state)}";

        return Results.Redirect(redirect + queryString);
    }

    private static IResult BuildErrorRedirect(string? redirectUri, string? state, string error, string description)
    {
        if (string.IsNullOrEmpty(redirectUri))
            return Results.BadRequest(new { error, error_description = description });

        var qs = $"?error={Uri.EscapeDataString(error)}&error_description={Uri.EscapeDataString(description)}";
        if (!string.IsNullOrEmpty(state))
            qs += $"&state={Uri.EscapeDataString(state)}";

        return Results.Redirect(redirectUri + qs);
    }

    private static string GenerateCode()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
