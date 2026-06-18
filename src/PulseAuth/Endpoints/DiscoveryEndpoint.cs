using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using PulseAuth.Configuration;
using PulseAuth.Models;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles GET /.well-known/openid-configuration
/// Returns the OpenID Connect discovery document.
/// </summary>
internal static class DiscoveryEndpoint
{
    public static IResult Handle(HttpContext ctx, IOptions<PulseAuthOptions> optionsAccessor)
    {
        var options = optionsAccessor.Value;
        var issuer  = options.Issuer.TrimEnd('/');
        var prefix  = options.RoutePrefix.TrimEnd('/');

        var doc = new DiscoveryDocument
        {
            Issuer                = issuer,
            AuthorizationEndpoint = $"{issuer}{prefix}/authorize",
            TokenEndpoint         = $"{issuer}{prefix}/token",
            UserInfoEndpoint      = $"{issuer}{prefix}/userinfo",
            JwksUri               = $"{issuer}/.well-known/jwks",
            EndSessionEndpoint    = $"{issuer}{prefix}/endsession",
            RevocationEndpoint    = $"{issuer}{prefix}/revocation",
            ScopesSupported       = options.SupportedScopes,
            ClaimsSupported       = ["sub", "name", "given_name", "family_name", "email", "email_verified", "picture", "preferred_username"],
        };

        return Results.Ok(doc);
    }
}
