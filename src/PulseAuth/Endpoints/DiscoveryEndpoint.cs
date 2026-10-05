using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Models;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles GET /.well-known/openid-configuration
/// Returns the OpenID Connect discovery document.
/// </summary>
internal static class DiscoveryEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext                ctx,
        IOptions<PulseAuthOptions> optionsAccessor,
        IKeyMaterialService        keyMaterial,
        IEnumerable<IExternalTokenValidator> externalValidators,
        CancellationToken          ct)
    {
        var options = optionsAccessor.Value;
        var signing = await keyMaterial.GetSigningCredentialsAsync(ct);
        var baseUrl = options.Issuer.TrimEnd('/');   // only for building endpoint URLs
        var prefix  = options.RoutePrefix.TrimEnd('/');

        var doc = new DiscoveryDocument
        {
            // Must be byte-for-byte identical to the "iss" claim of issued tokens (OIDC Discovery §4.3),
            // so it is published exactly as configured (a trailing "/" is NOT removed).
            Issuer                = options.Issuer,
            AuthorizationEndpoint = $"{baseUrl}{prefix}/authorize",
            TokenEndpoint         = $"{baseUrl}{prefix}/token",
            UserInfoEndpoint      = $"{baseUrl}{prefix}/userinfo",
            JwksUri               = $"{baseUrl}/.well-known/jwks",
            EndSessionEndpoint    = $"{baseUrl}{prefix}/endsession",
            RevocationEndpoint    = $"{baseUrl}{prefix}/revocation",
            IntrospectionEndpoint = $"{baseUrl}{prefix}/introspect",
            ScopesSupported       = options.SupportedScopes,
            IdTokenSigningAlgValuesSupported = [signing.Algorithm],
            CodeChallengeMethodsSupported    = options.AllowPlainPkce ? ["S256", "plain"] : ["S256"],
            GrantTypesSupported   = new[] { "authorization_code", "client_credentials", "refresh_token", "password" }
                                        .Concat(externalValidators.Select(v => v.SupportedGrantType))
                                        .Distinct()
                                        .ToArray(),
            ClaimsParameterSupported = true,
            RequestParameterSupported = options.AllowUnsignedRequestObjects,
            RequestObjectSigningAlgValuesSupported = options.AllowUnsignedRequestObjects ? ["none"] : null,
            AcrValuesSupported    = options.AcrValuesSupported.Count > 0 ? options.AcrValuesSupported : null,
            ClaimsSupported       = ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr",
                                     "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
                                     "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
                                     "email", "email_verified", "phone_number", "phone_number_verified", "address"],
        };

        return Results.Ok(doc);
    }
}
