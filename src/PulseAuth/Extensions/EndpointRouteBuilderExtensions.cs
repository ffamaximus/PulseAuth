using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Endpoints;
using PulseAuth.Validators;

namespace PulseAuth.Extensions;

/// <summary>
/// Extension methods to map PulseAuth endpoints using ASP.NET Core minimal APIs.
/// </summary>
public static class EndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps all PulseAuth OAuth2/OIDC endpoints.
    /// Call this inside <c>app.MapPulseAuth()</c> after <c>app.UseAuthentication()</c>.
    /// </summary>
    public static IEndpointRouteBuilder MapPulseAuth(this IEndpointRouteBuilder app)
    {
        var options = app.ServiceProvider
            .GetRequiredService<IOptions<PulseAuthOptions>>().Value;

        var prefix = options.RoutePrefix.TrimEnd('/');

        // OpenID Connect discovery
        app.MapGet("/.well-known/openid-configuration", (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            IKeyMaterialService km,
            CancellationToken ct) =>
            DiscoveryEndpoint.HandleAsync(ctx, opts, km, ct))
           .AllowAnonymous()
           .WithName("PulseAuth.Discovery");

        // JSON Web Key Set
        app.MapGet("/.well-known/jwks", (IKeyMaterialService km, CancellationToken ct) =>
            JwksEndpoint.HandleAsync(km, ct))
           .AllowAnonymous()
           .WithName("PulseAuth.Jwks");

        // Authorize endpoint
        app.MapGet($"{prefix}/authorize", (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            AuthorizeRequestValidator validator,
            IAuthorizationCodeStore codes,
            CancellationToken ct) =>
            AuthorizeEndpoint.HandleAsync(ctx, opts, validator, codes, ct))
           .WithName("PulseAuth.Authorize");

        // Token endpoint
        app.MapPost($"{prefix}/token", (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            TokenRequestValidator validator,
            ITokenService tokenSvc,
            IAuthorizationCodeStore codes,
            IRefreshTokenStore refreshTokens,
            CancellationToken ct) =>
            TokenEndpoint.HandleAsync(ctx, opts, validator, tokenSvc, codes, refreshTokens, ct))
           .AllowAnonymous()
           .WithName("PulseAuth.Token");

        // UserInfo endpoint
        app.MapGet($"{prefix}/userinfo", (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            IKeyMaterialService km,
            IUserAuthenticationService users,
            CancellationToken ct) =>
            UserInfoEndpoint.HandleAsync(ctx, opts, km, users, ct))
           .AllowAnonymous()
           .WithName("PulseAuth.UserInfo");

        // Revocation endpoint
        app.MapPost($"{prefix}/revocation", (HttpContext ctx,
            IRefreshTokenStore refreshTokens,
            CancellationToken ct) =>
            RevocationEndpoint.HandleAsync(ctx, refreshTokens, ct))
           .AllowAnonymous()
           .WithName("PulseAuth.Revocation");

        // End session (logout)
        app.MapGet($"{prefix}/endsession", (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            IClientStore clients,
            IRefreshTokenStore refreshTokens,
            IKeyMaterialService km,
            CancellationToken ct) =>
            EndSessionEndpoint.HandleAsync(ctx, opts, clients, refreshTokens, km, ct))
           .WithName("PulseAuth.EndSession");

        return app;
    }
}
