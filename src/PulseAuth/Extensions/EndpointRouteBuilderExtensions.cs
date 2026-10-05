using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Endpoints;
using PulseAuth.Services;
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

        // OpenID Connect discovery (public metadata)
        app.MapGet("/.well-known/openid-configuration", (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            IKeyMaterialService km,
            IEnumerable<IExternalTokenValidator> external,
            CancellationToken ct) =>
            DiscoveryEndpoint.HandleAsync(ctx, opts, km, external, ct))
           .AllowAnonymous()
           .WithCors(app, options, "/.well-known/openid-configuration", isPublic: true)
           .WithName("PulseAuth.Discovery");

        // JSON Web Key Set (public metadata)
        app.MapGet("/.well-known/jwks", (IKeyMaterialService km, CancellationToken ct) =>
            JwksEndpoint.HandleAsync(km, ct))
           .AllowAnonymous()
           .WithCors(app, options, "/.well-known/jwks", isPublic: true)
           .WithName("PulseAuth.Jwks");

        // Authorize endpoint (browser navigation — no CORS). GET and POST (OIDC Core §3.1.2.1).
        app.MapMethods($"{prefix}/authorize", [HttpMethods.Get, HttpMethods.Post], (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            AuthorizeRequestValidator validator,
            IAuthorizationCodeStore codes,
            IConsentStore consents,
            CancellationToken ct) =>
            AuthorizeEndpoint.HandleAsync(ctx, opts, validator, codes, consents, ct))
           .DisableAntiforgery()
           .WithName("PulseAuth.Authorize");

        // Token endpoint
        app.MapPost($"{prefix}/token", (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            TokenRequestValidator validator,
            ITokenService tokenSvc,
            IAuthorizationCodeStore codes,
            IRefreshTokenStore refreshTokens,
            IReferenceTokenStore referenceTokens,
            IUserAuthenticationService users,
            IRevokedTokenStore revokedTokens,
            CancellationToken ct) =>
            TokenEndpoint.HandleAsync(ctx, opts, validator, tokenSvc, codes, refreshTokens, referenceTokens, users, revokedTokens, ct))
           .AllowAnonymous()
           .WithCors(app, options, $"{prefix}/token", isPublic: false)
           .WithRateLimit(options)
           .WithName("PulseAuth.Token");

        // UserInfo endpoint (GET and POST — OIDC Core §5.3.1)
        app.MapMethods($"{prefix}/userinfo", [HttpMethods.Get, HttpMethods.Post], (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            AccessTokenValidator accessTokens,
            IUserAuthenticationService users,
            CancellationToken ct) =>
            UserInfoEndpoint.HandleAsync(ctx, opts, accessTokens, users, ct))
           .AllowAnonymous()
           .DisableAntiforgery()
           .WithCors(app, options, $"{prefix}/userinfo", isPublic: false)
           .WithRateLimit(options)
           .WithName("PulseAuth.UserInfo");

        // Revocation endpoint (RFC 7009)
        app.MapPost($"{prefix}/revocation", (HttpContext ctx,
            IClientStore clients,
            IRefreshTokenStore refreshTokens,
            IReferenceTokenStore referenceTokens,
            AccessTokenValidator accessTokens,
            IRevokedTokenStore revokedTokens,
            CancellationToken ct) =>
            RevocationEndpoint.HandleAsync(ctx, clients, refreshTokens, referenceTokens, accessTokens, revokedTokens, ct))
           .AllowAnonymous()
           .WithCors(app, options, $"{prefix}/revocation", isPublic: false)
           .WithRateLimit(options)
           .WithName("PulseAuth.Revocation");

        // Introspection endpoint (RFC 7662) — server-to-server, no CORS
        app.MapPost($"{prefix}/introspect", (HttpContext ctx,
            IClientStore clients,
            AccessTokenValidator accessTokens,
            IRefreshTokenStore refreshTokens,
            CancellationToken ct) =>
            IntrospectionEndpoint.HandleAsync(ctx, clients, accessTokens, refreshTokens, ct))
           .AllowAnonymous()
           .WithRateLimit(options)
           .WithName("PulseAuth.Introspection");

        // End session (OIDC RP-Initiated Logout — GET and POST)
        app.MapMethods($"{prefix}/endsession", [HttpMethods.Get, HttpMethods.Post], (HttpContext ctx,
            IOptions<PulseAuthOptions> opts,
            IClientStore clients,
            IRefreshTokenStore refreshTokens,
            IReferenceTokenStore referenceTokens,
            IKeyMaterialService km,
            CancellationToken ct) =>
            EndSessionEndpoint.HandleAsync(ctx, opts, clients, refreshTokens, referenceTokens, km, ct))
           .DisableAntiforgery()
           .WithName("PulseAuth.EndSession");

        return app;
    }

    private static RouteHandlerBuilder WithCors(
        this RouteHandlerBuilder builder, IEndpointRouteBuilder app, PulseAuthOptions options, string path, bool isPublic)
    {
        if (!options.EnableCors)
            return builder;

        builder.AddEndpointFilter((ctx, next) => PulseAuthCors.Filter(ctx, next, isPublic));

        // NOTE: the extra CancellationToken parameter matters — a lambda taking only HttpContext and
        // returning a Task binds to the RequestDelegate overload and its IResult would be ignored.
        app.MapMethods(path, [HttpMethods.Options], (HttpContext ctx, CancellationToken _) => PulseAuthCors.PreflightAsync(ctx, isPublic))
           .AllowAnonymous()
           .ExcludeFromDescription();

        return builder;
    }

    private static RouteHandlerBuilder WithRateLimit(this RouteHandlerBuilder builder, PulseAuthOptions options)
        => string.IsNullOrEmpty(options.RateLimitPolicy)
            ? builder
            : builder.RequireRateLimiting(options.RateLimitPolicy);
}
