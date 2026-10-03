using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using PulseAuth.Abstractions;

namespace PulseAuth.Endpoints;

/// <summary>
/// Minimal, self-contained CORS handling for the PulseAuth endpoints, driven by
/// <c>Client.AllowedCorsOrigins</c> (works without <c>app.UseCors()</c>).
/// Discovery and JWKS are public metadata and allow any origin.
/// </summary>
internal static class PulseAuthCors
{
    private const string AllowedMethods = "GET, POST, OPTIONS";
    private const string DefaultHeaders = "Authorization, Content-Type";

    /// <summary>Endpoint filter: adds Access-Control-Allow-Origin for allowed origins.</summary>
    public static async ValueTask<object?> Filter(
        EndpointFilterInvocationContext invocation, EndpointFilterDelegate next, bool isPublic)
    {
        await ApplyAsync(invocation.HttpContext, isPublic);
        return await next(invocation);
    }

    /// <summary>Answers a CORS preflight (OPTIONS) request.</summary>
    public static async Task<IResult> PreflightAsync(HttpContext ctx, bool isPublic)
    {
        if (await ApplyAsync(ctx, isPublic))
        {
            var requestedHeaders = ctx.Request.Headers.AccessControlRequestHeaders.ToString();
            ctx.Response.Headers.AccessControlAllowMethods = AllowedMethods;
            ctx.Response.Headers.AccessControlAllowHeaders =
                string.IsNullOrWhiteSpace(requestedHeaders) ? DefaultHeaders : requestedHeaders;
            ctx.Response.Headers.AccessControlMaxAge = "600";
        }

        return Results.NoContent();
    }

    private static async Task<bool> ApplyAsync(HttpContext ctx, bool isPublic)
    {
        var origin = ctx.Request.Headers.Origin.ToString();
        if (string.IsNullOrEmpty(origin))
            return false;

        if (isPublic)
        {
            ctx.Response.Headers.AccessControlAllowOrigin = "*";
            return true;
        }

        var clients = ctx.RequestServices.GetService<IClientStore>();
        if (clients is null || !await clients.IsOriginAllowedAsync(origin, ctx.RequestAborted))
            return false;

        ctx.Response.Headers.AccessControlAllowOrigin = origin;
        ctx.Response.Headers.Append("Vary", "Origin");
        return true;
    }
}
