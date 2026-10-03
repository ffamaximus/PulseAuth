using System.Text;
using Microsoft.AspNetCore.Http;

namespace PulseAuth.Endpoints;

/// <summary>
/// Reads client credentials from <c>Authorization: Basic</c> (client_secret_basic) or the form
/// body (client_secret_post), as defined in RFC 6749 §2.3.1. Malformed input is reported instead
/// of throwing, so bad requests end in <c>invalid_client</c> rather than HTTP 500.
/// </summary>
internal static class ClientCredentialsReader
{
    internal readonly record struct Result(bool IsValid, bool UsedBasic, string? ClientId, string? ClientSecret);

    public static Result Read(HttpContext ctx, IFormCollection form)
    {
        var authHeader = ctx.Request.Headers.Authorization.ToString();
        if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            string decoded;
            try
            {
                decoded = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader["Basic ".Length..].Trim()));
            }
            catch (FormatException)
            {
                return new Result(false, true, null, null);
            }

            var separator = decoded.IndexOf(':');
            if (separator <= 0)
                return new Result(false, true, null, null);

            var id     = FormDecode(decoded[..separator]);
            var secret = FormDecode(decoded[(separator + 1)..]);
            if (id is null || secret is null)
                return new Result(false, true, null, null);

            // A client MUST NOT use more than one authentication method (RFC 6749 §2.3).
            var formId = form["client_id"].ToString();
            if (!string.IsNullOrEmpty(form["client_secret"].ToString()) ||
                (!string.IsNullOrEmpty(formId) && !string.Equals(formId, id, StringComparison.Ordinal)))
                return new Result(false, true, null, null);

            return new Result(true, true, id, string.IsNullOrEmpty(secret) ? null : secret);
        }

        var clientId     = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();
        return new Result(
            true, false,
            string.IsNullOrEmpty(clientId) ? null : clientId,
            string.IsNullOrEmpty(clientSecret) ? null : clientSecret);
    }

    /// <summary>
    /// Error response for client authentication failures: 401 + WWW-Authenticate when the client
    /// used HTTP Basic (RFC 6749 §5.2), 400 otherwise.
    /// </summary>
    public static IResult InvalidClient(HttpContext ctx, bool usedBasic, string description)
    {
        if (usedBasic)
            ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"PulseAuth\"";

        return Results.Json(
            new { error = Constants.OAuthErrors.InvalidClient, error_description = description },
            statusCode: usedBasic ? StatusCodes.Status401Unauthorized : StatusCodes.Status400BadRequest);
    }

    /// <summary>400 invalid_request for bodies that are not application/x-www-form-urlencoded.</summary>
    public static IResult NotAForm()
        => Results.Json(
            new { error = Constants.OAuthErrors.InvalidRequest,
                  error_description = "The request body must be application/x-www-form-urlencoded" },
            statusCode: StatusCodes.Status400BadRequest);

    // application/x-www-form-urlencoded decoding ('+' = space), as required for Basic credentials.
    private static string? FormDecode(string value)
    {
        try
        {
            return Uri.UnescapeDataString(value.Replace('+', ' '));
        }
        catch (UriFormatException)
        {
            return null;
        }
    }
}
