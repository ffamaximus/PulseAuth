using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;

namespace PulseAuth.Helpers;

/// <summary>
/// Unsigned request objects passed by value (<c>request</c> parameter, OIDC Core §6.1, alg <c>none</c>).
/// Their claims are authorization request parameters that supersede the query ones. An unsigned
/// request object carries no more trust than the query string itself — it is accepted for
/// interoperability, never as proof of the client's identity.
/// </summary>
internal static class RequestObject
{
    // JWT claims that are not authorization request parameters (and nested request objects).
    private static readonly HashSet<string> Ignored = new(StringComparer.Ordinal)
    {
        "request", "request_uri", "iss", "aud", "exp", "iat", "nbf", "jti",
    };

    /// <summary>
    /// Merges the request object into the query. On failure <paramref name="merged"/> is the query
    /// without the <c>request</c> parameter (so the client and redirect_uri can still be validated to
    /// return the error) and <paramref name="error"/> describes the problem.
    /// </summary>
    public static bool TryMerge(IQueryCollection query, out QueryCollection merged, out string? error)
    {
        var parameters = query.Where(kv => kv.Key != "request")
                              .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
        merged = new QueryCollection(parameters);
        error  = null;

        var parts = query["request"].ToString().Split('.');
        if (parts.Length != 3)
        {
            error = "The request object is not a JWT";
            return false;
        }

        try
        {
            using var header = JsonDocument.Parse(WebEncoders.Base64UrlDecode(parts[0]));
            if (!header.RootElement.TryGetProperty("alg", out var alg) || alg.GetString() != "none" || parts[2].Length != 0)
            {
                error = "Only unsigned request objects (alg \"none\") are supported";
                return false;
            }

            using var payload = JsonDocument.Parse(WebEncoders.Base64UrlDecode(parts[1]));
            if (payload.RootElement.ValueKind != JsonValueKind.Object)
            {
                error = "The request object payload must be a JSON object";
                return false;
            }

            foreach (var claim in payload.RootElement.EnumerateObject())
            {
                if (Ignored.Contains(claim.Name))
                    continue;

                var value = claim.Value.ValueKind switch
                {
                    JsonValueKind.String => claim.Value.GetString() ?? "",
                    JsonValueKind.Null   => null,
                    _                    => claim.Value.GetRawText(),   // numbers (max_age), objects (claims)
                };
                if (value is null)
                    continue;

                // OIDC Core §6.1: client_id / response_type in the query and the object must match.
                if (claim.Name is "client_id" or "response_type" &&
                    parameters.TryGetValue(claim.Name, out var existing) && existing.ToString() != value)
                {
                    error = $"{claim.Name} in the request object does not match the request";
                    return false;
                }

                parameters[claim.Name] = new StringValues(value);
            }
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            error = "The request object is malformed";
            return false;
        }

        merged = new QueryCollection(parameters);
        return true;
    }
}
