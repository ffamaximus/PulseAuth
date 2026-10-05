using System.Text.Json;
using System.Text.Json.Nodes;

namespace PulseAuth.Helpers;

/// <summary>
/// The individual claims a client asked for with the OIDC <c>claims</c> request parameter
/// (OIDC Core §5.5): standard claims to return from the UserInfo endpoint and/or in the ID token.
/// Only claim names are honoured; <c>essential</c>, <c>value</c> and <c>values</c> are informative.
/// </summary>
public sealed class ClaimsRequest
{
    /// <summary>Standard claims requested for the UserInfo response.</summary>
    public IReadOnlyList<string> UserInfo { get; init; } = [];

    /// <summary>Standard claims requested for the ID token.</summary>
    public IReadOnlyList<string> IdToken { get; init; } = [];

    /// <summary>True when nothing was requested.</summary>
    public bool IsEmpty => UserInfo.Count == 0 && IdToken.Count == 0;

    /// <summary>
    /// Parses the <c>claims</c> parameter. Returns false when it is not a JSON object (or its
    /// <c>userinfo</c> / <c>id_token</c> members are not objects). Unknown members are ignored.
    /// </summary>
    public static bool TryParse(string? json, out ClaimsRequest request)
    {
        request = new ClaimsRequest();
        if (string.IsNullOrWhiteSpace(json))
            return true;

        try
        {
            if (JsonNode.Parse(json) is not JsonObject root)
                return false;

            if (!TryNames(root["userinfo"], out var userInfo) || !TryNames(root["id_token"], out var idToken))
                return false;

            request = new ClaimsRequest { UserInfo = userInfo, IdToken = idToken };
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Keeps only standard claims (OIDC Core §5.1) that <paramref name="isScopeAllowed"/> accepts for
    /// the scope that releases them — so the parameter can never reveal data the client could not
    /// obtain with a scope it is allowed (and, with consent, granted) to use.
    /// </summary>
    public ClaimsRequest Restrict(Func<string, bool> isScopeAllowed)
    {
        bool Allowed(string claim) => StandardClaims.ScopeOf(claim) is { } scope && isScopeAllowed(scope);
        return new ClaimsRequest
        {
            UserInfo = UserInfo.Where(Allowed).ToArray(),
            IdToken  = IdToken.Where(Allowed).ToArray(),
        };
    }

    /// <summary>Compact form for storage with the authorization code / refresh token; null when empty.</summary>
    public string? Serialize()
        => IsEmpty ? null : JsonSerializer.Serialize(new Stored(UserInfo.ToArray(), IdToken.ToArray()));

    /// <summary>Reads a value produced by <see cref="Serialize"/> (empty request for null / invalid input).</summary>
    public static ClaimsRequest Deserialize(string? stored)
    {
        if (string.IsNullOrEmpty(stored))
            return new ClaimsRequest();
        try
        {
            var s = JsonSerializer.Deserialize<Stored>(stored);
            return new ClaimsRequest { UserInfo = s?.u ?? [], IdToken = s?.i ?? [] };
        }
        catch (JsonException)
        {
            return new ClaimsRequest();
        }
    }

    private static bool TryNames(JsonNode? node, out string[] names)
    {
        names = [];
        if (node is null)
            return true;
        if (node is not JsonObject obj)
            return false;
        names = obj.Select(kv => kv.Key).Distinct(StringComparer.Ordinal).ToArray();
        return true;
    }

    // Short member names keep the stored value small.
    private sealed record Stored(string[] u, string[] i);
}
