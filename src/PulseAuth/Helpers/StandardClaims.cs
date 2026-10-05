using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using PulseAuth.Constants;
using PulseAuth.Models;

namespace PulseAuth.Helpers;

/// <summary>
/// The OpenID Connect standard claims (OIDC Core §5.1), the scope that releases each one (§5.4)
/// and how to read them from a <see cref="UserInfo"/>.
/// </summary>
public static class StandardClaims
{
    private static readonly IReadOnlyDictionary<string, string[]> ClaimsByScope = new Dictionary<string, string[]>
    {
        [StandardScopes.Profile] =
        [
            "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username",
            "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
        ],
        [StandardScopes.Email]   = ["email", "email_verified"],
        [StandardScopes.Address] = ["address"],
        [StandardScopes.Phone]   = ["phone_number", "phone_number_verified"],
    };

    private static readonly IReadOnlyDictionary<string, string> ScopeByClaim =
        ClaimsByScope.SelectMany(kv => kv.Value.Select(c => (Claim: c, Scope: kv.Key)))
                     .ToDictionary(x => x.Claim, x => x.Scope, StringComparer.Ordinal);

    /// <summary>The standard claims released by <paramref name="scope"/> (empty for other scopes).</summary>
    public static IReadOnlyList<string> ForScope(string scope)
        => ClaimsByScope.TryGetValue(scope, out var claims) ? claims : [];

    /// <summary>The scope that releases the standard claim <paramref name="claimName"/>, or null if it is not one.</summary>
    public static string? ScopeOf(string claimName)
        => ScopeByClaim.TryGetValue(claimName, out var scope) ? scope : null;

    /// <summary>
    /// The value of a standard claim for <paramref name="user"/>: a string, <c>bool</c>
    /// (<c>*_verified</c>), <c>long</c> (<c>updated_at</c>) or a dictionary (<c>address</c>).
    /// Null when the user has no value.
    /// </summary>
    public static object? GetValue(UserInfo user, string claimName) => claimName switch
    {
        "name"                  => NullIfEmpty(user.Name),
        "family_name"           => NullIfEmpty(user.FamilyName),
        "given_name"            => NullIfEmpty(user.GivenName),
        "middle_name"           => NullIfEmpty(user.MiddleName),
        "nickname"              => NullIfEmpty(user.Nickname),
        "preferred_username"    => NullIfEmpty(user.Username),
        "profile"               => NullIfEmpty(user.ProfileUrl),
        "picture"               => NullIfEmpty(user.Picture),
        "website"               => NullIfEmpty(user.Website),
        "gender"                => NullIfEmpty(user.Gender),
        "birthdate"             => NullIfEmpty(user.Birthdate),
        "zoneinfo"              => NullIfEmpty(user.ZoneInfo),
        "locale"                => NullIfEmpty(user.Locale),
        "updated_at"            => user.UpdatedAt?.ToUnixTimeSeconds(),
        "email"                 => NullIfEmpty(user.Email),
        "email_verified"        => user.EmailVerified,
        "phone_number"          => NullIfEmpty(user.PhoneNumber),
        "phone_number_verified" => user.PhoneNumberVerified,
        "address"               => user.Address?.ToClaimObject() is { Count: > 0 } address ? address : null,
        _                       => null,
    };

    /// <summary>A JWT claim for a value returned by <see cref="GetValue"/>, with the right JSON type.</summary>
    public static Claim ToJwtClaim(string claimName, object value) => value switch
    {
        bool b   => new Claim(claimName, b ? "true" : "false", ClaimValueTypes.Boolean),
        long l   => new Claim(claimName, l.ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        string s => new Claim(claimName, s),
        _        => new Claim(claimName, JsonSerializer.Serialize(value), JsonClaimValueTypes.Json),
    };

    private static string? NullIfEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;
}
