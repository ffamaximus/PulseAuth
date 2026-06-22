namespace PulseAuth.Identity.Options;

/// <summary>
/// Controls which Identity claims are pulled from the database and included in
/// PulseAuth tokens. Pass an instance to
/// <c>AddIdentityUsers&lt;TUser&gt;(opts => { ... })</c>.
/// </summary>
/// <example>
/// Include everything:
/// <code>
/// .AddIdentityUsers&lt;IdentityUser&gt;(claims =>
/// {
///     claims.IncludeRoles      = true;
///     claims.IncludeUserClaims = true;
/// })
/// </code>
///
/// Include roles and only specific claim types:
/// <code>
/// .AddIdentityUsers&lt;IdentityUser&gt;(claims =>
/// {
///     claims.IncludeRoles      = true;
///     claims.IncludeUserClaims = true;
///     claims.ClaimTypeFilter   = ["department", "tenant", "subscription"];
/// })
/// </code>
/// </example>
public sealed class IdentityClaimsOptions
{
    /// <summary>
    /// When <c>true</c>, roles from <c>AspNetUserRoles</c> are added as
    /// <c>"role"</c> claims in the token. Default: <c>false</c>.
    /// </summary>
    public bool IncludeRoles { get; set; } = false;

    /// <summary>
    /// When <c>true</c>, custom claims stored in <c>AspNetUserClaims</c> are
    /// included in the token as additional claims. Standard profile fields
    /// (<c>name</c>, <c>given_name</c>, etc.) are always mapped to their
    /// respective token fields regardless of this setting. Default: <c>true</c>.
    /// </summary>
    public bool IncludeUserClaims { get; set; } = true;

    /// <summary>
    /// Restricts which custom claim types are included when
    /// <see cref="IncludeUserClaims"/> is <c>true</c>.
    /// An empty collection means <em>all</em> custom claim types are included.
    /// </summary>
    /// <example>
    /// <code>
    /// claims.ClaimTypeFilter = ["department", "tenant", "subscription_plan"];
    /// </code>
    /// </example>
    public ICollection<string> ClaimTypeFilter { get; set; } = [];
}
