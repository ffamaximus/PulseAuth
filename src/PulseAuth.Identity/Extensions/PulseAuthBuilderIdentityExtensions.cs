using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using PulseAuth.Abstractions;
using PulseAuth.Builders;
using PulseAuth.Identity.Options;
using PulseAuth.Identity.Services;

namespace PulseAuth.Identity.Extensions;

/// <summary>
/// Extension methods that connect PulseAuth to ASP.NET Core Identity.
/// </summary>
public static class PulseAuthBuilderIdentityExtensions
{
    /// <summary>
    /// Registers <see cref="IdentityUserAuthenticationService{TUser}"/> as the
    /// <see cref="IUserAuthenticationService"/>, linking PulseAuth to Identity's
    /// <see cref="UserManager{TUser}"/> and <see cref="SignInManager{TUser}"/>.
    /// </summary>
    /// <typeparam name="TUser">Your <see cref="IdentityUser"/>-derived class.</typeparam>
    /// <param name="builder">The PulseAuth builder.</param>
    /// <param name="configureClaims">
    /// Optional. Configure which Identity claims are included in tokens.
    /// </param>
    /// <example>
    /// Default (no extra claims):
    /// <code>
    /// .AddIdentityUsers&lt;IdentityUser&gt;()
    /// </code>
    ///
    /// Include roles and all custom user claims:
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
    public static PulseAuthBuilder AddIdentityUsers<TUser>(
        this PulseAuthBuilder builder,
        Action<IdentityClaimsOptions>? configureClaims = null)
        where TUser : IdentityUser
    {
        var opts = new IdentityClaimsOptions();
        configureClaims?.Invoke(opts);

        builder.Services.AddSingleton(opts);
        builder.Services.AddScoped<IUserAuthenticationService,
            IdentityUserAuthenticationService<TUser>>();

        return builder;
    }
}
