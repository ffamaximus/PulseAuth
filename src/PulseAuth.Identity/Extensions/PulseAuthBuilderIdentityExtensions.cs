using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using PulseAuth.Abstractions;
using PulseAuth.Builders;
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
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddIdentity&lt;ApplicationUser, IdentityRole&gt;()
    ///     .AddEntityFrameworkStores&lt;ApplicationDbContext&gt;();
    ///
    /// builder.Services
    ///     .AddPulseAuth(opts => opts.Issuer = "https://auth.myapp.com")
    ///     .AddDeveloperSigningCredential()
    ///     .AddInMemoryClients(Config.Clients)
    ///     .AddIdentityUsers&lt;ApplicationUser&gt;();
    /// </code>
    /// </example>
    public static PulseAuthBuilder AddIdentityUsers<TUser>(this PulseAuthBuilder builder)
        where TUser : IdentityUser
    {
        builder.Services.AddScoped<IUserAuthenticationService,
            IdentityUserAuthenticationService<TUser>>();
        return builder;
    }
}
