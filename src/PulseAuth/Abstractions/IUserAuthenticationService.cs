using System.Security.Claims;
using PulseAuth.Models;

namespace PulseAuth.Abstractions;

/// <summary>
/// Validates user credentials and retrieves user profile information.
/// Implement this interface to connect PulseAuth to your user store.
/// The default implementation (<see cref="PulseAuth.Identity.IdentityUserAuthenticationService"/>) uses ASP.NET Core Identity.
/// </summary>
public interface IUserAuthenticationService
{
    /// <summary>
    /// Validates username/password credentials (used in the Password grant — legacy).
    /// Returns the user's info if valid, null otherwise.
    /// </summary>
    Task<UserInfo?> ValidateCredentialsAsync(string username, string password, CancellationToken ct = default);

    /// <summary>
    /// Retrieves a user by their subject ID (sub claim).
    /// </summary>
    Task<UserInfo?> GetUserByIdAsync(string subjectId, CancellationToken ct = default);

    /// <summary>
    /// Finds a user linked to an external provider identity (e.g. Google, GitHub).
    /// </summary>
    /// <param name="provider">Provider name ("Google", "GitHub", etc.).</param>
    /// <param name="externalId">The user's unique ID at the external provider.</param>
    /// <param name="ct"></param>
    Task<UserInfo?> FindByExternalProviderAsync(string provider, string externalId, CancellationToken ct = default);

    /// <summary>
    /// Provisions (creates or updates) a local user from an external provider login.
    /// Called when <see cref="FindByExternalProviderAsync"/> returns null.
    /// </summary>
    Task<UserInfo> AutoProvisionUserAsync(string provider, string externalId, IEnumerable<Claim> externalClaims, CancellationToken ct = default);
}
