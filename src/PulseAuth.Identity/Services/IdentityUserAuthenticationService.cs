using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using PulseAuth.Abstractions;
using PulseAuth.Models;

namespace PulseAuth.Identity.Services;

/// <summary>
/// <see cref="IUserAuthenticationService"/> backed by ASP.NET Core Identity.
/// Plug this in by calling <c>builder.AddIdentityUsers&lt;TUser&gt;()</c>.
/// </summary>
/// <typeparam name="TUser">Your IdentityUser-derived class.</typeparam>
public class IdentityUserAuthenticationService<TUser> : IUserAuthenticationService
    where TUser : IdentityUser
{
    private readonly UserManager<TUser>   _userManager;
    private readonly SignInManager<TUser> _signInManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="IdentityUserAuthenticationService{TUser}"/> class with the specified UserManager and SignInManager. The UserManager is used to manage user accounts, retrieve user information, and perform user-related operations, while the SignInManager is used to handle password verification and sign-in operations. This constructor is typically called by dependency injection when you register the service in your application's service container. Make sure to configure ASP.NET Core Identity properly in your application to ensure that the UserManager and SignInManager are available for injection.
    /// </summary>
    /// <param name="userManager"></param>
    /// <param name="signInManager"></param>
    public IdentityUserAuthenticationService(
        UserManager<TUser>   userManager,
        SignInManager<TUser> signInManager)
    {
        _userManager   = userManager;
        _signInManager = signInManager;
    }

    /// <inheritdoc />
    public async Task<UserInfo?> ValidateCredentialsAsync(
        string username, string password, CancellationToken ct = default)
    {
        var user = await _userManager.FindByNameAsync(username)
                ?? await _userManager.FindByEmailAsync(username);

        if (user is null) return null;

        var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        return result.Succeeded ? await BuildUserInfoAsync(user) : null;
    }

    /// <inheritdoc />
    public async Task<UserInfo?> GetUserByIdAsync(string subjectId, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(subjectId);
        return user is null ? null : await BuildUserInfoAsync(user);
    }

    /// <inheritdoc />
    public async Task<UserInfo?> FindByExternalProviderAsync(
        string provider, string externalId, CancellationToken ct = default)
    {
        var user = await _userManager.FindByLoginAsync(provider, externalId);
        return user is null ? null : await BuildUserInfoAsync(user);
    }

    /// <inheritdoc />
    public async Task<UserInfo> AutoProvisionUserAsync(
        string provider, string externalId, IEnumerable<Claim> externalClaims, CancellationToken ct = default)
    {
        var claims = externalClaims.ToList();

        // Try to get a sensible username from external claims
        var email    = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value
                    ?? claims.FirstOrDefault(c => c.Type == "email")?.Value;
        var username = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value
                    ?? claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
                    ?? email
                    ?? $"{provider}_{externalId}";

        // Construct a new user
        var user = Activator.CreateInstance<TUser>();
        user.UserName = SanitizeUsername(username);
        user.Email    = email;

        var createResult = await _userManager.CreateAsync(user);
        if (!createResult.Succeeded)
            throw new InvalidOperationException(
                $"Failed to auto-provision user: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");

        // Link the external login
        var loginInfo = new UserLoginInfo(provider, externalId, provider);
        await _userManager.AddLoginAsync(user, loginInfo);

        return await BuildUserInfoAsync(user);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<UserInfo> BuildUserInfoAsync(TUser user)
    {
        var claims = await _userManager.GetClaimsAsync(user);

        return new UserInfo
        {
            SubjectId   = user.Id,
            Username    = user.UserName,
            Email       = user.Email,
            EmailVerified = user.EmailConfirmed,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberVerified = user.PhoneNumberConfirmed,
            Name        = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value
                       ?? claims.FirstOrDefault(c => c.Type == "name")?.Value,
            GivenName   = claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value,
            FamilyName  = claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value,
            Picture     = claims.FirstOrDefault(c => c.Type == "picture")?.Value,
            AdditionalClaims = claims
                .Where(c => !WellKnownClaimTypes.Contains(c.Type))
                .ToList(),
        };
    }

    private static string SanitizeUsername(string input)
    {
        // Remove characters not valid in usernames
        var safe = new string(input.Where(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.').ToArray());
        return safe.Length > 0 ? safe[..Math.Min(safe.Length, 64)] : $"user_{Guid.NewGuid():N}"[..16];
    }

    private static readonly HashSet<string> WellKnownClaimTypes =
    [
        ClaimTypes.Name, ClaimTypes.GivenName, ClaimTypes.Surname, ClaimTypes.Email,
        "name", "given_name", "family_name", "email", "picture", "preferred_username",
    ];
}
