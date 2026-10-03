using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using PulseAuth.Abstractions;
using PulseAuth.Identity.Options;
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
    private readonly UserManager<TUser>    _userManager;
    private readonly SignInManager<TUser>  _signInManager;
    private readonly IdentityClaimsOptions _claimsOptions;

    /// <summary>
    /// Initializes a new instance of <see cref="IdentityUserAuthenticationService{TUser}"/>.
    /// </summary>
    public IdentityUserAuthenticationService(
        UserManager<TUser>    userManager,
        SignInManager<TUser>  signInManager,
        IdentityClaimsOptions claimsOptions)
    {
        _userManager   = userManager;
        _signInManager = signInManager;
        _claimsOptions = claimsOptions;
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
    /// <remarks>
    /// A user is active when it exists, is not locked out and — when Identity is configured with
    /// <c>SignIn.RequireConfirmedAccount/Email/PhoneNumber</c> — is still allowed to sign in.
    /// </remarks>
    public async Task<bool> IsActiveAsync(string subjectId, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(subjectId);
        if (user is null)
            return false;

        if (await _userManager.IsLockedOutAsync(user))
            return false;

        return await _signInManager.CanSignInAsync(user);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Identity changes the security stamp on password change/reset, e-mail change, 2FA changes,
    /// external login removal and <c>UserManager.UpdateSecurityStampAsync</c> ("sign out everywhere").
    /// </remarks>
    public async Task<string?> GetSecurityStampAsync(string subjectId, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(subjectId);
        return user is null || !_userManager.SupportsUserSecurityStamp
            ? null
            : await _userManager.GetSecurityStampAsync(user);
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

        var email    = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value
                    ?? claims.FirstOrDefault(c => c.Type == "email")?.Value;
        var username = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value
                    ?? claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
                    ?? email
                    ?? $"{provider}_{externalId}";

        // Never silently merge with an existing local account that has the same e-mail: linking
        // must be done by the signed-in owner of that account (account takeover protection).
        if (!string.IsNullOrEmpty(email) && await _userManager.FindByEmailAsync(email) is not null)
            throw new PulseAuth.Exceptions.UserProvisioningException("duplicate_email",
                $"An account with this e-mail already exists. Sign in to it and link your {provider} account.");

        var user = Activator.CreateInstance<TUser>();
        user.UserName = await GetUniqueUserNameAsync(SanitizeUsername(username));
        user.Email    = email;

        var createResult = await _userManager.CreateAsync(user);
        if (!createResult.Succeeded)
        {
            var duplicateEmail = createResult.Errors.Any(e => e.Code == nameof(IdentityErrorDescriber.DuplicateEmail));
            throw new PulseAuth.Exceptions.UserProvisioningException(
                duplicateEmail ? "duplicate_email" : "provisioning_failed",
                duplicateEmail
                    ? $"An account with this e-mail already exists. Sign in to it and link your {provider} account."
                    : "The user account could not be created.",
                new InvalidOperationException(string.Join(", ", createResult.Errors.Select(e => $"{e.Code}: {e.Description}"))));
        }

        var loginResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, externalId, provider));
        if (!loginResult.Succeeded)
        {
            await _userManager.DeleteAsync(user); // do not leave an orphan account without a login
            throw new PulseAuth.Exceptions.UserProvisioningException("provisioning_failed",
                "The user account could not be created.",
                new InvalidOperationException(string.Join(", ", loginResult.Errors.Select(e => $"{e.Code}: {e.Description}"))));
        }

        // Keep the profile information from the provider (name, picture, ...) as user claims,
        // so it is available in ID tokens / userinfo for the "profile" scope.
        var profileClaims = claims
            .Where(c => c.Type is ClaimTypes.Name or ClaimTypes.GivenName or ClaimTypes.Surname or "picture")
            .Where(c => !string.IsNullOrEmpty(c.Value))
            .ToList();
        if (profileClaims.Count > 0)
            await _userManager.AddClaimsAsync(user, profileClaims);

        return await BuildUserInfoAsync(user);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<UserInfo> BuildUserInfoAsync(TUser user)
    {
        // Always fetch user claims — needed to populate well-known profile fields
        // (Name, GivenName, etc.) regardless of IncludeUserClaims setting.
        var rawClaims = await _userManager.GetClaimsAsync(user);

        // ── Additional claims (non-profile) ───────────────────────────────────
        List<Claim> additionalClaims = [];

        if (_claimsOptions.IncludeUserClaims)
        {
            var filtered = rawClaims.Where(c => !WellKnownClaimTypes.Contains(c.Type));

            if (_claimsOptions.ClaimTypeFilter.Count > 0)
                filtered = filtered.Where(c => _claimsOptions.ClaimTypeFilter.Contains(c.Type));

            additionalClaims.AddRange(filtered);
        }

        if (_claimsOptions.IncludeRoles)
        {
            var roles = await _userManager.GetRolesAsync(user);
            additionalClaims.AddRange(roles.Select(r => new Claim("role", r)));
        }

        // ── Build UserInfo ────────────────────────────────────────────────────
        return new UserInfo
        {
            SubjectId           = user.Id,
            Username            = user.UserName,
            Email               = user.Email,
            EmailVerified       = user.EmailConfirmed,
            PhoneNumber         = user.PhoneNumber,
            PhoneNumberVerified = user.PhoneNumberConfirmed,
            Name       = rawClaims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value
                      ?? rawClaims.FirstOrDefault(c => c.Type == "name")?.Value,
            GivenName  = rawClaims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value,
            FamilyName = rawClaims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value,
            Picture    = rawClaims.FirstOrDefault(c => c.Type == "picture")?.Value,
            AdditionalClaims = additionalClaims,
        };
    }

    /// <summary>
    /// Display names from social providers are not unique ("Juan Pérez"): append a short random
    /// suffix when the user name is already taken instead of failing the login.
    /// </summary>
    private async Task<string> GetUniqueUserNameAsync(string baseName)
    {
        var candidate = baseName;
        for (var attempt = 0; attempt < 10; attempt++)
        {
            if (await _userManager.FindByNameAsync(candidate) is null)
                return candidate;

            var suffix = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(3)).ToLowerInvariant();
            candidate  = $"{baseName[..Math.Min(baseName.Length, 57)]}_{suffix}";
        }

        return $"user_{Guid.NewGuid():N}";
    }

    private static string SanitizeUsername(string input)
    {
        var safe = new string(input.Where(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.').ToArray());
        return safe.Length > 0 ? safe[..Math.Min(safe.Length, 64)] : $"user_{Guid.NewGuid():N}"[..16];
    }

    private static readonly HashSet<string> WellKnownClaimTypes =
    [
        ClaimTypes.Name, ClaimTypes.GivenName, ClaimTypes.Surname, ClaimTypes.Email,
        "name", "given_name", "family_name", "email", "picture", "preferred_username",
    ];
}
