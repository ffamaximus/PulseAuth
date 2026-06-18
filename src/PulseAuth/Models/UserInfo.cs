using System.Security.Claims;

namespace PulseAuth.Models;

/// <summary>
/// Represents an authenticated user's identity as known to PulseAuth.
/// </summary>
public class UserInfo
{
    /// <summary>Stable unique identifier for the user (sub claim).</summary>
    public string SubjectId { get; set; } = default!;

    /// <summary>Login username.</summary>
    public string? Username { get; set; }

    /// <summary>Email address.</summary>
    public string? Email { get; set; }

    /// <summary>Whether the email has been verified.</summary>
    public bool EmailVerified { get; set; }

    /// <summary>Full display name.</summary>
    public string? Name { get; set; }

    /// <summary>Given (first) name.</summary>
    public string? GivenName { get; set; }

    /// <summary>Family (last) name.</summary>
    public string? FamilyName { get; set; }

    /// <summary>URL of the user's profile picture.</summary>
    public string? Picture { get; set; }

    /// <summary>Phone number.</summary>
    public string? PhoneNumber { get; set; }

    /// <summary>Whether the phone number has been verified.</summary>
    public bool PhoneNumberVerified { get; set; }

    /// <summary>
    /// Additional application-specific claims to include in tokens.
    /// These are merged into access tokens and ID tokens based on scope.
    /// </summary>
    public IList<Claim> AdditionalClaims { get; set; } = new List<Claim>();
}
