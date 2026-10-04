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

    /// <summary>Middle name(s) (<c>middle_name</c>).</summary>
    public string? MiddleName { get; set; }

    /// <summary>Casual name (<c>nickname</c>).</summary>
    public string? Nickname { get; set; }

    /// <summary>URL of the user's profile page (<c>profile</c>).</summary>
    public string? ProfileUrl { get; set; }

    /// <summary>URL of the user's web page or blog (<c>website</c>).</summary>
    public string? Website { get; set; }

    /// <summary>Gender (<c>gender</c>), e.g. "female", "male" or another value.</summary>
    public string? Gender { get; set; }

    /// <summary>Birthday as ISO 8601 <c>YYYY-MM-DD</c> (or <c>0000-MM-DD</c> / <c>YYYY</c>) (<c>birthdate</c>).</summary>
    public string? Birthdate { get; set; }

    /// <summary>IANA time zone, e.g. "America/Bogota" (<c>zoneinfo</c>).</summary>
    public string? ZoneInfo { get; set; }

    /// <summary>BCP47 locale, e.g. "es-CO" (<c>locale</c>).</summary>
    public string? Locale { get; set; }

    /// <summary>When the profile was last updated (<c>updated_at</c>, emitted as seconds since epoch).</summary>
    public DateTimeOffset? UpdatedAt { get; set; }

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
