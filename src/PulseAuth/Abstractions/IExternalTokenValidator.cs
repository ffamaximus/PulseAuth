namespace PulseAuth.Abstractions;

/// <summary>
/// Represents an external identity returned after validating a provider token.
/// </summary>
/// <param name="SubjectId">The user's unique ID at the external provider.</param>
/// <param name="Email">Email address, if provided by the provider.</param>
/// <param name="Name">Full display name.</param>
/// <param name="GivenName">First name.</param>
/// <param name="FamilyName">Last name / surname.</param>
/// <param name="Picture">Profile picture URL.</param>
public record ExternalIdentity(
    string  SubjectId,
    string? Email,
    string? Name,
    string? GivenName,
    string? FamilyName,
    string? Picture);

/// <summary>
/// Validates a provider-issued token (e.g. Google ID token, Facebook access token)
/// and returns the external identity if valid.
/// Implement this interface to support additional social providers beyond the built-in ones.
/// </summary>
public interface IExternalTokenValidator
{
    /// <summary>Display name of the provider (e.g. "Google", "Facebook").</summary>
    string ProviderName { get; }

    /// <summary>
    /// The OAuth2 grant type URN this validator handles.
    /// e.g. <c>urn:ietf:params:oauth:grant-type:google_id_token</c>
    /// </summary>
    string SupportedGrantType { get; }

    /// <summary>
    /// Validates the provider token and returns the external identity.
    /// Returns <c>null</c> if the token is invalid, expired, or not issued for this application.
    /// </summary>
    /// <param name="token">The token issued by the external provider.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<ExternalIdentity?> ValidateAsync(string token, CancellationToken ct = default);
}
