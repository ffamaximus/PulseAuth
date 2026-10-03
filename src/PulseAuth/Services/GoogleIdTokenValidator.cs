using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;
using PulseAuth.Constants;

namespace PulseAuth.Services;

/// <summary>
/// Validates Google-issued ID tokens (obtained via Google Sign-In SDK / One Tap).
/// Fetches Google's JWKS automatically from the OIDC discovery document and caches them.
/// Registered via <c>builder.AddGoogleTokenExchange(googleClientId)</c>.
/// </summary>
public sealed class GoogleIdTokenValidator : IExternalTokenValidator
{
    private const string GoogleDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration";

    private readonly string _googleClientId;
    private readonly JwtSecurityTokenHandler _handler = new();
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _configManager;

    /// <inheritdoc />
    public string ProviderName => "Google";

    /// <inheritdoc />
    public string SupportedGrantType => GrantTypes.GoogleIdToken;

    /// <summary>
    /// Initializes the validator with the Google OAuth2 client ID.
    /// The client ID must match the <c>aud</c> claim in the Google ID token.
    /// </summary>
    /// <param name="googleClientId">
    /// The Google OAuth2 client ID (from Google Cloud Console → Credentials).
    /// </param>
    public GoogleIdTokenValidator(string googleClientId)
    {
        _googleClientId = googleClientId;
        _configManager  = new ConfigurationManager<OpenIdConnectConfiguration>(
            GoogleDiscoveryUrl,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever { RequireHttps = true });
    }

    /// <inheritdoc />
    public async Task<ExternalIdentity?> ValidateAsync(string token, CancellationToken ct = default)
    {
        OpenIdConnectConfiguration config;
        try
        {
            config = await _configManager.GetConfigurationAsync(ct);
        }
        catch
        {
            return null;
        }

        var parameters = new TokenValidationParameters
        {
            ValidIssuers      = ["accounts.google.com", "https://accounts.google.com"],
            ValidAudience     = _googleClientId,
            IssuerSigningKeys = config.SigningKeys,
            ValidateLifetime  = true,
        };

        try
        {
            var principal = _handler.ValidateToken(token, parameters, out _);

            var sub = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                   ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(sub))
                return null;

            // Only trust the e-mail address if Google says it is verified. An unverified address
            // must never be stored as the user's e-mail (it could later be used to link accounts).
            var emailVerified = string.Equals(Claim(principal, "email_verified"), "true", StringComparison.OrdinalIgnoreCase);
            var email = emailVerified
                ? Claim(principal, JwtRegisteredClaimNames.Email) ?? Claim(principal, ClaimTypes.Email)
                : null;

            return new ExternalIdentity(
                SubjectId:  sub,
                Email:      email,
                Name:       Claim(principal, JwtRegisteredClaimNames.Name)
                         ?? Claim(principal, ClaimTypes.Name),
                GivenName:  Claim(principal, JwtRegisteredClaimNames.GivenName)
                         ?? Claim(principal, ClaimTypes.GivenName),
                FamilyName: Claim(principal, JwtRegisteredClaimNames.FamilyName)
                         ?? Claim(principal, ClaimTypes.Surname),
                Picture:    Claim(principal, "picture"));
        }
        catch
        {
            return null;
        }
    }

    private static string? Claim(ClaimsPrincipal p, string type)
        => p.FindFirst(type)?.Value;
}
