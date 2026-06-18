namespace PulseAuth.Constants;

/// <summary>OpenID Connect standard scope constants.</summary>
public static class StandardScopes
{
    /// <summary>Required for OpenID Connect. Issues an ID token.</summary>
    public const string OpenId        = "openid";
    /// <summary>User profile claims: name, family_name, given_name, picture, etc.</summary>
    public const string Profile       = "profile";
    /// <summary>Email address claims.</summary>
    public const string Email         = "email";
    /// <summary>Address claim.</summary>
    public const string Address       = "address";
    /// <summary>Phone number claim.</summary>
    public const string Phone         = "phone";
    /// <summary>Enables issuance of refresh tokens.</summary>
    public const string OfflineAccess = "offline_access";

    /// <summary>
    /// All standard scopes defined by OpenID Connect. This is not an official list from the spec, but a convenient collection of the most common ones. You can include any subset of these in your discovery document and supported scopes configuration.
    /// </summary>
    public static IReadOnlyList<string> All => [OpenId, Profile, Email, Address, Phone, OfflineAccess];
}
