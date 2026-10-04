using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PulseAuth.EntityFramework.Entities;

/// <summary>
/// Base class for persisted grants (authorization codes, refresh tokens). Contains common properties like Key, ClientId, SubjectId, Scopes, CreatedAt, ExpiresAt and IsConsumed. Derived classes can add additional properties specific to their grant type (e.g., code challenge for authorization codes). This class is designed
/// </summary>
public abstract class PersistedGrantEntity
{
    /// <summary>
    /// Unique identifier for the persisted grant. This is typically a random string that serves as the primary key in the database. For authorization codes, this would be the code itself; for refresh tokens, it could be a unique token identifier. The Key property is used to look up the persisted grant when validating incoming requests (e.g., when exchanging an authorization code for tokens or when refreshing an access token). It should be sufficiently long and random to prevent guessing attacks. The MaxLength attribute ensures that the database column can accommodate typical values for keys without truncation.
    /// </summary>
    [Key, MaxLength(256)]
    public string Key { get; set; } = default!;
    /// <summary>
    /// Identifier of the client that the persisted grant is associated with. This should match the client_id of the client that initiated the authorization process. The ClientId property is used to ensure that the persisted grant is only valid for the client that created it, preventing misuse by other clients. The MaxLength attribute ensures that the database column can accommodate typical client IDs without truncation.
    /// </summary>
    [MaxLength(200)]
    public string ClientId { get; set; } = default!;
    /// <summary>
    /// Identifier of the user (subject) that the persisted grant is associated with. This should match the subject ID of the authenticated user for whom the authorization process was initiated. The SubjectId property is used to ensure that the persisted grant is only valid for the user that created it, preventing misuse by other users. The MaxLength attribute ensures that the database column can accommodate typical subject IDs without truncation.
    /// </summary>
    [MaxLength(200)]
    public string SubjectId { get; set; } = default!;

    /// <summary>
    /// Space-delimited list of scopes that the persisted grant is valid for. This should match the scopes that were requested during the authorization process and validated against the client's allowed scopes. The Scopes property is used to determine what permissions the access token will have when it is issued based on this persisted grant. The MaxLength attribute ensures that the database column can accommodate typical scope strings without truncation, while still allowing for a reasonable number of scopes to be included.
    /// </summary>
    [MaxLength(1000)]
    public string Scopes { get; set; } = default!;   // space-delimited
    /// <summary>
    /// The UTC date and time when the persisted grant was created. This is used to determine the age of the grant and can be useful for auditing and debugging purposes. The CreatedAt property is typically set to the current UTC time when the grant is created and should not be modified afterward. It can also be used in conjunction with the ExpiresAt property to determine if the grant has expired based on its age.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    /// <summary>
    /// The UTC date and time when the persisted grant expires. This is used to determine if the grant is still valid or if it has expired and should no longer be accepted for token issuance. The ExpiresAt property should be set based on the desired lifetime of the grant (e.g., a short lifetime for authorization codes, a longer lifetime for refresh tokens) and should be checked during validation to ensure that expired grants are rejected.
    /// </summary>
    public DateTime ExpiresAt { get; set; }
    /// <summary>
    /// Indicates whether the persisted grant has been consumed. For authorization codes, this should be set to true after the code has been exchanged for tokens, preventing it from being used again. For refresh tokens, this can be used to mark the token as consumed after it has been used to obtain new access tokens, depending on your token management strategy. The IsConsumed property should be checked during validation to ensure that consumed grants are rejected, and it can also be used for auditing and debugging purposes to track the usage of grants over time.
    /// </summary>
    public bool IsConsumed    { get; set; }
}

/// <summary>
/// Entity representing an authorization code persisted grant. Inherits common properties from PersistedGrantEntity and adds specific properties for authorization codes, such as CodeChallenge, CodeChallengeMethod, RedirectUri, Nonce, and SessionId. The CodeChallenge and CodeChallengeMethod properties are used to support PKCE (Proof Key for Code Exchange) for enhanced security in public clients. The RedirectUri property is used to validate the redirect URI during the token exchange process. The Nonce property can be used to include a unique value in the authorization request to mitigate replay attacks. The SessionId property can be used to associate the authorization code with a specific user session for additional security and auditing purposes.
/// </summary>
[Table("PulseAuth_AuthorizationCodes")]
public class AuthorizationCodeEntity : PersistedGrantEntity
{
    /// <summary>
    /// The code challenge derived from the original code verifier using the specified code challenge method (e.g., S256). This property is used to implement PKCE (Proof Key for Code Exchange) for public clients that cannot securely store a client secret. When a client initiates an authorization request with PKCE, it generates a random code verifier and derives the code challenge from it. The authorization server then stores the code challenge along with the authorization code. During the token exchange process, the client must provide the original code verifier, which the server uses to verify that it matches the stored code challenge. This mechanism helps prevent authorization code interception attacks by ensuring that only the client that initiated the request can exchange the authorization code for tokens.
    /// </summary>
    [MaxLength(512)]
    public string? CodeChallenge { get; set; }

    /// <summary>
    /// The method used to derive the code challenge from the original code verifier. Common values are "S256" for SHA-256 hashing and "plain" for no transformation (not recommended). This property is used in conjunction with the CodeChallenge property to implement PKCE (Proof Key for Code Exchange) for public clients. When a client initiates an authorization request with PKCE, it specifies the code challenge method it used to derive the code challenge. The authorization server then stores this information along with the authorization code. During the token exchange process, the server uses the specified code challenge method to verify that the provided code verifier matches the stored code challenge, ensuring that only the client that initiated the request can exchange the authorization code for tokens.
    /// </summary>
    [MaxLength(10)]
    public string? CodeChallengeMethod { get; set; }

    /// <summary>
    /// The redirect URI that was used in the authorization request. This property is used to validate the redirect URI during the token exchange process to ensure that it matches one of the registered redirect URIs for the client. This helps prevent open redirector attacks and ensures that tokens are only issued to valid redirect URIs associated with the client. The MaxLength attribute ensures that the database column can accommodate typical redirect URIs without truncation, while still allowing for a reasonable length to support various URI formats.
    /// </summary>
    [MaxLength(2000)]
    public string? RedirectUri { get; set; }

    /// <summary>
    /// A unique value included in the authorization request to mitigate replay attacks. The nonce property is typically used in OpenID Connect flows to include a random value in the authorization request that is then included in the ID token issued by the authorization server. This allows the client to verify that the ID token was issued in response to its own authorization request and not replayed by an attacker. The MaxLength attribute ensures that the database column can accommodate typical nonce values without truncation, while still allowing for a reasonable length to support various formats of nonce values (e.g., random strings, UUIDs).
    /// </summary>
    [MaxLength(200)]
    public string? Nonce { get; set; }

    /// <summary>
    /// An optional identifier for the user session associated with this authorization code. This can be used to link the authorization code to a specific user session for additional security and auditing purposes. For example, you can use the SessionId property to track which user session initiated the authorization request and ensure that the authorization code is only valid for that session. This can help prevent misuse of authorization codes across different sessions and provide better visibility into user activity. The MaxLength attribute ensures that the database column can accommodate typical session identifiers without truncation, while still allowing for a reasonable length to support various formats of session IDs (e.g., random strings, UUIDs).
    /// </summary>
    [MaxLength(200)]
    public string? SessionId { get; set; }

    /// <summary>When the user authenticated (1.4.0+); used for the ID token auth_time.</summary>
    public DateTime? AuthTime { get; set; }

    /// <summary>Authentication context class achieved by the sign-in (1.4.0+); ID token <c>acr</c>.</summary>
    [MaxLength(200)]
    public string? Acr { get; set; }
}

/// <summary>
/// Entity representing a refresh token persisted grant. Inherits common properties from PersistedGrantEntity and adds specific properties for refresh tokens, such as PreviousTokenId. The PreviousTokenId property can be used to implement token rotation by linking the current refresh token to the previous one, allowing you to invalidate the previous token when a new one is issued. This helps enhance security by ensuring that if a refresh token is compromised, it cannot be used indefinitely, as it will be invalidated once a new token is issued. The MaxLength attribute ensures that the database column can accommodate typical token identifiers without truncation, while still allowing for a reasonable length to support various formats of token IDs (e.g., random strings, UUIDs).
/// </summary>
[Table("PulseAuth_RefreshTokens")]
public class RefreshTokenEntity : PersistedGrantEntity
{
    /// <summary>
    /// An optional identifier for the previous refresh token in a token rotation scenario. This property can be used to link the current refresh token to the previous one, allowing you to implement token rotation by invalidating the previous token when a new one is issued. When a client uses a refresh token to obtain new access tokens, you can check if there is a PreviousTokenId associated with the current refresh token. If there is, you can invalidate the previous refresh token to prevent it from being used again, enhancing security by ensuring that if a refresh token is compromised, it cannot be used indefinitely. The MaxLength attribute ensures that the database column can accommodate typical token identifiers without truncation, while still allowing for a reasonable length to support various formats of token IDs (e.g., random strings, UUIDs).
    /// </summary>
    [MaxLength(256)]
    public string? PreviousTokenId { get; set; }

    /// <summary>
    /// SHA-256 of the user's security stamp when the token was issued (1.4.0+). If the stamp changes
    /// (password change, "sign out everywhere"...) the token is rejected on the next refresh.
    /// </summary>
    [MaxLength(100)]
    public string? UserStamp { get; set; }

    /// <summary>When the user originally authenticated (1.4.0+); used for the ID token auth_time.</summary>
    public DateTime? AuthTime { get; set; }
}

/// <summary>
/// A reference (opaque) access token (1.4.0+). <see cref="PersistedGrantEntity.Key"/> holds a hash of
/// the handle; <see cref="Data"/> the signed JWT returned by introspection.
/// </summary>
[Table("PulseAuth_ReferenceTokens")]
public class ReferenceTokenEntity
{
    /// <summary>Hashed handle (see GrantKeyHelper).</summary>
    [Key, MaxLength(256)]
    public string Key { get; set; } = default!;

    /// <summary>Client the token was issued to.</summary>
    [MaxLength(200)]
    public string ClientId { get; set; } = default!;

    /// <summary>Subject (user id or client id).</summary>
    [MaxLength(200)]
    public string SubjectId { get; set; } = default!;

    /// <summary>The signed JWT (unbounded text).</summary>
    public string Data { get; set; } = default!;

    /// <summary>Creation time (UTC).</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Expiration time (UTC).</summary>
    public DateTime ExpiresAt { get; set; }
}

/// <summary>A user's consent for a client (1.4.0+). One row per (SubjectId, ClientId).</summary>
[Table("PulseAuth_Consents")]
public class ConsentEntity
{
    /// <summary>Surrogate key.</summary>
    public int Id { get; set; }

    /// <summary>User id.</summary>
    [MaxLength(200)]
    public string SubjectId { get; set; } = default!;

    /// <summary>Client id.</summary>
    [MaxLength(200)]
    public string ClientId { get; set; } = default!;

    /// <summary>Granted scopes, space-delimited.</summary>
    [MaxLength(2000)]
    public string Scopes { get; set; } = default!;

    /// <summary>When the consent was given (UTC).</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Expiration (UTC); null = until revoked.</summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>False = one-time consent.</summary>
    public bool Remember { get; set; } = true;
}
