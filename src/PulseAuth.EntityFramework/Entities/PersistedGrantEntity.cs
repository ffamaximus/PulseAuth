using System.ComponentModel.DataAnnotations;

namespace PulseAuth.EntityFramework.Entities;

public abstract class PersistedGrantEntity
{
    [Key, MaxLength(256)]
    public string Key { get; set; } = default!;

    [MaxLength(200)]
    public string ClientId { get; set; } = default!;

    [MaxLength(200)]
    public string SubjectId { get; set; } = default!;

    [MaxLength(1000)]
    public string Scopes { get; set; } = default!;   // space-delimited

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public bool IsConsumed    { get; set; }
}

public class AuthorizationCodeEntity : PersistedGrantEntity
{
    [MaxLength(512)]
    public string? CodeChallenge { get; set; }

    [MaxLength(10)]
    public string? CodeChallengeMethod { get; set; }

    [MaxLength(2000)]
    public string? RedirectUri { get; set; }

    [MaxLength(200)]
    public string? Nonce { get; set; }

    [MaxLength(200)]
    public string? SessionId { get; set; }
}

public class RefreshTokenEntity : PersistedGrantEntity
{
    [MaxLength(256)]
    public string? PreviousTokenId { get; set; }
}
