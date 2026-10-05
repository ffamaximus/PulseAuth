using System.Security.Claims;
using PulseAuth.Abstractions;
using PulseAuth.Models;

namespace PulseAuth.ConformanceHost;

/// <summary>
/// Single fixed test user with every standard claim filled in, so the scope tests
/// (profile / email / phone) of the conformance suite find the claims they look for.
/// </summary>
public sealed class ConformanceUserService : IUserAuthenticationService
{
    public const string SubjectId = "conformance-user";

    private static readonly UserInfo User = new()
    {
        SubjectId           = SubjectId,
        Username            = "conformance",
        Name                = "Conformance Tester",
        GivenName           = "Conformance",
        FamilyName          = "Tester",
        MiddleName          = "Pulse",
        Nickname            = "conf",
        ProfileUrl          = "https://pulseauth.test/users/conformance",
        Picture             = "https://www.gravatar.com/avatar/00000000000000000000000000000000",
        Website             = "https://pulseauth.test",
        Gender              = "other",
        Birthdate           = "1990-01-01",
        ZoneInfo            = "America/Bogota",
        Locale              = "es-CO",
        UpdatedAt           = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        Email               = "conformance@pulseauth.test",
        EmailVerified       = true,
        PhoneNumber         = "+1 555 0100",
        PhoneNumberVerified = true,
        Address             = new UserAddress
        {
            Formatted     = "Calle 100 # 10-20\nBogotá D.C. 110111\nColombia",
            StreetAddress = "Calle 100 # 10-20",
            Locality      = "Bogotá D.C.",
            Region        = "Cundinamarca",
            PostalCode    = "110111",
            Country       = "CO",
        },
    };

    public Task<UserInfo?> ValidateCredentialsAsync(string username, string password, CancellationToken ct = default)
        => Task.FromResult<UserInfo?>(null);   // the password grant is not part of the conformance tests

    public Task<UserInfo?> GetUserByIdAsync(string subjectId, CancellationToken ct = default)
        => Task.FromResult(subjectId == SubjectId ? User : null);

    public Task<UserInfo?> FindByExternalProviderAsync(string provider, string externalId, CancellationToken ct = default)
        => Task.FromResult<UserInfo?>(null);

    public Task<UserInfo> AutoProvisionUserAsync(string provider, string externalId, IEnumerable<Claim> externalClaims, CancellationToken ct = default)
        => throw new NotSupportedException("External providers are not used by the conformance host.");
}
