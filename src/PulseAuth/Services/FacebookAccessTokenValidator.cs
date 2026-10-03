using System.Text.Json;
using PulseAuth.Abstractions;
using PulseAuth.Constants;

namespace PulseAuth.Services;

/// <summary>
/// Validates Facebook access tokens (obtained via the Facebook Login JS SDK).
/// Uses the Facebook Graph API to verify the token belongs to this app and fetch the user profile.
/// Registered via <c>builder.AddFacebookTokenExchange(appId, appSecret)</c>.
/// </summary>
public sealed class FacebookAccessTokenValidator : IExternalTokenValidator
{
    private readonly string _appId;
    private readonly string _appSecret;
    private readonly IHttpClientFactory _httpClientFactory;

    /// <inheritdoc />
    public string ProviderName => "Facebook";

    /// <inheritdoc />
    public string SupportedGrantType => GrantTypes.FacebookAccessToken;

    /// <summary>
    /// Initializes the validator with the Facebook App ID, App Secret, and an HTTP client factory.
    /// The App Secret is used to construct the app-level access token for the debug_token endpoint.
    /// </summary>
    public FacebookAccessTokenValidator(
        string appId,
        string appSecret,
        IHttpClientFactory httpClientFactory)
    {
        _appId             = appId;
        _appSecret         = appSecret;
        _httpClientFactory = httpClientFactory;
    }

    /// <inheritdoc />
    public async Task<ExternalIdentity?> ValidateAsync(string token, CancellationToken ct = default)
    {
        var http = _httpClientFactory.CreateClient("PulseAuth.Facebook");
        http.BaseAddress ??= new Uri("https://graph.facebook.com/");

        // ── Step 1: Verify token is valid and belongs to our app ─────────────
        var appToken   = $"{_appId}|{_appSecret}";
        var debugUrl   = $"debug_token?input_token={Uri.EscapeDataString(token)}&access_token={Uri.EscapeDataString(appToken)}";

        JsonElement debugData;
        try
        {
            var debugResponse = await http.GetAsync(debugUrl, ct);
            if (!debugResponse.IsSuccessStatusCode) return null;

            var debugJson = JsonDocument.Parse(await debugResponse.Content.ReadAsStringAsync(ct));
            debugData = debugJson.RootElement.GetProperty("data");
        }
        catch
        {
            return null;
        }

        if (!debugData.TryGetProperty("is_valid", out var isValidEl) || !isValidEl.GetBoolean())
            return null;

        // Verify the token was issued to THIS app. app_id is mandatory: a missing value must
        // never be treated as a match (otherwise tokens issued to other apps would be accepted).
        if (!debugData.TryGetProperty("app_id", out var appIdEl) ||
            appIdEl.ValueKind != JsonValueKind.String ||
            !string.Equals(appIdEl.GetString(), _appId, StringComparison.Ordinal))
            return null;

        // The debugged token must be a user token that has not expired.
        if (debugData.TryGetProperty("type", out var typeEl) &&
            typeEl.ValueKind == JsonValueKind.String &&
            !string.Equals(typeEl.GetString(), "USER", StringComparison.OrdinalIgnoreCase))
            return null;

        if (debugData.TryGetProperty("expires_at", out var expEl) &&
            expEl.ValueKind == JsonValueKind.Number &&
            expEl.TryGetInt64(out var expiresAt) && expiresAt > 0 &&
            DateTimeOffset.FromUnixTimeSeconds(expiresAt) <= DateTimeOffset.UtcNow)
            return null;

        // ── Step 2: Fetch user profile ────────────────────────────────────────
        // appsecret_proof proves the call comes from the app's server (recommended by Meta,
        // and required when "Require App Secret" is enabled for the app).
        var proof      = ComputeAppSecretProof(token, _appSecret);
        var profileUrl = $"me?fields=id,name,email,first_name,last_name,picture.type(large)&access_token={Uri.EscapeDataString(token)}&appsecret_proof={proof}";

        JsonElement profile;
        try
        {
            var profileResponse = await http.GetAsync(profileUrl, ct);
            if (!profileResponse.IsSuccessStatusCode) return null;

            profile = JsonDocument.Parse(await profileResponse.Content.ReadAsStringAsync(ct)).RootElement;
        }
        catch
        {
            return null;
        }

        if (!profile.TryGetProperty("id", out var idEl))
            return null;

        var id = idEl.GetString();
        if (string.IsNullOrEmpty(id)) return null;

        // The profile must belong to the user the token was issued to.
        if (debugData.TryGetProperty("user_id", out var userIdEl) &&
            userIdEl.ValueKind == JsonValueKind.String &&
            !string.Equals(userIdEl.GetString(), id, StringComparison.Ordinal))
            return null;

        // Extract picture URL (nested: picture → data → url)
        string? pictureUrl = null;
        if (profile.TryGetProperty("picture", out var picEl) &&
            picEl.TryGetProperty("data", out var picData) &&
            picData.TryGetProperty("url", out var picUrl))
        {
            pictureUrl = picUrl.GetString();
        }

        return new ExternalIdentity(
            SubjectId:  id,
            Email:      GetStr(profile, "email"),
            Name:       GetStr(profile, "name"),
            GivenName:  GetStr(profile, "first_name"),
            FamilyName: GetStr(profile, "last_name"),
            Picture:    pictureUrl);
    }

    private static string ComputeAppSecretProof(string accessToken, string appSecret)
    {
        var hash = System.Security.Cryptography.HMACSHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(appSecret),
            System.Text.Encoding.UTF8.GetBytes(accessToken));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? GetStr(JsonElement el, string prop)
        => el.TryGetProperty(prop, out var v) ? v.GetString() : null;
}
