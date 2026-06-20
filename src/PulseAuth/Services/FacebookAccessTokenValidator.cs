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

        // Verify the token is for this app
        if (debugData.TryGetProperty("app_id", out var appIdEl) &&
            appIdEl.GetString() != _appId)
            return null;

        // ── Step 2: Fetch user profile ────────────────────────────────────────
        var profileUrl = $"me?fields=id,name,email,first_name,last_name,picture.type(large)&access_token={Uri.EscapeDataString(token)}";

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

    private static string? GetStr(JsonElement el, string prop)
        => el.TryGetProperty(prop, out var v) ? v.GetString() : null;
}
