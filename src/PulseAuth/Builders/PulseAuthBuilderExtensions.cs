using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http.Headers;
using System.Text.Json;
using PulseAuth.Abstractions;
using PulseAuth.Services;

namespace PulseAuth.Builders;

/// <summary>
/// External identity provider extensions for <see cref="PulseAuthBuilder"/>.
/// Each method registers the corresponding ASP.NET Core OAuth/OIDC handler.
/// </summary>
public static class PulseAuthBuilderExtensions
{
    // ── Cookie / Session ──────────────────────────────────────────────────────

    /// <summary>
    /// Adds cookie-based authentication (required as the default sign-in scheme).
    /// Call this before adding external providers.
    /// </summary>
    public static PulseAuthBuilder AddCookieAuthentication(
        this PulseAuthBuilder builder,
        Action<CookieAuthenticationOptions>? configure = null)
    {
        var auth = builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme          = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        });

        if (configure is null)
            auth.AddCookie();
        else
            auth.AddCookie(configure);

        return builder;
    }

    // ── Google ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Adds Google OAuth2 login.
    /// Requires <c>ClientId</c> and <c>ClientSecret</c> from the Google Cloud Console.
    /// </summary>
    public static PulseAuthBuilder AddGoogle(
        this PulseAuthBuilder builder,
        Action<GoogleOptions> configure)
    {
        builder.Services
            .AddAuthentication()
            .AddGoogle(configure);
        return builder;
    }

    /// <summary>
    /// Adds Google OAuth2 login with ClientId and ClientSecret shortcut.
    /// </summary>
    public static PulseAuthBuilder AddGoogle(
        this PulseAuthBuilder builder,
        string clientId,
        string clientSecret,
        Action<GoogleOptions>? configure = null)
    {
        builder.Services
            .AddAuthentication()
            .AddGoogle(opts =>
            {
                opts.ClientId     = clientId;
                opts.ClientSecret = clientSecret;
                configure?.Invoke(opts);
            });
        return builder;
    }

    // ── Facebook ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Adds Facebook OAuth2 login.
    /// Requires a Facebook App ID and secret from developers.facebook.com.
    /// </summary>
    public static PulseAuthBuilder AddFacebook(
        this PulseAuthBuilder builder,
        Action<FacebookOptions> configure)
    {
        builder.Services
            .AddAuthentication()
            .AddFacebook(configure);
        return builder;
    }

    /// <summary>Adds Facebook login with App ID and secret shortcut.</summary>
    public static PulseAuthBuilder AddFacebook(
        this PulseAuthBuilder builder,
        string appId,
        string appSecret,
        Action<FacebookOptions>? configure = null)
    {
        builder.Services
            .AddAuthentication()
            .AddFacebook(opts =>
            {
                opts.AppId     = appId;
                opts.AppSecret = appSecret;
                configure?.Invoke(opts);
            });
        return builder;
    }

    // ── Microsoft Account ─────────────────────────────────────────────────────

    /// <summary>
    /// Adds Microsoft Account (personal, work and school) OAuth2 login.
    /// Requires a Microsoft Entra ID (formerly Azure AD) app registration.
    /// </summary>
    public static PulseAuthBuilder AddMicrosoft(
        this PulseAuthBuilder builder,
        Action<MicrosoftAccountOptions> configure)
    {
        builder.Services
            .AddAuthentication()
            .AddMicrosoftAccount(configure);
        return builder;
    }

    /// <summary>Adds Microsoft login with client ID and secret shortcut.</summary>
    public static PulseAuthBuilder AddMicrosoft(
        this PulseAuthBuilder builder,
        string clientId,
        string clientSecret,
        Action<MicrosoftAccountOptions>? configure = null)
    {
        builder.Services
            .AddAuthentication()
            .AddMicrosoftAccount(opts =>
            {
                opts.ClientId     = clientId;
                opts.ClientSecret = clientSecret;
                configure?.Invoke(opts);
            });
        return builder;
    }

    // ── GitHub ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Adds GitHub OAuth2 login.
    /// Requires a GitHub OAuth App client ID and secret from github.com/settings/developers.
    /// </summary>
    public static PulseAuthBuilder AddGitHub(
        this PulseAuthBuilder builder,
        string clientId,
        string clientSecret,
        Action<OAuthOptions>? configure = null)
    {
        builder.Services
            .AddAuthentication()
            .AddOAuth("GitHub", opts =>
            {
                opts.ClientId              = clientId;
                opts.ClientSecret          = clientSecret;
                opts.CallbackPath          = "/signin-github";
                opts.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                opts.TokenEndpoint         = "https://github.com/login/oauth/access_token";
                opts.UserInformationEndpoint = "https://api.github.com/user";
                opts.SaveTokens            = true;
                opts.Scope.Add("user:email");

                opts.ClaimActions.MapJsonKey(System.Security.Claims.ClaimTypes.NameIdentifier, "id");
                opts.ClaimActions.MapJsonKey(System.Security.Claims.ClaimTypes.Name,           "login");
                opts.ClaimActions.MapJsonKey(System.Security.Claims.ClaimTypes.Email,          "email");
                opts.ClaimActions.MapJsonKey("picture",                                         "avatar_url");
                opts.ClaimActions.MapJsonKey("urn:github:name",                                 "name");
                opts.ClaimActions.MapJsonKey("urn:github:url",                                  "html_url");

                opts.Events.OnCreatingTicket = async context =>
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    request.Headers.UserAgent.ParseAdd("PulseAuth");

                    var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                    response.EnsureSuccessStatusCode();

                    var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    context.RunClaimActions(payload.RootElement);
                };

                configure?.Invoke(opts);
            });
        return builder;
    }

    // ── Social Token Exchange (pure API / SPA SDK flows) ─────────────────────

    /// <summary>
    /// Enables the <c>urn:ietf:params:oauth:grant-type:google_id_token</c> grant.
    /// React/Angular SPAs can use the Google Sign-In SDK, obtain a Google ID token,
    /// and exchange it for PulseAuth tokens via <c>POST /connect/token</c>.
    /// </summary>
    /// <param name="builder">The PulseAuth builder.</param>
    /// <param name="googleClientId">
    /// The Google OAuth2 client ID (from Google Cloud Console → Credentials).
    /// Must match the <c>aud</c> claim of the incoming Google ID token.
    /// </param>
    public static PulseAuthBuilder AddGoogleTokenExchange(
        this PulseAuthBuilder builder,
        string googleClientId)
    {
        builder.Services.AddSingleton<IExternalTokenValidator>(
            _ => new GoogleIdTokenValidator(googleClientId));
        return builder;
    }

    /// <summary>
    /// Enables the <c>urn:ietf:params:oauth:grant-type:facebook_access_token</c> grant.
    /// React/Angular SPAs can use the Facebook Login SDK, obtain a Facebook access token,
    /// and exchange it for PulseAuth tokens via <c>POST /connect/token</c>.
    /// </summary>
    /// <param name="builder">The PulseAuth builder.</param>
    /// <param name="appId">Facebook App ID (from developers.facebook.com).</param>
    /// <param name="appSecret">Facebook App Secret. Used to verify tokens via the debug_token endpoint.</param>
    public static PulseAuthBuilder AddFacebookTokenExchange(
        this PulseAuthBuilder builder,
        string appId,
        string appSecret)
    {
        builder.Services.AddSingleton<IExternalTokenValidator>(
            sp => new FacebookAccessTokenValidator(
                appId, appSecret,
                sp.GetRequiredService<IHttpClientFactory>()));
        return builder;
    }

    // ── Generic OAuth2 ────────────────────────────────────────────────────────

    /// <summary>
    /// Adds any generic OAuth2 provider (Twitter/X, LinkedIn, Apple, etc.).
    /// </summary>
    public static PulseAuthBuilder AddOAuthProvider(
        this PulseAuthBuilder builder,
        string schemeName,
        Action<OAuthOptions> configure)
    {
        builder.Services
            .AddAuthentication()
            .AddOAuth(schemeName, configure);
        return builder;
    }
}
