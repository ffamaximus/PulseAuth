![PulseAuth Banner](https://raw.githubusercontent.com/ffamaximus/PulseAuth/refs/heads/main/banner.png)
# PulseAuth

**Free, open-source OAuth2 / OpenID Connect authorization server for ASP.NET Core.**

PulseAuth is a lightweight alternative to Duende IdentityServer (formerly IdentityServer4) designed to be accessible, free, and easy to set up. It implements the core OAuth2 and OIDC flows on top of ASP.NET Core minimal APIs and integrates natively with ASP.NET Core Identity.

---

## Packages

| Package | Description |
|---|---|
| `PulseAuth` | Core OAuth2/OIDC server — endpoints, token service, in-memory stores |
| `PulseAuth.Identity` | Connects PulseAuth to ASP.NET Core Identity (`UserManager`, `SignInManager`) |
| `PulseAuth.EntityFramework` | EF Core persistent stores (clients, codes, refresh tokens) |

---

## Supported flows

- **Authorization Code + PKCE** — secure for web apps, SPAs and mobile
- **Client Credentials** — service-to-service authentication
- **Refresh Token** — with optional rotation
- **Resource Owner Password** — legacy, disabled by default per OAuth 2.1

## OIDC endpoints

| Endpoint | URL |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks` |
| Authorize | `/connect/authorize` |
| Token | `/connect/token` |
| UserInfo | `/connect/userinfo` |
| Revocation | `/connect/revocation` |
| End Session | `/connect/endsession` |

---

## Quick start

### 1. Install

```bash
dotnet add package PulseAuth
dotnet add package PulseAuth.Identity
dotnet add package PulseAuth.EntityFramework   # optional, for production
```

### 2. Configure `Program.cs`

```csharp
using PulseAuth.Constants;
using PulseAuth.Extensions;
using PulseAuth.Builders;
using PulseAuth.Helpers;
using PulseAuth.Models;

var builder = WebApplication.CreateBuilder(args);

// ── ASP.NET Core Identity ────────────────────────────────────────────────────
builder.Services
    .AddDbContext<ApplicationDbContext>(opts =>
        opts.UseSqlServer(builder.Configuration.GetConnectionString("Default")))
    .AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

// ── PulseAuth ────────────────────────────────────────────────────────────────
builder.Services
    .AddPulseAuth(opts =>
    {
        opts.Issuer    = "https://auth.myapp.com";
        opts.LoginPath = "/Account/Login";
    })
    // Signing key — use AddDeveloperSigningCredential() for dev,
    // replace with a persistent key service for production
    .AddDeveloperSigningCredential()
    // In-memory clients — swap for .AddEntityFrameworkStores() in production
    .AddInMemoryClients(new[]
    {
        new Client
        {
            ClientId          = "my-spa",
            ClientName        = "My SPA",
            AllowedGrantTypes = GrantTypes.Code,
            RequirePkce       = true,
            AllowOfflineAccess = true,
            RedirectUris      = ["https://myapp.com/callback"],
            PostLogoutRedirectUris = ["https://myapp.com/"],
            AllowedScopes     = ["openid", "profile", "email", "offline_access"],
        },
        new Client
        {
            ClientId          = "api-service",
            ClientName        = "Backend API",
            ClientSecretHash  = ClientSecretHelper.HashSecret("super-secret"),
            AllowedGrantTypes = GrantTypes.ClientCredentialsOnly,
            AllowedScopes     = ["api"],
        },
    })
    // Connect to ASP.NET Core Identity for user management
    .AddIdentityUsers<ApplicationUser>()
    // Cookie auth for the interactive session
    .AddCookieAuthentication();

// ── External providers (optional) ────────────────────────────────────────────
builder.Services
    .AddPulseAuth()   // returns the existing builder
    .AddGoogle(
        clientId:     builder.Configuration["Auth:Google:ClientId"]!,
        clientSecret: builder.Configuration["Auth:Google:ClientSecret"]!)
    .AddFacebook(
        appId:     builder.Configuration["Auth:Facebook:AppId"]!,
        appSecret: builder.Configuration["Auth:Facebook:AppSecret"]!)
    .AddGitHub(
        clientId:     builder.Configuration["Auth:GitHub:ClientId"]!,
        clientSecret: builder.Configuration["Auth:GitHub:ClientSecret"]!)
    .AddMicrosoft(
        clientId:     builder.Configuration["Auth:Microsoft:ClientId"]!,
        clientSecret: builder.Configuration["Auth:Microsoft:ClientSecret"]!);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Map all PulseAuth endpoints
app.MapPulseAuth();

app.Run();
```

### 3. (Production) Switch to persistent stores

```csharp
builder.Services
    .AddPulseAuth(opts => opts.Issuer = "https://auth.myapp.com")
    .AddEntityFrameworkStores(opts =>
        opts.UseSqlServer(builder.Configuration.GetConnectionString("Default")))
    .AddIdentityUsers<ApplicationUser>();
```

Apply migrations:
```bash
dotnet ef migrations add InitPulseAuth --context PulseAuthDbContext
dotnet ef database update
```

---

## Hashing client secrets

Never store plaintext secrets. Use the helper:

```csharp
var (plain, hash) = ClientSecretHelper.GenerateAndHash();
Console.WriteLine($"Secret: {plain}");   // share this with the client
Console.WriteLine($"Hash:   {hash}");    // store this in the DB

// Or hash an existing secret:
string hash = ClientSecretHelper.HashSecret("my-secret");
```

---

## Custom user store

Implement `IUserAuthenticationService` to use any user database:

```csharp
public class MyUserService : IUserAuthenticationService
{
    public Task<UserInfo?> ValidateCredentialsAsync(string user, string pass, CancellationToken ct) { ... }
    public Task<UserInfo?> GetUserByIdAsync(string subjectId, CancellationToken ct) { ... }
    public Task<UserInfo?> FindByExternalProviderAsync(string provider, string externalId, CancellationToken ct) { ... }
    public Task<UserInfo>  AutoProvisionUserAsync(string provider, string externalId, IEnumerable<Claim> claims, CancellationToken ct) { ... }
}

// Register:
builder.Services
    .AddPulseAuth(...)
    .AddUserAuthentication<MyUserService>();
```

---

## Login page

PulseAuth redirects to `LoginPath` (default `/Account/Login`) when the user is not authenticated. Your login page must sign the user in using ASP.NET Core Identity and then redirect back to the `returnUrl` parameter.

```csharp
// Example Razor Page
public class LoginModel : PageModel
{
    public async Task<IActionResult> OnPostAsync(string returnUrl = "/")
    {
        var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, false, false);
        if (result.Succeeded)
            return LocalRedirect(returnUrl);

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return Page();
    }
}
```

---

## External provider callback

After a social login, redirect the user back to the authorize endpoint:

```csharp
// /Account/ExternalLoginCallback
public async Task<IActionResult> Callback(string returnUrl = "/")
{
    var info = await _signInManager.GetExternalLoginInfoAsync();
    
    // Find or auto-provision the user
    var user = await _pulseAuthUsers.FindByExternalProviderAsync(info.LoginProvider, info.ProviderKey)
            ?? await _pulseAuthUsers.AutoProvisionUserAsync(
                info.LoginProvider, info.ProviderKey, info.Principal.Claims);

    await _signInManager.SignInAsync(identityUser, isPersistent: false);
    return LocalRedirect(returnUrl);
}
```

---

## 💖 Support

This project is developed and maintained by **Andrés Mariño**. If you find this library useful, consider supporting its continued development:

- **Bitcoin (BTC):** `bc1p9zqgxghkjhauruhsza9n382e6kp5tpj4xtzu2csv4mypsdtdc4tqvdyg86`
- **Ko-fi:** [![Support Me](https://img.shields.io/badge/Ko--fi-Support%20Me-red?style=flat-square&logo=ko-fi)](https://ko-fi.com/andresdev21)

---

## 📝 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

Made with ❤️ for the .NET community