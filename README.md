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
- **Resource Owner Password** — direct username/password login (ideal for React/Angular SPAs that own their own login UI)
- **Google ID Token exchange** — accept a Google-issued ID token from the frontend SDK and return PulseAuth tokens
- **Facebook Access Token exchange** — accept a Facebook access token from the frontend SDK and return PulseAuth tokens

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
dotnet add package PulseAuth.EntityFramework

# MariaDB / MySQL provider (recommended: Pomelo)
dotnet add package Pomelo.EntityFrameworkCore.MySql
```

### 2. `appsettings.json`

```json
{
  "ConnectionStrings": {
    "Default": "Server=localhost;Port=3306;Database=myauth;User=root;Password=secret;"
  },
  "PulseAuth": {
    "Issuer": "https://auth.myapp.com"
  },
  "Auth": {
    "Google":   { "ClientId": "", "ClientSecret": "" },
    "Facebook": { "AppId":    "", "AppSecret":    "" }
  }
}
```

### 3. Configure `Program.cs`

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PulseAuth.Builders;
using PulseAuth.Constants;
using PulseAuth.Extensions;
using PulseAuth.Helpers;
using PulseAuth.Models;

var builder = WebApplication.CreateBuilder(args);
var conn    = builder.Configuration.GetConnectionString("Default")!;

// ── MariaDB server version (auto-detect or pin explicitly) ───────────────────
var serverVersion = ServerVersion.AutoDetect(conn);
// Or pin it:  new MariaDbServerVersion(new Version(10, 11));

// ── ASP.NET Core Identity (users & roles) ────────────────────────────────────
builder.Services
    .AddDbContext<ApplicationDbContext>(opts =>
        opts.UseMySql(conn, serverVersion))
    .AddIdentity<ApplicationUser, IdentityRole>(opts =>
    {
        opts.Password.RequiredLength  = 8;
        opts.Password.RequireDigit    = true;
        opts.SignIn.RequireConfirmedAccount = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// ── PulseAuth ─────────────────────────────────────────────────────────────────
var pulse = builder.Services.AddPulseAuth(opts =>
{
    opts.Issuer              = builder.Configuration["PulseAuth:Issuer"]!;
    opts.RotateRefreshTokens = true;
});

pulse
    .AddDeveloperSigningCredential()          // swap for persistent key in prod
    .AddEntityFrameworkStores(opts =>         // clients, codes and tokens in MariaDB
        opts.UseMySql(conn, serverVersion))
    .AddIdentityUsers<ApplicationUser>()
    // ── Social token exchange (pure API — no redirect pages required) ────────
    .AddGoogleTokenExchange(
        builder.Configuration["Auth:Google:ClientId"]!)
    .AddFacebookTokenExchange(
        builder.Configuration["Auth:Facebook:AppId"]!,
        builder.Configuration["Auth:Facebook:AppSecret"]!)
    // ── Clients ──────────────────────────────────────────────────────────────
    .AddInMemoryClients(
    [
        // React / Angular SPA — password grant + social exchange + refresh
        new Client
        {
            ClientId           = "my-spa",
            ClientName         = "My SPA",
            AllowedGrantTypes  =
            [
                GrantTypes.Password,
                GrantTypes.GoogleIdToken,
                GrantTypes.FacebookAccessToken,
                GrantTypes.RefreshToken,
            ],
            AllowOfflineAccess = true,
            AllowedScopes      = [StandardScopes.OpenId, StandardScopes.Profile,
                                   StandardScopes.Email, StandardScopes.OfflineAccess, "api"],
        },
        // Backend microservice — client credentials
        new Client
        {
            ClientId          = "my-api",
            ClientName        = "Backend API",
            ClientSecretHash  = ClientSecretHelper.HashSecret("change-me-in-prod"),
            AllowedGrantTypes = GrantTypes.ClientCredentialsOnly,
            AllowedScopes     = ["api"],
        },
    ]);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapPulseAuth();

app.Run();
```

### 4. Apply migrations

Two contexts: one for Identity, one for PulseAuth stores.

```bash
# Identity tables (AspNetUsers, AspNetRoles, etc.)
dotnet ef migrations add InitIdentity  --context ApplicationDbContext
dotnet ef database update              --context ApplicationDbContext

# PulseAuth tables (PulseAuth_Clients, PulseAuth_AuthCodes, etc.)
dotnet ef migrations add InitPulseAuth --context PulseAuthDbContext
dotnet ef database update              --context PulseAuthDbContext
```

> **Tip:** you can share the same MariaDB database for both contexts; the table prefixes (`AspNet_*` vs `PulseAuth_*`) prevent collisions.

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

## React / Angular SPA — pure API mode

If your frontend is a React or Angular SPA and you want to keep **all UI in the frontend** (no server-rendered login pages), configure PulseAuth in pure API mode:

### Email/password login

Enable the `password` grant on your client and call `/connect/token` directly from the SPA:

```csharp
// Auth server Program.cs
var client = new Client
{
    ClientId          = "mundoecoa-spa",
    AllowedGrantTypes = [GrantTypes.Password, GrantTypes.RefreshToken],
    AllowOfflineAccess = true,
    AllowedScopes     = [StandardScopes.OpenId, StandardScopes.Profile,
                          StandardScopes.Email, StandardScopes.OfflineAccess, "api"],
};
```

```typescript
// React / TypeScript
const tokens = await fetch('https://auth.myapp.com/connect/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'password',
    client_id:  'mundoecoa-spa',
    username:   email,
    password:   password,
    scope:      'openid profile email offline_access api',
  }),
}).then(r => r.json());
// tokens.access_token, tokens.refresh_token, tokens.id_token
```

### Google Sign-In (SDK → token exchange)

1. Add the exchange on the auth server:

```csharp
builder.Services
    .AddPulseAuth(...)
    .AddGoogleTokenExchange(googleClientId: "123-xxx.apps.googleusercontent.com");
```

2. Enable the grant type on the client:

```csharp
AllowedGrantTypes = [GrantTypes.Password, GrantTypes.GoogleIdToken, GrantTypes.RefreshToken],
```

3. From React (using `@react-oauth/google` or similar):

```typescript
// After Google Sign-In returns credential (ID token)
const tokens = await fetch('https://auth.myapp.com/connect/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:google_id_token',
    client_id:  'mundoecoa-spa',
    token:      googleCredential,   // from useGoogleLogin / CredentialResponse
    scope:      'openid profile email offline_access api',
  }),
}).then(r => r.json());
```

### Facebook Login (SDK → token exchange)

1. Add the exchange on the auth server:

```csharp
builder.Services
    .AddPulseAuth(...)
    .AddFacebookTokenExchange(appId: "123456789", appSecret: "your-secret");
```

2. Enable the grant type on the client:

```csharp
AllowedGrantTypes = [GrantTypes.Password, GrantTypes.FacebookAccessToken, GrantTypes.RefreshToken],
```

3. From React (using `react-facebook-login` or the JS SDK):

```typescript
// After FB.login() returns authResponse.accessToken
const tokens = await fetch('https://auth.myapp.com/connect/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:facebook_access_token',
    client_id:  'mundoecoa-spa',
    token:      fbAccessToken,
    scope:      'openid profile email offline_access api',
  }),
}).then(r => r.json());
```

### Validating tokens in other microservices

Any microservice in your ecosystem can validate PulseAuth tokens using standard JWT Bearer authentication — no package dependency required:

```csharp
// In any ASP.NET Core microservice
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        // Auth server URL — tokens are validated against its JWKS automatically
        opts.Authority = "https://auth.myapp.com";
        opts.Audience  = "mundoecoa-spa";   // or your client_id
        opts.RequireHttpsMetadata = false;  // only in dev
    });
```

The microservice downloads the public keys from `https://auth.myapp.com/.well-known/jwks` and caches them. No shared secrets, no extra packages beyond `Microsoft.AspNetCore.Authentication.JwtBearer`.

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