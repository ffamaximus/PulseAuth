![PulseAuth Banner](https://raw.githubusercontent.com/ffamaximus/PulseAuth/refs/heads/main/banner.png)

# PulseAuth

**Free, open-source OAuth2 / OpenID Connect authorization server for ASP.NET Core.**

PulseAuth is a lightweight alternative to Duende IdentityServer designed to be accessible, free, and easy to set up. It implements the core OAuth2 and OIDC flows on top of ASP.NET Core minimal APIs and integrates natively with ASP.NET Core Identity.

---

## Packages

| Package | Description |
|---|---|
| `PulseAuth` | Core OAuth2/OIDC server — endpoints, token service, in-memory stores |
| `PulseAuth.Identity` | Connects PulseAuth to ASP.NET Core Identity (`UserManager`, `SignInManager`) |
| `PulseAuth.EntityFramework` | EF Core persistent stores (clients, codes, refresh tokens) |

> Each package targets **net8.0**, **net9.0** and **net10.0**.

---

## Supported flows

- **Authorization Code + PKCE** — secure for web apps, SPAs and mobile
- **Client Credentials** — service-to-service authentication
- **Refresh Token** — with optional rotation
- **Resource Owner Password** — direct username/password login (ideal for React/Angular SPAs that own their login UI)
- **Google ID Token exchange** — accept a Google-issued ID token from the frontend SDK and return PulseAuth tokens
- **Facebook Access Token exchange** — accept a Facebook access token and return PulseAuth tokens

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

### 1. Install packages

```bash
dotnet add package PulseAuth
dotnet add package PulseAuth.Identity
dotnet add package PulseAuth.EntityFramework

# Database provider — Pomelo for MariaDB/MySQL (recommended)
dotnet add package Pomelo.EntityFrameworkCore.MySql

# Or for SQL Server:
# dotnet add package Microsoft.EntityFrameworkCore.SqlServer

# EF Core CLI tools (if not already installed)
dotnet tool install --global dotnet-ef
```

> **MariaDB users:** use **Pomelo** (`Pomelo.EntityFrameworkCore.MySql`), not Oracle's `MySql.EntityFrameworkCore`. Oracle's connector has known incompatibilities with MariaDB's `information_schema` that cause runtime errors. See [Troubleshooting](#troubleshooting) for details.

---

### 2. `appsettings.json`

```json
{
  "ConnectionStrings": {
    "AuthDb": "Server=localhost;Port=3306;Database=myauth;User=root;Password=secret;"
  },
  "PulseAuth": {
    "Issuer": "https://auth.myapp.com"
  },
  "Auth": {
    "Google":   { "ClientId": "" },
    "Facebook": { "AppId": "", "AppSecret": "" }
  }
}
```

---

### 3. Choose a context strategy

PulseAuth supports three patterns. Pick the one that fits your app:

#### Option A — Single migration for Identity + PulseAuth (recommended)

Inherit `PulseAuthIdentityDbContext<TUser>`. One migration creates **both** `AspNet*` (Identity) and `PulseAuth_*` tables in the same database. No double-context confusion.

```csharp
// Infrastructure/Contexts/AuthDbContext.cs
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PulseAuth.EntityFramework.DbContexts;

public class AuthDbContext : PulseAuthIdentityDbContext<IdentityUser>
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

    // Add your own application DbSets here if needed
}
```

Then in `Program.cs`:

```csharp
// Identity registers its stores via AuthDbContext
builder.Services
    .AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// PulseAuth reads the same context that Identity already registered
builder.Services.AddPulseAuth(...)
    .AddEntityFrameworkStoresWithIdentity<AuthDbContext>();
```

> `AddEntityFrameworkStoresWithIdentity<TContext>` does **not** re-register the DbContext — it only resolves `TContext` from DI (which Identity already registered) and wires up the PulseAuth stores.

#### Option B — PulseAuth tables only (inherit PulseAuthDbContext)

Inherit `PulseAuthDbContext` if you don't use ASP.NET Core Identity or you want Identity in a separate context.

```csharp
public class AppDbContext : PulseAuthDbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<Order> Orders { get; set; } = default!;
}
```

#### Option C — Fully standalone

Use `PulseAuthDbContext` directly. Identity and PulseAuth each use their own context (can be the same or different databases).

---

### 4. `Program.cs` — Option A (recommended)

> **Important:** all `builder.Services` calls must come **before** `builder.Build()`.

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PulseAuth.Constants;
using PulseAuth.EntityFramework.Extensions;
using PulseAuth.Extensions;
using PulseAuth.Identity.Extensions;
using PulseAuth.Models;

var builder = WebApplication.CreateBuilder(args);
var conn = builder.Configuration.GetConnectionString("AuthDb")!;

// ── ASP.NET Core Identity ─────────────────────────────────────────────────────
// Identity registers AuthDbContext in DI and configures its own stores.
builder.Services
    .AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// Register AuthDbContext with EF Core (must come after AddIdentity, before Build)
builder.Services.AddDbContext<AuthDbContext>(opts =>
    opts.UseMySql(conn, new MariaDbServerVersion(new Version(10, 11, 0))));

// ── PulseAuth ─────────────────────────────────────────────────────────────────
builder.Services
    .AddPulseAuth(opts =>
    {
        opts.Issuer = builder.Configuration["PulseAuth:Issuer"]!;
        opts.RotateRefreshTokens = true;
    })
    .AddDeveloperSigningCredential()          // dev only — use AddSigningCredential(...) in prod (see "Signing keys")
    .AddIdentityUsers<IdentityUser>()
    // Reuses the AuthDbContext already registered above by Identity
    .AddEntityFrameworkStoresWithIdentity<AuthDbContext>()
    .AddInMemoryClients(
    [
        new Client
        {
            ClientId          = "my-spa",
            AllowedGrantTypes = [GrantTypes.Password, GrantTypes.RefreshToken,
                                  GrantTypes.GoogleIdToken, GrantTypes.FacebookAccessToken],
            AllowOfflineAccess = true,
            AllowedScopes      = ["openid", "profile", "email", "offline_access", "api"],
        },
        new Client
        {
            ClientId          = "my-api",
            ClientSecretHash  = ClientSecretHelper.HashSecret("change-in-prod"),
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

---

### 5. Migrations

PulseAuth.EntityFramework ships **without** an embedded database provider — migrations are generated from your startup project so the SQL matches your actual provider (MariaDB, SQL Server, PostgreSQL, etc.).

#### 5.1 Create a design-time factory

Add this file to your startup project. It lets `dotnet ef` instantiate the context without booting your full app:

```csharp
// Infrastructure/Factories/AuthDbContextFactory.cs  (Option A — PulseAuthIdentityDbContext)
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

public class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        // Use a hardcoded dev connection string — AutoDetect requires a live server.
        var cs = Environment.GetEnvironmentVariable("DESIGN_CONNECTION")
                 ?? "Server=localhost;Port=3306;Database=myauth_dev;" +
                    "User Id=root;Password=secret;";

        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseMySql(cs, new MariaDbServerVersion(new Version(10, 11, 0)))
            // For MySQL:      new MySqlServerVersion(new Version(8, 0, 0))
            // For SQL Server: .UseSqlServer(cs)
            .Options;

        return new AuthDbContext(options);
    }
}
```

> **Why `new MariaDbServerVersion(...)` instead of `ServerVersion.AutoDetect`?**
> `AutoDetect` opens a real connection to detect the version. In design-time (CI, fresh machines) the server may not be available. A hardcoded version avoids this and is safe — it only affects how EF generates the SQL dialect, not the runtime behavior.

#### 5.2 Run migrations

```bash
# From your startup project directory:

# Option A — PulseAuthIdentityDbContext (single migration for ALL tables)
dotnet ef migrations add Init --context AuthDbContext --output-dir Migrations
dotnet ef database update --context AuthDbContext

# Option B/C — separate contexts (one migration per context)
dotnet ef migrations add InitIdentity  --context ApplicationDbContext --output-dir Migrations/Identity
dotnet ef migrations add InitPulseAuth --context PulseAuthDbContext   --output-dir Migrations/PulseAuth

dotnet ef database update --context ApplicationDbContext
dotnet ef database update --context PulseAuthDbContext
```

> **Option A creates both `AspNet*` and `PulseAuth_*` tables in a single `dotnet ef database update`.** The table prefixes prevent naming collisions even in the same database.

---

## Hashing client secrets

Never store plaintext secrets. Use the helper:

```csharp
var (plain, hash) = ClientSecretHelper.GenerateAndHash();
Console.WriteLine($"Secret: {plain}");   // share with the client
Console.WriteLine($"Hash:   {hash}");    // store in DB / config

// Or hash an existing value:
string hash = ClientSecretHelper.HashSecret("my-secret");
```

---

## Signing keys

All instances of the authorization server **must sign with the same key**, otherwise tokens
become invalid after a restart and do not validate across instances.

### Development

```csharp
.AddDeveloperSigningCredential()                       // persisted to ./pulseauth-tempkey.pem
.AddDeveloperSigningCredential(filename: "keys/dev.pem")
.AddDeveloperSigningCredential(persistKey: false)      // in-memory, regenerated on every start
```

The developer key is created once and stored **unencrypted**. If the path is not writable
(e.g. a read-only container file system) PulseAuth logs a warning and falls back to an in-memory key
instead of failing at startup. An existing but corrupt key file is an error. Add it to `.gitignore`:

```gitignore
pulseauth-tempkey.pem
```

### Production

```csharp
// X.509 certificate with private key (RSA or ECDSA) — kid = certificate thumbprint
var cert = X509CertificateLoader.LoadPkcs12FromFile("signing.pfx", password);   // .NET 9+
// var cert = new X509Certificate2("signing.pfx", password);                     // .NET 8
builder.Services.AddPulseAuth(...)
    .AddSigningCredential(cert);

// Or any RSA / ECDSA key (e.g. loaded from Azure Key Vault, AWS Secrets Manager, a PEM file)
var rsa = RSA.Create();
rsa.ImportFromPem(pemFromVault);
builder.Services.AddPulseAuth(...)
    .AddSigningCredential(new RsaSecurityKey(rsa));            // RS256, kid = RFC 7638 thumbprint
```

### Key rotation

`AddValidationKey(...)` publishes an extra public key in the JWKS and accepts it when validating
tokens, without signing with it:

1. Publish the **new** key as validation key and deploy. Wait at least one access-token lifetime
   so resource servers refresh their JWKS cache.
2. Promote the new key to signing key and keep the **old** one as validation key.
3. When every token signed with the old key has expired, remove it.

```csharp
.AddSigningCredential(newCert)
.AddValidationKey(oldCert)   // public key only — no private key required
```

For fully automatic rotation, implement `IKeyMaterialService` and register it with
`AddKeyMaterialService<T>()`.

---

## React / Angular SPA — pure API mode

Keep all UI in the frontend. PulseAuth exposes a REST token endpoint — no Razor pages required.

### Email/password login

```csharp
// Client config
new Client
{
    ClientId          = "my-spa",
    AllowedGrantTypes = [GrantTypes.Password, GrantTypes.RefreshToken],
    AllowOfflineAccess = true,
    AllowedScopes     = ["openid", "profile", "email", "offline_access", "api"],
}
```

```typescript
// React / TypeScript
const res = await fetch('https://auth.myapp.com/connect/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'password',
    client_id:  'my-spa',
    username:   email,
    password:   password,
    scope:      'openid profile email offline_access api',
  }),
});
const { access_token, refresh_token, id_token } = await res.json();
```

### Google Sign-In (ID token exchange)

```csharp
// Auth server
builder.Services.AddPulseAuth(...)
    .AddGoogleTokenExchange(
        builder.Configuration["Auth:Google:ClientId"]!);

// Client
AllowedGrantTypes = [GrantTypes.Password, GrantTypes.GoogleIdToken, GrantTypes.RefreshToken],
```

```typescript
// After Google SDK returns a credential (ID token)
const res = await fetch('https://auth.myapp.com/connect/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:google_id_token',
    client_id:  'my-spa',
    token:      googleCredential,
    scope:      'openid profile email offline_access api',
  }),
});
```

### Facebook Login (access token exchange)

```csharp
// Auth server
builder.Services.AddPulseAuth(...)
    .AddFacebookTokenExchange(
        builder.Configuration["Auth:Facebook:AppId"]!,
        builder.Configuration["Auth:Facebook:AppSecret"]!);

// Client
AllowedGrantTypes = [GrantTypes.Password, GrantTypes.FacebookAccessToken, GrantTypes.RefreshToken],
```

```typescript
// After FB.login() returns authResponse.accessToken
const res = await fetch('https://auth.myapp.com/connect/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:facebook_access_token',
    client_id:  'my-spa',
    token:      fbAccessToken,
    scope:      'openid profile email offline_access api',
  }),
});
```

### Refreshing tokens

```typescript
const res = await fetch('https://auth.myapp.com/connect/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type:    'refresh_token',
    client_id:     'my-spa',
    refresh_token: storedRefreshToken,
  }),
});
```

Refresh tokens are rotated on every use (`RotateRefreshTokens = true`): always store the new
`refresh_token` from the response. A rotated token is still accepted for a short grace period
(`RefreshTokenReuseGracePeriod`, default **10 seconds**) so concurrent refreshes — e.g. the app open
in several tabs — or a retry after a network error do not log the user out. Each request inside the
window gets its own new refresh token. Revoked tokens never benefit from the grace period.

```csharp
.AddPulseAuth(opts =>
{
    opts.RefreshTokenReuseGracePeriod = TimeSpan.FromSeconds(10); // TimeSpan.Zero = strict one-time use
})
```

---

## Roles and custom claims in tokens

By default `AddIdentityUsers<TUser>()` maps standard profile fields (`name`, `given_name`, `email`, etc.) but does **not** include roles or custom claims. Enable them with the optional `configureClaims` delegate:

```csharp
// Include everything: roles + all custom claims from AspNetUserClaims
.AddIdentityUsers<IdentityUser>(claims =>
{
    claims.IncludeRoles      = true;
    claims.IncludeUserClaims = true;
})

// Only roles (no custom claims)
.AddIdentityUsers<IdentityUser>(claims =>
{
    claims.IncludeRoles = true;
})

// Only specific claim types (e.g. department and tenant)
.AddIdentityUsers<IdentityUser>(claims =>
{
    claims.IncludeUserClaims = true;
    claims.ClaimTypeFilter   = ["department", "tenant"];
})

// Roles + specific claim types
.AddIdentityUsers<IdentityUser>(claims =>
{
    claims.IncludeRoles      = true;
    claims.IncludeUserClaims = true;
    claims.ClaimTypeFilter   = ["department", "tenant", "subscription_plan"];
})
```

The resulting JWT for a user with role `Admin` and a custom claim `department=engineering`:

```json
{
  "sub":        "abc-123",
  "email":      "user@example.com",
  "role":       "Admin",
  "department": "engineering",
  "exp":        1719000000
}
```

| Option | Type | Default | Description |
|---|---|---|---|
| `IncludeRoles` | `bool` | `false` | Adds roles from `AspNetUserRoles` as `role` claims |
| `IncludeUserClaims` | `bool` | `true` | Adds custom claims from `AspNetUserClaims` |
| `ClaimTypeFilter` | `ICollection<string>` | `[]` (all) | When non-empty, restricts which custom claim types are included |

> Profile fields (`name`, `given_name`, `family_name`, `picture`) are always mapped regardless of these settings.

### Managing roles and claims with Identity

```csharp
// Add a role to a user
await userManager.AddToRoleAsync(user, "Admin");

// Add a custom claim to a user
await userManager.AddClaimAsync(user, new Claim("department", "engineering"));
await userManager.AddClaimAsync(user, new Claim("tenant", "acme"));

// Remove
await userManager.RemoveFromRoleAsync(user, "Admin");
await userManager.RemoveClaimAsync(user, new Claim("department", "engineering"));
```

> Role and claim changes take effect on the **next login** (next token issued). Existing tokens remain valid until they expire. Use short token lifetimes (`AccessTokenLifetime`) if you need changes to propagate faster.

### Using roles in microservices

```csharp
// Attribute-based
app.MapGet("/reports", [Authorize(Roles = "Admin,Manager")] () => ...);

// Policy-based
builder.Services.AddAuthorization(opts =>
{
    opts.AddPolicy("AdminOnly",    p => p.RequireRole("Admin"));
    opts.AddPolicy("PremiumUsers", p => p.RequireClaim("subscription_plan", "premium"));
});

app.MapGet("/dashboard", () => ...).RequireAuthorization("AdminOnly");
```

---

## Validating tokens in other microservices

Any ASP.NET Core microservice can validate PulseAuth tokens using standard JWT Bearer — no PulseAuth package required:

```csharp
// In any microservice Program.cs
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        opts.Authority = "https://auth.myapp.com";   // PulseAuth discovery endpoint
        opts.Audience  = "my-spa";
        opts.RequireHttpsMetadata = false;            // dev only
    });

builder.Services.AddAuthorization();

// ...
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/orders", (ClaimsPrincipal user) => ...)
   .RequireAuthorization();
```

The microservice fetches public keys from `/.well-known/jwks` automatically and caches them. No shared secrets, no extra dependencies beyond `Microsoft.AspNetCore.Authentication.JwtBearer`.

---

## Custom user store

Implement `IUserAuthenticationService` to use any user database (without ASP.NET Core Identity):

```csharp
public class MyUserService : IUserAuthenticationService
{
    public Task<UserInfo?> ValidateCredentialsAsync(string user, string pass, CancellationToken ct) { ... }
    public Task<UserInfo?> GetUserByIdAsync(string subjectId, CancellationToken ct) { ... }
    public Task<UserInfo?> FindByExternalProviderAsync(string provider, string externalId, CancellationToken ct) { ... }
    public Task<UserInfo>  AutoProvisionUserAsync(string provider, string externalId,
                               IEnumerable<Claim> claims, CancellationToken ct) { ... }
}

// Register instead of .AddIdentityUsers<T>():
builder.Services.AddPulseAuth(...)
    .AddUserAuthentication<MyUserService>();
```

---

## Login page (Authorization Code flow)

PulseAuth redirects to `LoginPath` (default `/Account/Login`) when the user is not authenticated. Your login page signs the user in via ASP.NET Core Identity and redirects back:

```csharp
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

## Troubleshooting

### `Object cannot be cast from DBNull` when running `database update`

**Cause:** Oracle's `MySql.EntityFrameworkCore` package is not fully compatible with MariaDB. Its internal character-set loader expects columns that MariaDB's `information_schema` returns as `NULL`.

**Fix:** replace Oracle's package with [Pomelo](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql), which is built for both MySQL and MariaDB:

```bash
dotnet remove package MySql.EntityFrameworkCore
dotnet add package Pomelo.EntityFrameworkCore.MySql
```

Then replace `UseMySQL` (capital SQL) with `UseMySql` everywhere:

```csharp
opts.UseMySql(conn, ServerVersion.AutoDetect(conn))
// or with a pinned version (recommended for design-time):
opts.UseMySql(conn, new MariaDbServerVersion(new Version(10, 11, 0)))
```

---

### `'Requested value 'None' was not found.'` during migrations

**Cause:** Oracle's `MySql.EntityFrameworkCore` cannot parse `SslMode=None` — that value does not exist in its enum. The design-time factory's connection string contains an invalid SSL mode, or the connection string passed to `UseMySQL` is empty.

**Fix (if still using Oracle's package):** use `SslMode=Disabled` instead of `SslMode=None`, and ensure the connection string is never empty:

```csharp
var cs = "Server=localhost;Port=3306;Database=myauth;User Id=root;Password=secret;SslMode=Disabled;";
```

**Recommended fix:** switch to Pomelo (see above) — this error does not occur with Pomelo.

---

### `Unable to create a 'DbContext'` — factory not found

EF tools print this when no `IDesignTimeDbContextFactory<T>` is found in your startup project and the application host startup also fails.

Ensure your factory: (1) is `public`, (2) is in your startup project (not in the library), (3) implements `IDesignTimeDbContextFactory<YourContext>` where `YourContext` matches the `--context` argument.

---

### Services registered after `builder.Build()`

All `builder.Services.Add*` calls must come **before** `var app = builder.Build()`. Services added after `Build()` are silently ignored.

```csharp
// ✅ Correct
builder.Services.AddDbContext<AppDbContext>(...);
builder.Services.AddPulseAuth(...);
var app = builder.Build();

// ❌ Wrong — these services are never registered
var app = builder.Build();
builder.Services.AddDbContext<AppDbContext>(...);
```

---

### `AuthDbContext` cannot be resolved — inheriting `PulseAuthDbContext`

When your context inherits `PulseAuthDbContext`, its constructor must accept `DbContextOptions<YourContext>` (not `DbContextOptions<PulseAuthDbContext>`):

```csharp
// ❌ Wrong — DI registers DbContextOptions<AppDbContext>, not <PulseAuthDbContext>
public AppDbContext(DbContextOptions<PulseAuthDbContext> options) : base(options) { }

// ✅ Correct — PulseAuthDbContext has a protected constructor that accepts DbContextOptions
public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
```

And in `Program.cs` use the generic overload so DI wires up `AppDbContext` as `PulseAuthDbContext`:

```csharp
.AddEntityFrameworkStores<AppDbContext>(opts => opts.UseMySql(conn, version))
```

---

### `Cannot create a DbSet for 'IdentityUser'` at runtime

**Cause:** Your context inherits `PulseAuthDbContext` (which does NOT include Identity tables) but ASP.NET Core Identity expects Identity's `DbSet`s to be present.

**Fix:** switch to `PulseAuthIdentityDbContext<TUser>` (Option A) so a single context includes both Identity and PulseAuth tables:

```csharp
// ❌ Wrong — no Identity tables
public class AuthDbContext : PulseAuthDbContext { ... }

// ✅ Correct — includes both AspNet* and PulseAuth_* tables
public class AuthDbContext : PulseAuthIdentityDbContext<IdentityUser> { ... }
```

---

### CS1929 / ambiguous call on `AddEntityFrameworkStores` with Identity

**Cause:** Both `PulseAuth.EntityFramework` and `Microsoft.AspNetCore.Identity.EntityFrameworkCore` define `AddEntityFrameworkStores<TContext>` extension methods on `IdentityBuilder`. The compiler cannot resolve which one to call.

**Fix:** split the calls so there is no ambiguity — call Identity's version via the `IdentityBuilder` chain, then call PulseAuth's version separately on the `PulseAuthBuilder`:

```csharp
// ✅ No ambiguity
builder.Services
    .AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()   // Identity's extension
    .AddDefaultTokenProviders();

builder.Services.AddDbContext<AuthDbContext>(opts => opts.UseMySql(conn, version));

builder.Services.AddPulseAuth(...)
    .AddEntityFrameworkStoresWithIdentity<AuthDbContext>();  // PulseAuth's extension
```

---

## 💖 Support

This project is developed and maintained by **Andrés Mariño**. If you find this library useful, consider supporting its continued development:

- **Bitcoin (BTC):** `bc1p9zqgxghkjhauruhsza9n382e6kp5tpj4xtzu2csv4mypsdtdc4tqvdyg86`
- **Ko-fi:** [![Support Me](https://img.shields.io/badge/Ko--fi-Support%20Me-red?style=flat-square&logo=ko-fi)](https://ko-fi.com/andresdev21)

---

## 📝 License

MIT — see [LICENSE](LICENSE) for details.

---

Made with ❤️ for the .NET community
