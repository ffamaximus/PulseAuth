using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PulseAuth.EntityFramework.Entities;

[Table("PulseAuth_Clients")]
public class ClientEntity
{
    [Key]
    [MaxLength(200)]
    public string ClientId { get; set; } = default!;

    [MaxLength(512)]
    public string? ClientSecretHash { get; set; }

    [Required, MaxLength(200)]
    public string ClientName { get; set; } = default!;

    [MaxLength(1000)]
    public string? Description { get; set; }

    [MaxLength(500)]
    public string? LogoUri { get; set; }

    public bool Enabled { get; set; } = true;
    public bool RequirePkce { get; set; } = true;
    public bool AllowOfflineAccess { get; set; } = false;
    public bool RequireConsent { get; set; } = false;

    public int AccessTokenLifetime { get; set; } = 3600;
    public int RefreshTokenLifetime { get; set; } = 2592000;
    public int AuthorizationCodeLifetime { get; set; } = 300;
    public int IdentityTokenLifetime { get; set; } = 300;

    // Navigation
    public ICollection<ClientGrantTypeEntity>       GrantTypes      { get; set; } = new List<ClientGrantTypeEntity>();
    public ICollection<ClientRedirectUriEntity>     RedirectUris    { get; set; } = new List<ClientRedirectUriEntity>();
    public ICollection<ClientPostLogoutUriEntity>   PostLogoutUris  { get; set; } = new List<ClientPostLogoutUriEntity>();
    public ICollection<ClientScopeEntity>           AllowedScopes   { get; set; } = new List<ClientScopeEntity>();
    public ICollection<ClientCorsOriginEntity>      CorsOrigins     { get; set; } = new List<ClientCorsOriginEntity>();
    public ICollection<ClientClaimEntity>           Claims          { get; set; } = new List<ClientClaimEntity>();
}

[Table("PulseAuth_ClientGrantTypes")]
public class ClientGrantTypeEntity
{
    public int    Id       { get; set; }
    public string ClientId { get; set; } = default!;
    [MaxLength(100)]
    public string GrantType { get; set; } = default!;
}

[Table("PulseAuth_ClientRedirectUris")]
public class ClientRedirectUriEntity
{
    public int    Id         { get; set; }
    public string ClientId   { get; set; } = default!;
    [MaxLength(2000)]
    public string RedirectUri { get; set; } = default!;
}

[Table("PulseAuth_ClientPostLogoutUris")]
public class ClientPostLogoutUriEntity
{
    public int    Id          { get; set; }
    public string ClientId    { get; set; } = default!;
    [MaxLength(2000)]
    public string PostLogoutUri { get; set; } = default!;
}

[Table("PulseAuth_ClientScopes")]
public class ClientScopeEntity
{
    public int    Id       { get; set; }
    public string ClientId { get; set; } = default!;
    [MaxLength(200)]
    public string Scope    { get; set; } = default!;
}

[Table("PulseAuth_ClientCorsOrigins")]
public class ClientCorsOriginEntity
{
    public int    Id       { get; set; }
    public string ClientId { get; set; } = default!;
    [MaxLength(200)]
    public string Origin   { get; set; } = default!;
}

[Table("PulseAuth_ClientClaims")]
public class ClientClaimEntity
{
    public int    Id       { get; set; }
    public string ClientId { get; set; } = default!;
    [MaxLength(200)]
    public string Type     { get; set; } = default!;
    [MaxLength(1000)]
    public string Value    { get; set; } = default!;
}
