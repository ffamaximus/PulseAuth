using Microsoft.AspNetCore.Http;
using PulseAuth.Abstractions;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles GET /.well-known/jwks
/// Returns the JSON Web Key Set used to verify JWT signatures.
/// </summary>
internal static class JwksEndpoint
{
    public static async Task<IResult> HandleAsync(IKeyMaterialService keyMaterial, CancellationToken ct)
    {
        var jwks = await keyMaterial.GetPublicKeysAsync(ct);

        // Serialize only the public keys array
        var keys = jwks.Keys.Select(k => new
        {
            kty = k.Kty,
            use = "sig",
            kid = k.Kid,
            alg = "RS256",
            n   = k.N,
            e   = k.E,
        });

        return Results.Ok(new { keys });
    }
}
