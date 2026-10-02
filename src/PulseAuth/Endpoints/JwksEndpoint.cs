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

        // Serialize ONLY public members, per key type (RSA: n/e, EC: crv/x/y).
        var keys = jwks.Keys.Select(k =>
        {
            var jwk = new Dictionary<string, string?>
            {
                ["kty"] = k.Kty,
                ["use"] = "sig",
                ["kid"] = k.Kid,
                ["alg"] = string.IsNullOrEmpty(k.Alg) ? "RS256" : k.Alg,
            };

            if (k.Kty == "EC")
            {
                jwk["crv"] = k.Crv;
                jwk["x"]   = k.X;
                jwk["y"]   = k.Y;
            }
            else
            {
                jwk["n"] = k.N;
                jwk["e"] = k.E;
            }

            return jwk;
        });

        return Results.Ok(new { keys });
    }
}
