namespace PulseAuth.Models;

/// <summary>
/// Postal address of a user — the OIDC <c>address</c> claim (OIDC Core §5.1.1), returned for the
/// <c>address</c> scope as a JSON object. All members are optional.
/// </summary>
public class UserAddress
{
    /// <summary>Full mailing address formatted for display (<c>formatted</c>); lines separated by "\n".</summary>
    public string? Formatted { get; set; }

    /// <summary>Street address, may contain several lines separated by "\n" (<c>street_address</c>).</summary>
    public string? StreetAddress { get; set; }

    /// <summary>City or locality (<c>locality</c>).</summary>
    public string? Locality { get; set; }

    /// <summary>State, province, prefecture or region (<c>region</c>).</summary>
    public string? Region { get; set; }

    /// <summary>Zip or postal code (<c>postal_code</c>).</summary>
    public string? PostalCode { get; set; }

    /// <summary>Country name or ISO 3166-1 code (<c>country</c>).</summary>
    public string? Country { get; set; }

    /// <summary>The non-empty members keyed by their OIDC names; empty when nothing is set.</summary>
    public IReadOnlyDictionary<string, string> ToClaimObject()
    {
        var result = new Dictionary<string, string>();
        void Add(string key, string? value)
        {
            if (!string.IsNullOrEmpty(value))
                result[key] = value;
        }

        Add("formatted",      Formatted);
        Add("street_address", StreetAddress);
        Add("locality",       Locality);
        Add("region",         Region);
        Add("postal_code",    PostalCode);
        Add("country",        Country);
        return result;
    }
}
