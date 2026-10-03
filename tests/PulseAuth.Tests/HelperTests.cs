using PulseAuth.Helpers;
using PulseAuth.Models;

namespace PulseAuth.Tests;

public class HelperTests
{
    [Fact]
    public void GrantKeyHelper_StoresHashNotValue()
    {
        var key = GrantKeyHelper.ToStorageKey("secret-token");

        Assert.StartsWith(GrantKeyHelper.HashPrefix, key);
        Assert.DoesNotContain("secret-token", key);
        Assert.Equal(key, GrantKeyHelper.ToStorageKey("secret-token"));
        Assert.Equal(RefreshToken.ComputeTokenId("secret-token"), GrantKeyHelper.TokenIdFromStorageKey(key));
        Assert.Equal(RefreshToken.ComputeTokenId("secret-token"), GrantKeyHelper.TokenIdFromStorageKey("secret-token")); // legacy row
    }

    [Fact]
    public void RefreshTokenFamily_ResolvesAncestorsDescendantsAndForks_AcrossLegacyAndHashedKeys()
    {
        static string K(string t) => GrantKeyHelper.ToStorageKey(t);
        static string Id(string t) => RefreshToken.ComputeTokenId(t);

        var rows = new List<(string, string?)>
        {
            ("legacy-root", null),             // written by PulseAuth <= 1.2.x (raw key)
            (K("t1"),  Id("legacy-root")),
            (K("t2a"), Id("t1")),
            (K("t2b"), Id("t1")),              // grace-period fork
            (K("t3"),  Id("t2a")),
            (K("other"), null),                // another session
        };

        var family = RefreshTokenFamily.Resolve(rows, K("t1"));

        Assert.Equal(5, family.Count);
        Assert.Contains(K("t3"), family);
        Assert.DoesNotContain(K("other"), family);
    }

    [Fact]
    public void ClientSecretHelper_VerifiesHashedSecret()
    {
        var (plain, hash) = ClientSecretHelper.GenerateAndHash();

        Assert.True(ClientSecretHelper.Verify(plain, hash));
        Assert.False(ClientSecretHelper.Verify(plain + "x", hash));
    }
}
