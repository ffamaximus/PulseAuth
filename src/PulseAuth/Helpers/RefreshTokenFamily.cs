using PulseAuth.Models;

namespace PulseAuth.Helpers;

/// <summary>
/// Resolves refresh token rotation families (linked through
/// <see cref="RefreshToken.PreviousTokenId"/>). Used by token stores to implement
/// <c>IRefreshTokenStore.RevokeFamilyAsync</c>.
/// </summary>
public static class RefreshTokenFamily
{
    private const int MaxDepth = 10_000; // guard against corrupted / cyclic data

    /// <summary>
    /// Returns the keys of every token in the same family as <paramref name="reusedTokenKey"/>:
    /// walks up to the oldest ancestor still stored, then collects all of its descendants
    /// (including forks created inside the reuse grace period).
    /// </summary>
    /// <param name="candidates">
    /// All stored tokens of the same subject + client as (Key, PreviousTokenId) pairs. Keys may be
    /// hashed storage keys (<see cref="GrantKeyHelper.ToStorageKey"/>) or raw token values.
    /// </param>
    /// <param name="reusedTokenKey">The stored key of the reused token.</param>
    public static IReadOnlySet<string> Resolve(
        IEnumerable<(string Key, string? PreviousTokenId)> candidates,
        string reusedTokenKey)
    {
        var list       = candidates.ToList();
        var keyById    = new Dictionary<string, string>(StringComparer.Ordinal);
        var previousOf = new Dictionary<string, string?>(StringComparer.Ordinal);
        var childrenOf = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (var (key, previousId) in list)
        {
            keyById[GrantKeyHelper.TokenIdFromStorageKey(key)] = key;
            previousOf[key] = previousId;

            if (!string.IsNullOrEmpty(previousId))
            {
                if (!childrenOf.TryGetValue(previousId, out var children))
                    childrenOf[previousId] = children = [];
                children.Add(key);
            }
        }

        // 1. Walk up to the root (oldest ancestor still present).
        var root  = reusedTokenKey;
        var guard = new HashSet<string>(StringComparer.Ordinal) { root };
        for (var depth = 0; depth < MaxDepth; depth++)
        {
            if (!previousOf.TryGetValue(root, out var prevId) || string.IsNullOrEmpty(prevId) ||
                !keyById.TryGetValue(prevId, out var parent) || !guard.Add(parent))
                break;
            root = parent;
        }

        // 2. Collect the root and all of its descendants (BFS). The reused token is a descendant
        //    of the root, so it (and everything derived from it) is reached by the walk.
        var family = new HashSet<string>(StringComparer.Ordinal) { root };
        var queue  = new Queue<string>();
        queue.Enqueue(root);
        while (queue.Count > 0 && family.Count < MaxDepth)
        {
            var key = queue.Dequeue();
            if (!childrenOf.TryGetValue(GrantKeyHelper.TokenIdFromStorageKey(key), out var children))
                continue;

            foreach (var child in children)
                if (family.Add(child))
                    queue.Enqueue(child);
        }

        family.Add(reusedTokenKey); // in case its parent chain is broken / missing
        return family;
    }
}
