using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;

namespace KartApiGateway.Api.Security;

/// <summary>
/// Resolves RS256 signing keys for validating an Identity-issued access token at the edge
/// (design-decisions.md's "JWT Validation — Reuse of kart-category-service's JWKS Pattern").
/// Verbatim copy of kart-category-service's JwksSigningKeyResolver — same HttpClient-based
/// fetch, same 10-minute IMemoryCache duration, same synchronous IssuerSigningKeyResolver
/// delegate shape — differing only in namespace, per that decision doc's explicit intent.
/// </summary>
public sealed class JwksSigningKeyResolver
{
    private const string CacheKey = "identity-jwks";
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(10);

    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _cache;
    private readonly string _jwksUri;

    public JwksSigningKeyResolver(HttpClient httpClient, IMemoryCache cache, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _cache = cache;
        _jwksUri = configuration["Identity:JwksUri"]
            ?? throw new InvalidOperationException("Identity:JwksUri is not configured.");
    }

    public IEnumerable<SecurityKey> ResolveSigningKeys(
        string token,
        SecurityToken securityToken,
        string kid,
        TokenValidationParameters validationParameters)
    {
        var keySet = _cache.GetOrCreate(CacheKey, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = CacheDuration;
            return FetchJwksAsync().GetAwaiter().GetResult();
        });

        return keySet?.Keys ?? Enumerable.Empty<SecurityKey>();
    }

    private async Task<JsonWebKeySet> FetchJwksAsync()
    {
        var response = await _httpClient.GetAsync(_jwksUri);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        return new JsonWebKeySet(json);
    }
}
