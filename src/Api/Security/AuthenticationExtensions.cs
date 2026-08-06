using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace KartApiGateway.Api.Security;

/// <summary>
/// Edge JWT validation (design-decisions.md's "JWT Validation" decision): checks signature +
/// expiry against kart-identity-service's JWKS, never re-derives role/scope grants locally —
/// each downstream service still does its own fine-grained check. ADR-0023: the client's
/// original token is forwarded unchanged (YARP forwards the Authorization header by default;
/// no internal header is minted here). The "authenticated" policy is the coarse gate this
/// release's route table needs (design-decisions.md "Adding a Future Service's Route"); a
/// "AdminOnly" gates the `/v1/admin/*` route added for kart-admin-service, on the same claim
/// shape kart-category-service's own AuthenticationExtensions already uses:
/// `new Claim("roles", role)` per kart-identity-service's JwtAccessTokenGenerator, value
/// "admin" for the Admin-scoped service principal Admin Service authenticates as (ADR-0010).
/// </summary>
public static class AuthenticationExtensions
{
    public const string AuthenticatedPolicy = "authenticated";
    public const string AdminOnlyPolicy = "AdminOnly";
    private const string RolesClaimType = "roles";
    private const string AdminRoleValue = "admin";

    public static IServiceCollection AddGatewayAuthentication(this IServiceCollection services)
    {
        services.AddMemoryCache();
        services.AddHttpClient<JwksSigningKeyResolver>();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<JwksSigningKeyResolver>((options, resolver) =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    // Identity's JwtAccessTokenGenerator sets neither `iss` nor `aud` on the
                    // tokens it mints - validating either here would reject every real token
                    // (same reasoning as kart-category-service's own AuthenticationExtensions).
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeyResolver = resolver.ResolveSigningKeys,
                };
            });

        services.AddAuthorizationBuilder()
            .AddPolicy(AuthenticatedPolicy, policy => policy.RequireAuthenticatedUser())
            .AddPolicy(AdminOnlyPolicy, policy => policy.RequireClaim(RolesClaimType, AdminRoleValue));

        return services;
    }
}
