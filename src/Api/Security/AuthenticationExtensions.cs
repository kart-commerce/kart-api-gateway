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
/// "AdminOrSupportAgent" gates the `/v1/ai-assistant/*` route added for
/// kart-ai-assistant-service (ADR-0025's Gateway coarse check: "JWT carries `Admin` or
/// `Support Agent` role claim") - same `roles` claim shape, role value "support_agent" per
/// kart-identity-service's `PlatformRole` enum / database-design.md CHECK constraint
/// (`role IN ('customer', 'support_agent', 'admin')`).
/// </summary>
public static class AuthenticationExtensions
{
    public const string AuthenticatedPolicy = "authenticated";
    public const string AdminOnlyPolicy = "AdminOnly";
    public const string AdminOrSupportAgentPolicy = "AdminOrSupportAgent";
    private const string RolesClaimType = "roles";
    private const string AdminRoleValue = "admin";
    private const string SupportAgentRoleValue = "support_agent";

    public static IServiceCollection AddGatewayAuthentication(this IServiceCollection services)
    {
        services.AddMemoryCache();
        services.AddHttpClient<JwksSigningKeyResolver>();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(SetJwtBearerOptions);

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
            .AddPolicy(AdminOnlyPolicy, policy => policy.RequireClaim(RolesClaimType, AdminRoleValue))
            .AddPolicy(AdminOrSupportAgentPolicy, policy => policy.RequireClaim(RolesClaimType, AdminRoleValue, SupportAgentRoleValue));

        return services;
    }
    
    private static void SetJwtBearerOptions(JwtBearerOptions options)
    {
        // IMPORTANT: Disable claim type mapping on the handler itself
        // This helps to keep JWT claim names (like "sub") unchanged instead of converting to long XML URIs
        // Like "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" instead of "sub"
        options.MapInboundClaims = false;
        

        // Structured, through the same Serilog/OTel pipeline every other log line in this
        // service goes through (kart-conventions.md: "never string-concatenated messages") -
        // these three events previously bypassed it entirely via Console.WriteLine, which meant
        // an auth failure/challenge at the platform's single edge/entry point never reached Loki
        // or carried a TraceId at all.
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("KartApiGateway.Api.Security.Authentication");
                logger.LogWarning(context.Exception, "Stage {Stage}: JWT authentication failed on {Path}", "AuthenticationFailed", context.Request.Path);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("KartApiGateway.Api.Security.Authentication");
                logger.LogDebug("Stage {Stage}: JWT validated for subject {Subject} on {Path}", "AuthenticationSucceeded", context.Principal?.FindFirst("sub")?.Value, context.Request.Path);
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("KartApiGateway.Api.Security.Authentication");
                logger.LogWarning("Stage {Stage}: JWT challenge on {Path} - {Error} {ErrorDescription}", "AuthenticationChallenged", context.Request.Path, context.Error, context.ErrorDescription);
                return Task.CompletedTask;
            }
        };
    }
}
