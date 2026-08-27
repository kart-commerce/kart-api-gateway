using System.Security.Claims;
using FluentAssertions;
using KartApiGateway.Api.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace KartApiGateway.Api.UnitTests.Security;

/// <summary>
/// Exercises the actual `IAuthorizationService` produced by `AddGatewayAuthentication` (the same
/// policy set every YARP route in appsettings.json's `AuthorizationPolicy` field is checked
/// against, per Program.cs's `app.UseAuthorization()`), rather than re-implementing the claim
/// check by hand - a policy-name typo in appsettings.json or a change to
/// AuthenticationExtensions.cs that quietly narrows/widens a policy fails these tests the same
/// way it would fail in the running gateway.
///
/// Covers the `/v1/ai-assistant/{**catch-all}` route added for kart-ai-assistant-service
/// (ADR-0025's Gateway coarse check): unlike the pre-existing `AdminOnly` policy gating
/// `/v1/admin/*` (kart-admin-service), this route's `AdminOrSupportAgent` policy must admit BOTH
/// the `admin` and `support_agent` role claims.
/// </summary>
public sealed class AuthenticationExtensionsTests
{
    private static IAuthorizationService BuildAuthorizationService()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddGatewayAuthentication();
        return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    private static ClaimsPrincipal PrincipalWithRole(string role)
    {
        var identity = new ClaimsIdentity(new[] { new Claim("roles", role) }, "TestScheme");
        return new ClaimsPrincipal(identity);
    }

    [Fact]
    public async Task AdminOrSupportAgentPolicy_AdminRoleJwt_Succeeds()
    {
        var authorizationService = BuildAuthorizationService();

        var result = await authorizationService.AuthorizeAsync(
            PrincipalWithRole("admin"), AuthenticationExtensions.AdminOrSupportAgentPolicy);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task AdminOrSupportAgentPolicy_SupportAgentRoleJwt_AlsoSucceeds()
    {
        // The actual new behavior this route adds: the pre-existing AdminOnly policy would have
        // rejected a Support Agent outright (see AdminOnlyPolicy_SupportAgentRoleJwt_StillFails
        // below) - AdminOrSupportAgent is what makes /v1/ai-assistant reachable for this role.
        var authorizationService = BuildAuthorizationService();

        var result = await authorizationService.AuthorizeAsync(
            PrincipalWithRole("support_agent"), AuthenticationExtensions.AdminOrSupportAgentPolicy);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task AdminOrSupportAgentPolicy_CustomerRoleJwt_IsRejected()
    {
        var authorizationService = BuildAuthorizationService();

        var result = await authorizationService.AuthorizeAsync(
            PrincipalWithRole("customer"), AuthenticationExtensions.AdminOrSupportAgentPolicy);

        result.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task AdminOnlyPolicy_SupportAgentRoleJwt_StillFails()
    {
        // Regression guard: adding AdminOrSupportAgent must not widen the pre-existing AdminOnly
        // policy that still gates /v1/admin/* (kart-admin-service) - the two policies are
        // additive, not a change to AdminOnly's own claim check.
        var authorizationService = BuildAuthorizationService();

        var result = await authorizationService.AuthorizeAsync(
            PrincipalWithRole("support_agent"), AuthenticationExtensions.AdminOnlyPolicy);

        result.Succeeded.Should().BeFalse();
    }
}
