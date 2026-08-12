using Kart.Shared.Observability;

namespace KartApiGateway.Api.Middleware;

/// <summary>
/// The gateway is this platform's single edge/entry point (kart-conventions.md), so it's the
/// first hop every flow-instrumented request passes through - tagging Flow here means the
/// gateway's own request log line (via <c>UseSerilogRequestLogging</c>) and every downstream
/// service's logs for the same request carry the identical Flow name, queryable together in
/// Grafana by TraceId alone. Maps by route prefix rather than a per-route attribute, since YARP's
/// route config is data (appsettings.json), not attributed C# controller actions this gateway
/// even has.
/// </summary>
public sealed class FlowTaggingMiddleware(RequestDelegate next, ILogger<FlowTaggingMiddleware> logger)
{
    // Every path prefix this session's flow touches - admin-service's proxy surface and
    // Product's own direct write/read API. Extend this table, don't replace it, as future flows
    // are instrumented the same way.
    private static readonly (string PathPrefix, string Flow)[] FlowsByPathPrefix =
    [
        ("/v1/admin/products", "ProductCatalogManagementAdmin"),
        ("/v1/product-groups", "ProductCatalogManagementAdmin"),
        ("/v1/products", "ProductCatalogManagementAdmin"),
    ];

    public async Task InvokeAsync(HttpContext context)
    {
        var flow = FlowsByPathPrefix.FirstOrDefault(f => context.Request.Path.StartsWithSegments(f.PathPrefix)).Flow;

        if (flow is null)
        {
            await next(context);
            return;
        }

        using var flowScope = KartFlowContext.Push(flow);
        logger.LogInformation("Stage {Stage}: {Method} {Path} received at gateway", "AdminGatewayRequestReceived", context.Request.Method, context.Request.Path);

        await next(context);

        logger.LogInformation("Stage {Stage}: {Method} {Path} forwarded, gateway responded {StatusCode}", "AdminGatewayRequestForwarded", context.Request.Method, context.Request.Path, context.Response.StatusCode);
    }
}
