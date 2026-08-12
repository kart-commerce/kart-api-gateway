using Kart.Shared.Observability;
using KartApiGateway.Api.Middleware;
using KartApiGateway.Api.Security;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.AddKartObservability("kart-api-gateway");

builder.Services.AddGatewayAuthentication();
builder.Services.AddAuthorization();

builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

app.MapGet("/health/live", () => Results.Ok(new { status = "live" }));
app.MapGet("/health/ready", () => Results.Ok(new { status = "ready" }));

// Placed before UseSerilogRequestLogging so this gateway's own per-request log line (and every
// downstream service's logs for the same request) carry the same Flow.
app.UseMiddleware<FlowTaggingMiddleware>();
app.UseSerilogRequestLogging();

app.UseAuthentication();
app.UseAuthorization();

app.MapReverseProxy();

app.Run();
