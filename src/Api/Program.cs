using Kart.Shared.Observability;
using KartApiGateway.Api.Security;

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

app.UseAuthentication();
app.UseAuthorization();

app.MapReverseProxy();

app.Run();
