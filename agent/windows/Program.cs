using System.Net.Http.Json;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "Tervyx Endpoint Agent");
builder.Services.AddHostedService<HeartbeatWorker>();
await builder.Build().RunAsync();

sealed class HeartbeatWorker(ILogger<HeartbeatWorker> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var baseUrl = Environment.GetEnvironmentVariable("TERYVX_AGENT_URL") ?? throw new InvalidOperationException("TERYVX_AGENT_URL is required");
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var serviceUri) || serviceUri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("TERYVX_AGENT_URL must be an absolute HTTPS URL");
        var identity = Environment.GetEnvironmentVariable("TERYVX_AGENT_IDENTITY") ?? throw new InvalidOperationException("TERYVX_AGENT_IDENTITY is required");
        var organization = Environment.GetEnvironmentVariable("TERYVX_AGENT_ORGANIZATION_ID") ?? throw new InvalidOperationException("TERYVX_AGENT_ORGANIZATION_ID is required");
        var token = SecretStore.LoadToken();
        var thumbprint = Environment.GetEnvironmentVariable("TERYVX_AGENT_CERT_THUMBPRINT")
            ?? throw new InvalidOperationException("TERYVX_AGENT_CERT_THUMBPRINT is required");
        using var handler = new HttpClientHandler();
        var clientCertificate = CertificateStore.LoadClientCertificate(thumbprint);
        handler.ClientCertificates.Add(clientCertificate);
        using var client = new HttpClient(handler) { BaseAddress = serviceUri, Timeout = TimeSpan.FromSeconds(15) };
        client.DefaultRequestHeaders.Add("X-Agent-Token", token);
        client.DefaultRequestHeaders.Add("X-Agent-Organization-Id", organization);
        client.DefaultRequestHeaders.Add("X-Agent-Certificate-Serial", clientCertificate.SerialNumber);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var health = new { health = new { uptime_seconds = Environment.TickCount64 / 1000, service = "healthy" }, agent_version = typeof(HeartbeatWorker).Assembly.GetName().Version?.ToString() };
                using var response = await client.PostAsJsonAsync($"/api/v1/endpoints/agent/{identity}/heartbeat", health, stoppingToken);
                response.EnsureSuccessStatusCode();
                log.LogInformation("Heartbeat acknowledged for endpoint {Identity}", identity);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                log.LogWarning(ex, "Heartbeat failed; retrying with bounded interval");
            }
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        }
    }
}
