using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

if (args.Length > 1 || (args.Length == 1 && args[0] != "--expect-eager-auth"))
{
    Console.Error.WriteLine("Usage: dotnet run --project McpAnonymousOAuth -- [--expect-eager-auth]");
    return 2;
}
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
try
{
    Console.WriteLine("MCP SDK 2.2.0; real loopback HTTP; fresh SDK token cache per case.");
    await RunCaseAsync(anonymousCatalog: false, expectEager: false, deadline.Token);
    await RunCaseAsync(anonymousCatalog: true, expectEager: args.Length == 1, deadline.Token);
    Console.WriteLine("PASS: Both cases match the observed challenge-driven SDK behavior.");
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine($"FAIL: {error.Message}");
    return 1;
}

static async Task RunCaseAsync(bool anonymousCatalog, bool expectEager, CancellationToken ct)
{
    var label = anonymousCatalog ? "anonymous-catalog" : "protected-initialization";
    Console.WriteLine($"\nCASE {label}");
    var state = new ProbeState(anonymousCatalog);
    var builder = WebApplication.CreateBuilder(Array.Empty<string>());
    builder.Logging.ClearProviders();
    builder.WebHost.UseUrls("http://127.0.0.1:0");
    builder.Services.AddSingleton(state);
    builder.Services.AddMcpServer().WithHttpTransport().WithTools<ProbeTools>();
    await using var app = builder.Build();
    app.Use(async (context, next) =>
    {
        if (!context.Request.Path.StartsWithSegments("/mcp"))
        {
            await next(context);
            return;
        }
        var method = context.Request.Method;
        if (HttpMethods.IsPost(context.Request.Method))
        {
            context.Request.EnableBuffering();
            using var document = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted);
            context.Request.Body.Position = 0;
            if (document.RootElement.TryGetProperty("method", out var methodProperty))
                method = methodProperty.GetString() ?? "response";
        }
        var authenticated = context.Request.Headers.Authorization == $"Bearer {state.AccessToken}";
        var requiresToken = !state.AnonymousCatalog || method == "tools/call";
        if (requiresToken && !authenticated)
        {
            Interlocked.Increment(ref state.Challenges);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = $"Bearer resource_metadata=\"{state.Origin}/.well-known/oauth-protected-resource/mcp\", scope=\"probe.read\"";
        }
        else
        {
            await next(context);
        }
        state.Trace.Enqueue($"MCP {method}: HTTP {context.Response.StatusCode}; bearer={authenticated}");
    });
    app.MapGet("/.well-known/oauth-protected-resource/mcp", () =>
    {
        Interlocked.Increment(ref state.ResourceDiscovery);
        return Results.Json(new
        {
            resource = $"{state.Origin}/mcp",
            authorization_servers = new[] { state.Origin },
            scopes_supported = new[] { "probe.read" },
        });
    });
    app.MapGet("/.well-known/oauth-authorization-server", () =>
    {
        Interlocked.Increment(ref state.IssuerDiscovery);
        return Results.Json(new
        {
            issuer = state.Origin,
            authorization_endpoint = $"{state.Origin}/authorize",
            token_endpoint = $"{state.Origin}/token",
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { "authorization_code" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post" },
            code_challenge_methods_supported = new[] { "S256" },
            authorization_response_iss_parameter_supported = true,
        });
    });
    app.MapGet("/authorize", (HttpContext context) => state.Authorize(context));
    Func<HttpContext, Task<IResult>> tokenHandler = state.ExchangeAsync;
    app.MapPost("/token", tokenHandler);
    app.MapMcp("/mcp");
    await app.StartAsync(ct);
    state.Origin = app.Urls.Single();

    // The simulated browser returns the redirect to the SDK without another HTTP request.
    using var browserHandler = new HttpClientHandler { AllowAutoRedirect = false };
    using var browser = new HttpClient(browserHandler);
    var options = new HttpClientTransportOptions
    {
        Endpoint = new Uri($"{state.Origin}/mcp"),
        TransportMode = HttpTransportMode.StreamableHttp,
        OAuth = new ClientOAuthOptions
        {
            RedirectUri = new Uri($"{state.Origin}/callback"),
            ClientId = ProbeState.ClientId,
            ClientSecret = state.ClientSecret,
            Scopes = ["probe.read"],
            AuthorizationCallbackHandler = async (context, cancellation) =>
            {
                Interlocked.Increment(ref state.Callbacks);
                using var response = await browser.GetAsync(context.AuthorizationUri, cancellation);
                Require(response.StatusCode == HttpStatusCode.Redirect, "The fake authorization server must return a redirect.");
                var location = response.Headers.Location ?? throw new InvalidOperationException("The redirect URI is absent.");
                var query = QueryHelpers.ParseQuery(location.Query);
                return new AuthorizationResult
                {
                    Code = query["code"].ToString(),
                    State = query["state"].ToString(),
                    Iss = query["iss"].ToString(),
                };
            },
        },
    };
    await using var transport = new HttpClientTransport(options);
    await using var client = await McpClient.CreateAsync(transport, cancellationToken: ct);
    var tools = await client.ListToolsAsync(cancellationToken: ct);
    Require(tools.Any(tool => tool.Name == "protected_echo"), "The protected tool must appear in the catalog.");
    state.Print("after initialize + tools/list");
    if (expectEager)
    {
        Require(state.Callbacks > 0,
            "Explicit-auth expectation: initialization and catalog discovery completed, but the SDK produced no authorization callback or token.");
        Require(state.TokenExchanges == 1 && state.PkceChecks == 1 && state.ToolExecutions == 0,
            "Explicit authorization must exchange the code without a tool invocation.");
        return;
    }
    var expectedCallbacks = anonymousCatalog ? 0 : 1;
    Require(state.Callbacks == expectedCallbacks && state.TokenExchanges == expectedCallbacks,
        "Authorization and token exchange counts differ from the scenario contract.");
    Require(state.ToolExecutions == 0, "Discovery must not execute the tool.");
    if (anonymousCatalog)
    {
        Require(state.ResourceDiscovery == 0 && state.IssuerDiscovery == 0 && state.Challenges == 0,
            "Anonymous discovery must not trigger OAuth metadata requests or challenges.");
    }
    var result = await client.CallToolAsync("protected_echo", cancellationToken: ct);
    Require(result.IsError != true, "The authorized tool call must succeed.");
    Require(result.Content.OfType<TextContentBlock>().Any(block => block.Text == "authorized"), "The tool result differs.");
    Require(state.Callbacks == 1 && state.TokenExchanges == 1 && state.PkceChecks == 1,
        "Each case must complete exactly one OAuth callback, token exchange, and PKCE check.");
    Require(state.ToolExecutions == 1, "The rejected request must not execute the tool before the authenticated retry.");
    state.Print("after tools/call");
    Console.WriteLine($"PASS {label}");
}

static void Require(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

sealed class ProbeState(bool anonymousCatalog)
{
    public const string ClientId = "local-spike-client";
    public bool AnonymousCatalog { get; } = anonymousCatalog;
    public string Origin { get; set; } = "";
    public string ClientSecret { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public string AccessToken { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public ConcurrentQueue<string> Trace { get; } = new();
    private readonly ConcurrentDictionary<string, AuthorizationCode> _codes = new();
    public int Callbacks;
    public int TokenExchanges;
    public int PkceChecks;
    public int Challenges;
    public int ResourceDiscovery;
    public int IssuerDiscovery;
    public int ToolExecutions;

    public IResult Authorize(HttpContext context)
    {
        var query = context.Request.Query;
        if (query["client_id"] != ClientId || query["response_type"] != "code"
            || query["redirect_uri"] != $"{Origin}/callback" || query["code_challenge_method"] != "S256"
            || string.IsNullOrEmpty(query["state"]) || string.IsNullOrEmpty(query["code_challenge"]))
            return Results.BadRequest(new { error = "invalid_request" });
        var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        _codes[code] = new AuthorizationCode(query["redirect_uri"].ToString(), query["code_challenge"].ToString());
        return Results.Redirect(QueryHelpers.AddQueryString($"{Origin}/callback", new Dictionary<string, string?>
        {
            ["code"] = code,
            ["state"] = query["state"].ToString(),
            ["iss"] = Origin,
        }));
    }

    public async Task<IResult> ExchangeAsync(HttpContext context)
    {
        var form = await context.Request.ReadFormAsync(context.RequestAborted);
        if (form["client_id"] != ClientId || form["client_secret"] != ClientSecret)
            return Results.BadRequest(new { error = "invalid_client" });
        if (form["grant_type"] != "authorization_code" || !_codes.TryRemove(form["code"].ToString(), out var code))
            return Results.BadRequest(new { error = "invalid_grant" });
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"].ToString()));
        var challenge = WebEncoders.Base64UrlEncode(hash);
        if (form["redirect_uri"] != code.RedirectUri || challenge != code.Challenge)
            return Results.BadRequest(new { error = "invalid_grant" });
        Interlocked.Increment(ref PkceChecks);
        Interlocked.Increment(ref TokenExchanges);
        return Results.Json(new { access_token = AccessToken, token_type = "Bearer", expires_in = 3600, scope = "probe.read" });
    }

    public void Print(string stage)
    {
        Console.WriteLine($"{stage}: callbacks={Callbacks}; exchanges={TokenExchanges}; PKCE={PkceChecks}; tool executions={ToolExecutions}");
        Console.WriteLine($"metadata: resource={ResourceDiscovery}; issuer={IssuerDiscovery}; challenges={Challenges}");
        while (Trace.TryDequeue(out var line))
            Console.WriteLine($"  {line}");
    }
    private sealed record AuthorizationCode(string RedirectUri, string Challenge);
}

[McpServerToolType]
sealed class ProbeTools
{
    [McpServerTool(Name = "protected_echo"), Description("Return a fixed result after the HTTP authorization gate permits this call.")]
    public static string Echo(ProbeState state)
    {
        Interlocked.Increment(ref state.ToolExecutions);
        return "authorized";
    }
}
