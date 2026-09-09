using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using ModelContextProtocol.Authentication;

// This adapter belongs to one explicit authorization candidate. It is not a shared HTTP handler.
sealed class ExplicitAuthorizationHandler(Uri endpoint, Uri metadataUri) : DelegatingHandler(new HttpClientHandler())
{
    private int _challengeSent;
    public int SyntheticChallenges => Volatile.Read(ref _challengeSent);

    public static async Task<ExplicitAuthorizationHandler> CreateAsync(Uri endpoint, CancellationToken ct)
    {
        var metadataUri = new Uri($"{endpoint.GetLeftPart(UriPartial.Authority)}/.well-known/oauth-protected-resource{endpoint.AbsolutePath.TrimEnd('/')}");
        using var transport = new HttpClientHandler { AllowAutoRedirect = false };
        using var http = new HttpClient(transport);
        using var response = await http.GetAsync(metadataUri, ct);
        response.EnsureSuccessStatusCode();
        using var metadata = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var root = metadata.RootElement;
        if (!root.TryGetProperty("resource", out var resource)
            || !Uri.TryCreate(resource.GetString(), UriKind.Absolute, out var resourceUri)
            || resourceUri != endpoint)
            throw new InvalidOperationException("Protected-resource metadata does not match the configured MCP endpoint.");
        if (!root.TryGetProperty("authorization_servers", out var issuers) || issuers.ValueKind != JsonValueKind.Array
            || issuers.GetArrayLength() == 0
            || issuers.EnumerateArray().Any(issuer => !Uri.TryCreate(issuer.GetString(), UriKind.Absolute, out var uri)
                || (uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback))))
            throw new InvalidOperationException("Protected-resource metadata has no usable authorization server.");
        return new ExplicitAuthorizationHandler(endpoint, metadataUri);
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (request.RequestUri == endpoint && request.Method == HttpMethod.Post
            && request.Headers.Authorization is null && Interlocked.CompareExchange(ref _challengeSent, 1, 0) == 0)
        {
            // No server request occurs here. The SDK consumes this challenge, exchanges the code, and sends its authenticated retry.
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized) { RequestMessage = request };
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Bearer", $"resource_metadata=\"{metadataUri.AbsoluteUri}\""));
            return Task.FromResult(response);
        }
        return base.SendAsync(request, ct);
    }
}

// SDK initialization can recover anonymously after a failed OAuth exchange. The host must check candidate credentials separately.
sealed class CandidateTokenCache : ITokenCache
{
    private TokenContainer? _tokens;
    private int _stores;
    public int Stores => Volatile.Read(ref _stores);

    public ValueTask<TokenContainer?> GetTokensAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Volatile.Read(ref _tokens));
    }

    public ValueTask StoreTokensAsync(TokenContainer tokens, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Volatile.Write(ref _tokens, tokens);
        Interlocked.Increment(ref _stores);
        return ValueTask.CompletedTask;
    }

    public void RequireAuthorization()
    {
        if (Volatile.Read(ref _tokens) is not { AccessToken.Length: > 0 })
            throw new InvalidOperationException("Explicit authorization produced no candidate access token.");
    }
}
