# MCP OAuth with anonymous catalog discovery

This isolated spike reproduces a missing OAuth callback with the unmodified MCP C# SDK 2.2.0.
The second spike tests an explicit authorization adapter that supplies one local HTTP challenge.
It contains no Netclaw project references, broker, credential store, or copied Netclaw source.
One console process hosts a local SDK MCP server and creates real SDK clients over loopback HTTP.

## Run

Install the .NET SDK version specified in `global.json`, then run:

```bash
./verify.sh
```

The script restores locked packages, builds the project, and runs three commands.
The first command must succeed.
The second command must fail with the exact explicit authorization expectation below.
The third command tests the adapter and its failure boundaries.
The script returns zero only when all results match.

To inspect each result separately:

```bash
dotnet run --project McpAnonymousOAuth
dotnet run --project McpAnonymousOAuth -- --expect-eager-auth
dotnet run --project McpAnonymousOAuth -- --synthetic-challenge
```

The first command exits with code 0.
The second command exits with code 1 on SDK 2.2.0.
The third command exits with code 0 when all six adapter cases pass.
Its failure comes from this spike's assertion, not an SDK exception:

```text
FAIL: Explicit-auth expectation: initialization and catalog discovery completed, but the SDK produced no authorization callback or token.
```

`--expect-eager-auth` expresses a host requirement.
It does not enable an SDK option or invoke an explicit SDK authorization API.

## Experiment

Each original case uses a fresh server, a fresh client, and the default SDK token cache.
Both servers advertise OAuth metadata and require the same authorization-code protocol.
Only the placement of the HTTP authorization gate changes.

| Observation | Protected initialization | Anonymous catalog |
| --- | --- | --- |
| `server/discover` | HTTP 401, then authenticated HTTP 200 | Anonymous HTTP 200 |
| `tools/list` | Authenticated HTTP 200 | Anonymous HTTP 200 |
| OAuth callbacks after discovery | 1 | 0 |
| Token exchanges after discovery | 1 | 0 |
| OAuth metadata requests after discovery | 2 | 0 |
| First protected `tools/call` | Authenticated HTTP 200 | HTTP 401, then authenticated HTTP 200 |
| Total callbacks after the tool call | 1 | 1 |
| Total token exchanges after the tool call | 1 | 1 |
| Tool executions | 1 | 1 |

The SDK selects `server/discover` for initialization in this version.
The original comparison does not force a protocol revision or alter HTTP responses on the client.
The server rejects an unauthorized tool request before the tool executes.

The relevant client code is ordinary SDK use:

```csharp
await using var client = await McpClient.CreateAsync(transport, cancellationToken: ct);
var tools = await client.ListToolsAsync(cancellationToken: ct);
// The anonymous case reaches this point without an OAuth callback.
var result = await client.CallToolAsync("protected_echo", cancellationToken: ct);
// The HTTP 401 now starts OAuth, and the SDK retries the call with a token.
```

## Local OAuth provider

The fake provider supports protected-resource metadata, authorization-server metadata, authorization-code redirects, and token exchange.
It uses a pre-registered client with a random secret.
It checks that secret, the registered redirect URI, the single-use code, and the S256 PKCE verifier.
The authorization response returns the state and issuer to the SDK.

The callback delegate simulates browser consent through a real HTTP request.
It returns the authorization response to the SDK without a browser or a callback listener.
All addresses use loopback, and all credentials exist only in memory.
The trace prints methods, status codes, and counters. It does not print credential values or authorization URLs.
This fake provider is test code and is not suitable for production use.

## Second spike: one synthetic challenge

The adapter successfully starts SDK OAuth before any protected tool call.
It uses the public `HttpClientTransport` constructor that accepts an `HttpClient`.
It needs no SDK fork, reflection, or separate OAuth implementation.

[ExplicitAuthorizationHandler.cs](McpAnonymousOAuth/ExplicitAuthorizationHandler.cs) contains the adapter and a small candidate token cache.
The adapter first retrieves protected-resource metadata and checks its resource identity and authorization-server entries.
It then supplies one local HTTP 401 for the first unauthenticated POST to the exact MCP endpoint.
That request never reaches the server.
The SDK consumes the challenge, performs OAuth, and sends an authenticated retry to the real server.

```text
Host requests explicit authorization
  -> Validate protected-resource metadata
  -> Create a fresh candidate token cache and adapter
  -> SDK sends its first MCP POST
  -> Adapter supplies one local HTTP 401
  -> SDK discovers OAuth metadata and performs the code exchange
  -> SDK stores the candidate token
  -> SDK sends the authenticated MCP request
  -> Host checks the candidate token before it reports authorization success
```

The success case produces one callback, one exchange, one PKCE check, and one SDK token-cache write before any tool executes.
The MCP server supplies no authentication challenge during this flow.
A later catalog request causes no additional OAuth activity.
An unrelated HTTP request retains its real HTTP 409 status and does not consume the synthetic challenge.
After consumption, a direct unauthorized request retains the server's real HTTP 401.

The adapter has an atomic one-use limit and belongs to one explicit authorization candidate.
Normal clients in the original comparison do not use it.
Its metadata preflight adds a request; the SDK still fetches metadata for its own protocol work.

### A required host guard

The negative test found an important limit: SDK 2.2.0 can return an anonymous client after the token endpoint rejects the exchange.
The SDK can recover through anonymous initialization, so client creation alone does not prove authorization success.
The adapter does not suppress or replace the token endpoint's HTTP 400 response.

The spike supplies a fresh `ITokenCache` and checks that the SDK stores an access token.
The host rejects the anonymous client when that cache remains empty.
Netclaw must retain its own callback, credential, cancellation, and publication guards if it adopts this technique.
This spike's in-memory check does not replace those production contracts.

| Adapter case | Verified result |
| --- | --- |
| Successful explicit authorization | Token exists before tool use; one synthetic challenge |
| Wrong resource in metadata | Host rejects metadata before OAuth or MCP use |
| Metadata HTTP 503 | Host receives the failure before adapter construction |
| Token endpoint HTTP 400 | SDK returns an anonymous client; host token guard rejects it |
| Cancellation at the authorization callback | Caller receives cancellation; no exchange or tool execution |
| Protected tool HTTP 503 | Caller receives HTTP 503; no tool execution or additional OAuth |

See [the second spike trace](evidence/synthetic-challenge.txt).
The original comparison and its expected failure remain part of `verify.sh`.

This adapter is a proof of concept, not a production compatibility layer.
It tests Streamable HTTP on loopback with a known metadata path and a fresh token cache.
It does not test SSE, discovery fallback paths, multiple authorization servers, concurrent initialization, refresh, or hostile metadata changes between requests.
It also does not preserve detailed OAuth diagnostics when the SDK recovers anonymously; the host guard reports the absent token.
Those limits require work before adoption in Netclaw.

## Evidence and interpretation

The recorded runs used .NET SDK 10.0.400 on Linux with the locked MCP packages at 2.2.0.
See [the successful comparison](evidence/observed.txt) and [the explicit authorization expectation](evidence/explicit-expectation.txt).
The build completed with zero warnings and zero errors.
`dotnet slopwatch analyze --no-baseline` reported zero issues.
Run `dotnet tool restore` first if the local Slopwatch tool is absent.

The experiment proves that successful MCP discovery does not imply OAuth authorization.
It also proves that SDK authorization succeeds when a later protected operation returns an HTTP challenge.
Thus, the evidence supports a request for explicit authorization support, rather than a claim that OAuth exchange fails generally.
The second spike proves that a local adapter can provide that behavior with the current SDK, if the host also checks candidate credentials.
The SDK does not produce Netclaw's `BeginCommit` exception. That exception belongs to the host lifecycle.

This spike does not contact Google or reproduce its exact protected-operation error format.
It does not test HTTP 200 tool errors, refresh, consent UI, durable credentials, or Netclaw publication.
It does not establish a protocol violation or prove that every host needs proactive OAuth.
A host command that promises authorization before any tool call exposes the gap shown here.

## References

- [SDK 2.2.0 OAuth provider](https://github.com/modelcontextprotocol/csharp-sdk/blob/v2.2.0/src/ModelContextProtocol.Core/Authentication/ClientOAuthProvider.cs)
- [SDK 2.2.0 OAuth options](https://github.com/modelcontextprotocol/csharp-sdk/blob/v2.2.0/src/ModelContextProtocol.Core/Authentication/ClientOAuthOptions.cs)
- [Original Netclaw report](https://github.com/netclaw-dev/netclaw/issues/2123)

This repository provides a standalone reproduction for review. No upstream SDK issue was filed.
