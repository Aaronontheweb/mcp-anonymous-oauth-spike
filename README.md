# MCP OAuth with anonymous catalog discovery

This isolated spike reproduces a missing OAuth callback with the unmodified MCP C# SDK 2.2.0.
It contains no Netclaw references, broker, credential store, or copied Netclaw source.
One console process hosts a local SDK MCP server and creates real SDK clients over loopback HTTP.

## Run

Install the .NET SDK version specified in `global.json`, then run:

```bash
./verify.sh
```

The script restores locked packages, builds the project, and runs two commands.
The first command must succeed.
The second command must fail with the exact explicit authorization expectation below.
The script returns zero only when both results match.

To inspect each result separately:

```bash
dotnet run --project McpAnonymousOAuth
dotnet run --project McpAnonymousOAuth -- --expect-eager-auth
```

The first command exits with code 0.
The second command exits with code 1 on SDK 2.2.0.
Its failure comes from this spike's assertion, not an SDK exception:

```text
FAIL: Explicit-auth expectation: initialization and catalog discovery completed, but the SDK produced no authorization callback or token.
```

`--expect-eager-auth` expresses a host requirement.
It does not enable an SDK option or invoke an explicit SDK authorization API.

## Experiment

Each case uses a fresh server, a fresh client, and the default SDK token cache.
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
The spike does not force a protocol revision or alter HTTP responses on the client.
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

## Evidence and interpretation

The recorded run used .NET SDK 10.0.400 on Linux with the locked MCP packages at 2.2.0.
See [the successful comparison](evidence/observed.txt) and [the explicit authorization expectation](evidence/explicit-expectation.txt).
The build completed with zero warnings and zero errors.
`dotnet slopwatch analyze --no-baseline` reported zero issues.
Run `dotnet tool restore` first if the local Slopwatch tool is absent.

The experiment proves that successful MCP discovery does not imply OAuth authorization.
It also proves that SDK authorization succeeds when a later protected operation returns an HTTP challenge.
Thus, the evidence supports a request for explicit authorization support, rather than a claim that OAuth exchange fails generally.
The SDK does not produce Netclaw's `BeginCommit` exception. That exception belongs to the host lifecycle.

This spike does not contact Google or reproduce its exact protected-operation error format.
It does not test HTTP 200 tool errors, refresh, consent UI, durable credentials, or Netclaw publication.
It does not establish a protocol violation or prove that every host needs proactive OAuth.
A host command that promises authorization before any tool call exposes the gap shown here.

## References

- [SDK 2.2.0 OAuth provider](https://github.com/modelcontextprotocol/csharp-sdk/blob/v2.2.0/src/ModelContextProtocol.Core/Authentication/ClientOAuthProvider.cs)
- [SDK 2.2.0 OAuth options](https://github.com/modelcontextprotocol/csharp-sdk/blob/v2.2.0/src/ModelContextProtocol.Core/Authentication/ClientOAuthOptions.cs)
- [Original Netclaw report](https://github.com/netclaw-dev/netclaw/issues/2123)

This repository is local. No upstream issue or remote repository was created.
