# MCP server

Krivy exposes its functionality to AI assistants as a
[Model Context Protocol](https://modelcontextprotocol.io) server using the
Streamable HTTP transport at `/mcp`.

## Authentication

The MCP endpoint uses the same static bearer tokens and scopes as the
[REST API](api.md). The client must send the token on every request:

```
Authorization: Bearer <token>
```

Krivy does **not** implement OAuth: it advertises no authorization server or
protected-resource metadata, and requests without a valid token get a plain
`401`. MCP clients that can only connect with OAuth are not supported; use a
client that lets you configure a static header.

Each MCP session is bound to the token that created it. Tools that need a
scope the token lacks return a tool error ("permission denied: this tool
requires a token with the "manage" scope") rather than failing the
connection. Use a `read` token for a read-only assistant.

## Tools

| Tool                    | Scope    | Description |
|-------------------------|----------|-------------|
| `security_summary`      | read     | Open findings by severity/namespace, affected images, silences, last scans |
| `list_findings`         | read     | Filter by `status`, `severity`, `namespace`, `image`, `vulnerability`, `acknowledged`, `deployed`; `limit` (≤500) / `offset` |
| `get_finding`           | read     | Finding with image, workloads, namespaces, silence state (`id`) |
| `list_scans`            | read     | Scan runs with `status`/`scope`/`namespace` filters and pagination |
| `get_scan_status`       | read     | Progress of one scan run (`scan_id`) |
| `list_silences`         | read     | Active silences, or all with `include_inactive` |
| `scan_cluster`          | scan     | Trigger a full cluster scan |
| `scan_namespace`        | scan     | Trigger a scan of one `namespace` |
| `acknowledge_finding`   | manage   | Acknowledge a finding (`id`, optional `reason`) |
| `unacknowledge_finding` | manage   | Remove an acknowledgement (`id`) |
| `create_silence`        | manage   | Silence a `finding`/`image`/`namespace`/`vulnerability` `target`, with `duration` (e.g. `720h`) or `expires_at` (RFC 3339) |
| `remove_silence`        | manage   | Revoke a silence (`id`) |

Every tool returns structured output (with an output schema) plus a short
text summary. Read tools are annotated `readOnlyHint: true`. Scans
triggered through MCP are recorded with trigger `mcp`.

## Claude Code

```sh
export KRIVY_TOKEN=...   # a read token for browsing, manage for triage
claude mcp add --transport http krivy https://krivy.example.com/mcp \
  --header "Authorization: Bearer $KRIVY_TOKEN"
```

Then ask, for example, "Which critical vulnerabilities are open in the
payments namespace?".

## Claude Desktop and other clients

Clients that support remote Streamable HTTP servers with custom headers can
be configured with JSON like:

```json
{
  "mcpServers": {
    "krivy": {
      "type": "http",
      "url": "https://krivy.example.com/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

For clients that only support local (stdio) servers, bridge with
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

```json
{
  "mcpServers": {
    "krivy": {
      "command": "npx",
      "args": ["mcp-remote", "https://krivy.example.com/mcp",
               "--header", "Authorization: Bearer ${KRIVY_TOKEN}"],
      "env": { "KRIVY_TOKEN": "<token>" }
    }
  }
}
```

## Local testing

```sh
kubectl -n krivy port-forward svc/krivy 8080:8080
claude mcp add --transport http krivy http://localhost:8080/mcp \
  --header "Authorization: Bearer $KRIVY_TOKEN"
```

Or inspect the tools with the MCP Inspector
(`npx @modelcontextprotocol/inspector`), choosing "Streamable HTTP" and
adding the `Authorization` header.

Serve Krivy behind TLS when it is reachable outside the cluster: the bearer
token is sent with every request.
