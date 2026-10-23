# Webhook notifications

Krivy sends notifications as outbound HTTP webhooks. You can point them at
Telegram, Discord, Slack, or any HTTP endpoint. Each destination has a Go
template that builds the request body, so one mechanism covers every chat
tool. You don't need a separate integration for each one.

Copy-paste examples are in [`examples/webhooks/`](../examples/webhooks/).

## Configuration only

Destinations are defined **only** in the Krivy config file, under
`notifications:`. The REST API and MCP server have no endpoints for creating,
changing or deleting webhooks. This is deliberate:

- A compromised API token can't redirect alerts or exfiltrate data to an
  attacker's URL.
- Webhook URLs and credentials stay in Kubernetes Secrets and are not stored
  in the database.
- The configuration is declarative and reviewable in Git/Helm.

To change destinations, edit the config (the Helm `config` value or the
ConfigMap) and restart Krivy. Krivy validates every destination at startup.
Each template is parsed and dry-run against a synthetic event for every event
type it subscribes to. A broken template therefore stops Krivy from starting,
instead of failing silently when the first alert fires.

```yaml
notifications:
  baseURL: https://krivy.example.com     # exposed to templates as .BaseURL
  allowPrivateNetworks: false            # see "SSRF protection"
  destinations:
    - name: telegram                     # unique, shown in delivery records
      url: https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage
      method: POST                       # default POST
      contentType: application/json      # default application/json
      headers:                           # optional; values support ${ENV}
        X-Custom: value
      events: [new_critical, resolved, scan_failed]   # required
      namespaces: [payments]             # optional finding filter
      timeout: 10s                       # per attempt, default 10s
      maxRetries: 3                      # default 3; -1 disables retries
      secrets:                           # exposed as .Secrets.<key>
        chatId: ${TELEGRAM_CHAT_ID}
      template: |
        {"chat_id": {{ json .Secrets.chatId }}, "text": {{ json "hello" }}}
```

## Secrets

Use `${ENV_VAR}` references for credentials and supply the values from a
Kubernetes Secret through environment variables (`envFrom`/`env` in the Helm
chart). Write `$${` for a literal `${`. Krivy refuses to start if a referenced
variable is unset.

`${ENV}` is expanded in **`url`**, **`headers`** values and **`secrets`**
values only. Templates are **never** env-expanded. To use a secret in the body,
put it in the `secrets` map and reference it as `.Secrets.<key>`, for example
`{{ json .Secrets.chatId }}`. That way the value is always JSON-escaped and
can't change the body's structure.

Krivy never writes header values, `secrets` values or the URL (which may
contain a bot token) to the delivery record's `lastError`, and it keeps them
out of its logs. If a server echoes them back in an error response, they are
replaced with `[REDACTED]`.

## Events

| Event          | When                                                   | `.Findings`              |
|----------------|--------------------------------------------------------|--------------------------|
| `new_critical` | A scan found `CRITICAL` findings that are new or reopened | the new findings      |
| `resolved`     | Previously open findings were fixed or are no longer deployed | the resolved findings |
| `scan_failed`  | A scan run finished as `failed` or `partial`           | always empty             |

Which findings count as notification-worthy is decided by the orchestrator
before the event is raised: `new_critical` only includes `CRITICAL` findings
that are not acknowledged and not silenced, and `resolved` only includes
findings that are not silenced (see
[acknowledgements and silences](acknowledgements-and-silences.md)). The
webhook layer only filters and delivers.

**Namespace filter:** if `namespaces` is set, Krivy drops findings that don't
affect a workload in those namespaces. It also removes other namespaces and
workloads from each finding, so one team's webhook doesn't reveal another
team's workload names. If no findings remain, nothing is sent. A `scan_failed`
event is still sent for cluster-wide scans and for namespace scans of a listed
namespace.

## Template data

Templates use Go [`text/template`](https://pkg.go.dev/text/template) syntax
with `missingkey=error`, so a typo like `.Secrets.chatid` is an error. Data:

| Field | Type | Notes |
|---|---|---|
| `.Event.Type` | string | `new_critical`, `resolved` or `scan_failed` |
| `.Event.Time` | time | when the event was raised (UTC) |
| `.Event.Cluster` | string | optional cluster display name |
| `.Scan.ID`, `.Scan.Scope`, `.Scan.Namespace`, `.Scan.Status`, `.Scan.Trigger` | string | scope is `cluster` or `namespace` |
| `.Scan.TotalImages`, `.Scan.FailedImages` | int | |
| `.Scan.Error` | string | set for failures |
| `.Scan.FinishedAt` | time | |
| `.Findings` | list | after namespace filtering; see below |
| `.Count` | int | `len .Findings` |
| `.Secrets` | map | the destination's `secrets` |
| `.BaseURL` | string | `notifications.baseURL`, no trailing slash |

Each finding has `.ID`, `.VulnerabilityID`, `.Severity`, `.PkgName`,
`.InstalledVersion`, `.FixedVersion` (may be empty), `.Title`, `.PrimaryURL`,
`.ImageKey`, `.ImageRef`, `.Namespaces` (list) and `.Workloads` (list of
`namespace/Kind/name`).

If `template` is empty, the body is the event itself as JSON:
`{"type", "scan", "findings", "cluster", "time"}`.

### Functions

| Function | Example | Result |
|---|---|---|
| `json` | `{{ json .Scan.Error }}` | the value as JSON (strings quoted and escaped; `<`, `>`, `&` become `\u003c`, `\u003e`, `\u0026`). **This is the safe way to put text into a body.** |
| `jsonEscape` | `"x {{ jsonEscape .Title }} y"` | the JSON-escaped string *without* quotes, for use inside a string literal you write in the template |
| `quote` | `{{ quote .Count }}` | any value converted to a JSON string literal |
| `join` | `{{ join ", " .Namespaces }}` | joined list |
| `upper` / `lower` | `{{ upper .Severity }}` | |
| `truncate` | `{{ truncate 100 .Title }}` | at most N characters (runes), ending in `…` if cut |
| `default` | `{{ default "no fix" .FixedVersion }}` | the fallback if the value is empty |
| `len` | `{{ len .Findings }}` | |
| `first` | `{{ range first 10 .Findings }}` | the first N list items |
| `countBySeverity` | `{{ countBySeverity .Findings "HIGH" }}` / `{{ json (countBySeverity .Findings) }}` | a count, or a map of severity to count |
| `now` | `{{ now }}` | current time (UTC) |
| `formatTime` | `{{ formatTime "2006-01-02 15:04" .Event.Time }}` | Go layout |
| `add` / `sub` | `{{ sub .Count 10 }}` | integer arithmetic |

All standard `text/template` builtins (`if`, `range`, `eq`, `gt`, `printf`,
`index`, `html`, ...) are available. `call` is disabled. There are no
functions for environment, file, network or command access.

### Writing safe JSON templates

Never write a value straight into a JSON string, like `"text": "{{ .Title }}"`.
A title containing `"` or a newline produces broken JSON, and a crafted
package name could inject fields. Use `json`:

```
{"text": {{ json .Scan.Error }}}
```

To build a longer message, accumulate it in a variable with `printf`, then
encode it once. Inside a template string literal, `\n` is a newline:

```
{{- $msg := printf "%d new critical vulnerabilities" .Count -}}
{{- range first 10 .Findings -}}
  {{- $msg = printf "%s\n- %s in %s %s" $msg .VulnerabilityID .PkgName .InstalledVersion -}}
{{- end -}}
{"text": {{ json $msg }}}
```

Remember that `scan_failed` has no findings, so `index .Findings 0` fails the
startup dry-run. Guard such expressions with `{{ if .Findings }}`.

For JSON content types (`application/json` or `*+json`), Krivy checks the
rendered body with a JSON validator. An invalid body is not sent: the delivery
is marked failed and is not retried. Bodies are capped at 256 KiB, and a
template's execution is capped at 2 seconds.

## Delivery, retries and dedupe

- `Notify` only records and queues the delivery. Sending happens in a
  background worker pool, so slow endpoints never block scans. The queue lives
  in memory and is bounded. If it overflows, the delivery is recorded as
  `failed` ("notification queue full").
- **Success** means a 2xx response.
- **Retried** (up to `maxRetries`, with exponential backoff from 1s to 2min
  plus jitter): network errors, timeouts, `408`, `429` and `5xx`. Krivy
  honours `Retry-After` on `429`/`503`, up to 5 minutes.
- **Not retried:** other `4xx` responses, `3xx` (**redirects are never
  followed**), invalid rendered JSON, and SSRF-blocked targets.
- **Dedupe:** each delivery has a key derived from the destination, event
  type, scan ID and sorted finding IDs. Krivy sends the same notification to
  the same destination at most once, even if the event is raised again.
- Delivery records (`pending`, `delivered` or `failed`, with attempts, last
  response code and redacted last error) are stored in the
  `notification_deliveries` table.
- On shutdown, queued and in-flight deliveries are marked `failed`
  ("interrupted by shutdown"). On startup, deliveries still `pending` that are
  older than 5 minutes are marked `failed` ("interrupted by restart"). Krivy
  doesn't replay them.

## SSRF protection

By default, Krivy refuses to connect to non-public addresses: loopback,
RFC 1918 private ranges, `fc00::/7`, link-local (including the cloud metadata
endpoint `169.254.169.254`), CGNAT `100.64.0.0/10`, unspecified, multicast and
reserved ranges. IPv4-mapped, NAT64 and 6to4 forms are checked too. The check
runs at **connect time** on the resolved IP address, so DNS rebinding can't
bypass it. Webhook requests ignore `HTTP(S)_PROXY`.

If you need an in-cluster receiver (for example
`http://alert-relay.monitoring.svc`) or an egress proxy, set:

```yaml
notifications:
  allowPrivateNetworks: true
```

Only do this if everyone who can edit the Krivy config is trusted with network
access from the Krivy pod.

## Examples

Each file in [`examples/webhooks/`](../examples/webhooks/) is a complete
`notifications:` fragment. A unit test loads, validates and renders each one.

### Telegram

[`telegram.yaml`](../examples/webhooks/telegram.yaml). Create a bot with
[@BotFather](https://t.me/BotFather), add it to your chat, and look up the chat
ID (for example via `getUpdates`). Then set `TELEGRAM_BOT_TOKEN` and
`TELEGRAM_CHAT_ID`.

The example sends **plain text** (no `parse_mode`), so vulnerability titles
and package names need no HTML or Markdown escaping. If you want
`"parse_mode": "HTML"`, every dynamic value must be HTML-escaped first and
then JSON-encoded, for example `{{ json (printf "<b>%s</b>" (html .Title)) }}`.
Otherwise a title containing `<` makes Telegram reject the message with
HTTP 400.

> **No acknowledge buttons.** Telegram inline keyboards ("Acknowledge",
> "Silence") are **not supported**. Krivy webhooks are outbound-only: Krivy
> doesn't receive Telegram callbacks, and it deliberately exposes no
> unauthenticated callback endpoint. Acknowledge or silence findings through
> the authenticated REST API or the MCP server.

### Discord

[`discord.yaml`](../examples/webhooks/discord.yaml). Set `DISCORD_WEBHOOK_URL`
to the channel webhook URL. The example sets `"allowed_mentions": {"parse": []}`
so a crafted title can't ping `@everyone`. Discord limits content to 2000
characters, so the example truncates.

### Slack

[`slack.yaml`](../examples/webhooks/slack.yaml). Set `SLACK_WEBHOOK_URL` to an
incoming-webhook URL. This example also shows the `namespaces` filter.

### Generic JSON

[`generic.yaml`](../examples/webhooks/generic.yaml). A structured JSON
document with a bearer token header, suitable for incident tooling, n8n,
Zapier, or your own receiver.
