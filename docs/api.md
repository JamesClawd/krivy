# REST API

Krivy serves a JSON REST API under `/api/v1`. The machine-readable
OpenAPI 3.1 description is served (without authentication) at
`GET /api/v1/openapi.yaml`.

## Authentication and scopes

Every endpoint except the OpenAPI document requires a static bearer token
from Krivy's token configuration:

```
Authorization: Bearer <token>
```

| Scope    | Grants                                                         |
|----------|----------------------------------------------------------------|
| `read`   | All `GET` endpoints                                            |
| `scan`   | `read` + trigger and cancel scans                              |
| `manage` | `scan` + acknowledge findings, create and revoke silences      |

A missing or unknown token yields `401 unauthenticated`; a valid token
without the required scope yields `403 forbidden`.

```sh
export KRIVY=https://krivy.example.com
export TOKEN=...   # e.g. from a Kubernetes secret
```

## Errors

All errors share one shape:

```json
{"error": {"code": "not_found", "message": "resource not found"}}
```

| Status | Code                 | When                                                 |
|--------|----------------------|------------------------------------------------------|
| 400    | `bad_request`        | Invalid JSON, unknown fields, bad query parameters, validation errors |
| 401    | `unauthenticated`    | Missing or invalid bearer token                      |
| 403    | `forbidden`          | Token lacks the required scope                       |
| 404    | `not_found`          | Unknown resource or endpoint                         |
| 405    | `method_not_allowed` | Endpoint exists but not for this method              |
| 409    | `conflict`           | The request conflicts with the current state         |
| 500    | `internal`           | Unexpected error (details are only logged server-side) |

Request bodies are limited to 1 MiB and must be a single JSON object
without unknown fields.

## Pagination

List endpoints for scans and findings accept `limit` (1–500, default 50)
and `offset` (default 0) and return:

```json
{"items": [...], "total": 123, "limit": 50, "offset": 0}
```

## Scans

Trigger a cluster scan (scope `scan`). The response is `202 Accepted` with
the scan run and a `Location` header; an empty body also means a cluster
scan:

```sh
curl -sS -X POST "$KRIVY/api/v1/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope":"cluster"}'
```

Scan one namespace:

```sh
curl -sS -X POST "$KRIVY/api/v1/scans" -H "Authorization: Bearer $TOKEN" \
  -d '{"scope":"namespace","namespace":"payments"}'
```

Follow progress (includes per-image jobs) and list runs:

```sh
curl -sS "$KRIVY/api/v1/scans/<id>" -H "Authorization: Bearer $TOKEN"
curl -sS "$KRIVY/api/v1/scans?status=running&limit=10" -H "Authorization: Bearer $TOKEN"
```

Filters for `GET /api/v1/scans`: `status` (`pending`, `running`,
`succeeded`, `partial`, `failed`, `cancelled`), `scope` (`cluster`,
`namespace`), `namespace`.

Cancel a run (scope `scan`; cancelling a finished run returns it unchanged):

```sh
curl -sS -X POST "$KRIVY/api/v1/scans/<id>/cancel" -H "Authorization: Bearer $TOKEN"
```

## Findings

```sh
# Open critical findings in namespace "payments" that nobody triaged yet
curl -sS -G "$KRIVY/api/v1/findings" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode status=open --data-urlencode severity=critical \
  --data-urlencode namespace=payments --data-urlencode acknowledged=false

# One finding with its image, workloads, namespaces and silence state
curl -sS "$KRIVY/api/v1/findings/<id>" -H "Authorization: Bearer $TOKEN"
```

Filters: `status` (`open`, `resolved`), `severity` (`CRITICAL`, `HIGH`,
`MEDIUM`, `LOW`, `UNKNOWN`; case-insensitive), `namespace`, `image` (image
key), `vulnerability` (e.g. `CVE-2024-3094`), `acknowledged` and
`deployed` (`true`/`false`).

Acknowledge and un-acknowledge (scope `manage`):

```sh
curl -sS -X POST "$KRIVY/api/v1/findings/<id>/acknowledge" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"reason":"Not exploitable: code path unused"}'

curl -sS -X DELETE "$KRIVY/api/v1/findings/<id>/acknowledge" \
  -H "Authorization: Bearer $TOKEN"
```

## Silences

Silences suppress notifications for matching findings (they stay visible
in the API). `kind` is `finding`, `image`, `namespace` or `vulnerability`;
bound a silence with `duration` (Go duration, e.g. `720h`) or `expiresAt`
(RFC 3339), or omit both for no expiry. Creating and revoking requires
scope `manage`.

```sh
curl -sS -X POST "$KRIVY/api/v1/silences" -H "Authorization: Bearer $TOKEN" \
  -d '{"kind":"vulnerability","target":"CVE-2024-3094","reason":"accepted risk","duration":"720h"}'

curl -sS "$KRIVY/api/v1/silences" -H "Authorization: Bearer $TOKEN"           # active only
curl -sS "$KRIVY/api/v1/silences?all=true" -H "Authorization: Bearer $TOKEN"  # incl. expired/revoked

curl -sS -X DELETE "$KRIVY/api/v1/silences/<id>" -H "Authorization: Bearer $TOKEN"
```

`POST` returns `201` with the silence; `DELETE` returns `200` with the
revoked silence.

## Summary

```sh
curl -sS "$KRIVY/api/v1/summary" -H "Authorization: Bearer $TOKEN"
```

Returns open findings (total, unacknowledged, by severity, by namespace),
affected and deployed image counts, active silences and the latest scans.
