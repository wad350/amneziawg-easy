---
title: API
---

# Integration API v1

Use `/api/v1` from another application's backend. The web interface continues to use its original `/api` endpoints. The integration contract is available as authenticated OpenAPI 3.1 JSON at `/api/v1/openapi.json`.

Client lists and details exclude private keys, preshared keys, header-protection keys, executable hooks and one-time download links. Configuration and QR exports deliberately contain the client credentials. All v1 responses use `Cache-Control: no-store`.

## Authentication

Use `Authorization: Bearer <token>`. Service-token authentication is opt-in and bound to an existing account. The account's enabled state, role and client ownership are checked on every request. An administrator account is needed to create clients or manage routing.

Generate a token and its digest locally:

```js
// Save the printed token privately in the integrating backend.
import { randomBytes, createHash } from 'node:crypto';
const token = `awg_${randomBytes(32).toString('base64url')}`;
console.log('Token:', token);
console.log(
    'AWG_API_TOKEN_SHA256=' + createHash('sha256').update(token).digest('hex'),
);
```

Set these variables in the installation's private `.env`:

```dotenv
AWG_API_TOKEN_SHA256=<the 64-character digest>
AWG_API_TOKEN_USER=<existing account username>
```

Recreate this installation's container to load the environment. The server stores only the digest. Rotate the credential by replacing the digest and the integrating backend's token. Clearing either variable disables token authentication. Tokens are restricted to the v1 operations below; they cannot change account passwords, setup, hooks or interface settings.

Keep the token in the integrating backend, outside browser JavaScript, URLs and client configuration files. Use HTTPS. Basic Authentication and existing authenticated sessions remain available with their original permission checks. Basic and service-token authentication reject accounts with verified two-factor authentication; an authenticated session retains the normal 2FA flow. `DISABLE_PASSWORD_AUTH` controls password authentication independently of the explicitly configured service token.

## Operations

| Method | Path relative to `/api/v1`          | Result                                                      |
| ------ | ----------------------------------- | ----------------------------------------------------------- |
| GET    | `/server`                           | Protocol, endpoint and public server/default settings       |
| GET    | `/clients?filter=...&sort=asc`      | `{ "clients": [...] }` with traffic and handshake status    |
| POST   | `/clients`                          | Create a client with current server defaults                |
| GET    | `/clients/{clientId}`               | `{ "client": {...} }` without credentials                   |
| PATCH  | `/clients/{clientId}`               | Change permitted fields; preserve keys and addresses        |
| DELETE | `/clients/{clientId}`               | Remove that client                                          |
| GET    | `/clients/{clientId}/configuration` | Original AmneziaWG `.conf` download                         |
| GET    | `/clients/{clientId}/qrcode.svg`    | Original configuration as an SVG QR code                    |
| GET    | `/routing`                          | Rules, status, revision and outbound names without profiles |
| PUT    | `/routing/rules`                    | Update rules while retaining server-side outbound profiles  |
| GET    | `/openapi.json`                     | Machine-readable request and response contract              |

Inactive IPv6 addresses are returned as `null`. AWG metadata excludes the header-protection key. Nullable junk/CPS overrides retain the native serializer's meaning. Download the original configuration to obtain every supported AmneziaWG 3.1 parameter without reconstructing it from metadata.

Create a client with `{ "name": "Device", "expiresAt": null }`. Optional `awgSettings` accepts the supported per-client advanced settings. New clients receive independently generated keys, addresses and a preshared key. Existing imported clients without a preshared key continue to export without one.

PATCH accepts `name`, `enabled`, `expiresAt`, `dns`, `allowedIps`, `mtu` and `persistentKeepalive`. Omitted fields remain unchanged; `dns: null` and `allowedIps: null` restore server defaults. PATCH cannot replace tunnel addresses, keys, hooks or shared obfuscation settings. Enable or disable a client with `{ "enabled": true }` or `{ "enabled": false }`. `persistentKeepalive` changes the scalar value; an existing advanced `persistentKeepaliveRange` still takes precedence. PATCH preserves that advanced setting.

Client writes reuse the existing configuration synchronization and firewall update. They do not restart the interface. A runtime synchronization failure can occur after a database write; after an error, read the client state before retrying rather than assuming the operation was rolled back.

## Routing updates

GET `/routing` returns a `revision`. Include it in PUT `/routing/rules`:

```json
{
    "revision": "<revision from GET /routing>",
    "enabled": true,
    "apply": true,
    "rules": [
        {
            "id": "selected-domains",
            "name": "Selected domains",
            "enabled": true,
            "networks": ["tcp", "udp"],
            "ports": ["443"],
            "domains": [],
            "suffixes": ["example.org"],
            "cidrs": [],
            "ruleSets": [],
            "outbound": "<existing outbound id>"
        }
    ]
}
```

The array replaces the rule list in its supplied order. Use an outbound ID returned by GET `/routing`, or `direct`. Profiles and their credentials stay on the server. A stale revision returns HTTP 409 without overwriting a newer change. `apply` defaults to `false`: the rules are saved as a draft while the last applied policy remains active. Set `apply: true` to use the existing validated application/rollback mechanism.

## Backend example

This example uses Python's standard library and environment variables supplied privately by the backend:

```python
import json
import os
import urllib.request

base = os.environ['AWG_API_BASE'].rstrip('/')  # https://server.example:8443/api/v1
token = os.environ['AWG_API_TOKEN']

def request(path, method='GET', body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        base + path,
        data=data,
        method=method,
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read()

clients = json.loads(request('/clients'))['clients']
# Export verbatim; never rebuild an AWG profile from the listing.
if clients:
    configuration = request(f"/clients/{clients[0]['id']}/configuration")
```

The original `/api` remains available for the web application. Its full client-detail and routing responses can contain credentials, and its full client-update operation accepts additional fields such as hooks. Use the versioned API for external integration.
