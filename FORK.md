# LCSR fork: per-user Zabbix identity

This is a fork of [initMAX/zabbix-mcp-server](https://github.com/initMAX/zabbix-mcp-server)
maintained by Rutgers LCSR. It adds one thing: an authentication gateway in
front of the server can hand it the calling user's own Zabbix API token on
every request, so each Zabbix call runs with that user's role and host group
permissions. Zabbix, not this server, decides what the user may see and do.
Upstream declined this shape in issue #74. If upstream ever ships it, this
fork goes away.

Branches: `main` tracks `upstream/main` untouched. All fork work is on
`per-user-token`. Upstream is merged in, never rebased.

## Configuration

```toml
[server]
trusted_proxies = ["10.0.0.5"]            # the gateway's address(es)
zabbix_token_header = "X-Zabbix-Token"    # unset = feature off
```

`zabbix_token_header` names the header the gateway sends the user's Zabbix
API token in. It is only honoured when the TCP peer is in `trusted_proxies`;
from any other peer the header is dropped and a warning is logged. Setting
it without `trusted_proxies` is a config error.

The gateway sends two credentials on every `/mcp` request: its own MCP
bearer token in `Authorization` and the user's Zabbix token in the header.
Both are required. The MCP token's `allowed_servers`, scopes, `read_only`,
`check_write` and the rate limiter keep applying; the effective rights are
the intersection of those and the user's Zabbix rights.

## Behaviour

- With the header present, `ClientManager` uses a client authenticated with
  the user's token, cached per `(server, sha256(token))` and dropped after
  15 minutes idle. The shared `[zabbix.<name>].api_token` client is never
  touched on such a request.
- If Zabbix rejects the token, or the header is present but empty, the tool
  returns an error saying so. There is no fallback to the shared token.
- Any other Zabbix error (for example "No permissions to call
  host.create" for a user whose role forbids it) is reported the way
  upstream reports every Zabbix error: a generic "API call failed" with the
  detail in the server log.
- The token arrives in a header, never as a tool argument, so the model
  never sees it.
- `graph_render` still fetches `chart2.php` with the shared token or the
  configured frontend credentials; the JSON-RPC calls it makes run as the
  user.

## Touch points for the next upstream merge

| Piece | File |
|---|---|
| contextvar + ASGI middleware | `src/zabbix_mcp/gateway_auth.py` (new) |
| per-user client cache, token-aware `_get_client` / `call` | `src/zabbix_mcp/client.py` |
| `zabbix_token_header` field and parsing | `src/zabbix_mcp/config.py` (`ServerConfig`, `[server]` parser) |
| middleware installed | `src/zabbix_mcp/server.py`, one block right after `_make_request_context_middleware(...)` |
| tests | `tests/test_gateway_auth.py` (new) |
| CI | `.github/workflows/tests.yml` (new) |

```bash
git fetch upstream
git checkout per-user-token
git merge upstream/main      # or a release tag
python -m pytest tests -v
```

Expect conflicts only in `server.py` at the middleware insertion. If upstream
rewrites `ClientManager`, redo the `client.py` piece against the new class;
everything else survives unchanged.

The gateway itself lives in a separate repo (`zabbix-auth-mcp`).
