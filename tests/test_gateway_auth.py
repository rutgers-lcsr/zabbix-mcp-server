#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""Per-user Zabbix identity handed over by an authentication gateway.

Fork feature (rutgers-lcsr): a trusted proxy forwards the calling user's
own Zabbix API token in a configured header, and every Zabbix call then
runs as that user. Three things are guarded here: the header is only
believed from a trusted peer, the token never reaches anything but the
contextvar, and the client never quietly falls back to the shared token.

The Zabbix client is a fake; nothing here needs a live server.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from unittest import mock

from zabbix_utils.exceptions import APIRequestError

from zabbix_mcp.client import ClientManager, ZabbixTokenRejected
from zabbix_mcp.config import (
    AppConfig,
    ConfigError,
    ServerConfig,
    ZabbixServerConfig,
    load_config,
)
from zabbix_mcp.gateway_auth import current_zabbix_token, make_zabbix_token_middleware


# ---------------------------------------------------------------- config

_BASE_TOML = """
[server]
transport = "http"
%s

[zabbix.dev]
url = "https://zabbix.example.invalid"
api_token = "shared-token"
"""


def _load(server_lines: str) -> AppConfig:
    fd, path = tempfile.mkstemp(suffix=".toml")
    with os.fdopen(fd, "w") as fh:
        fh.write(_BASE_TOML % server_lines)
    try:
        return load_config(path)
    finally:
        os.unlink(path)


class TestConfig(unittest.TestCase):

    def test_unset_by_default(self):
        cfg = _load('trusted_proxies = ["127.0.0.1"]')
        self.assertIsNone(cfg.server.zabbix_token_header)

    def test_set_with_trusted_proxies(self):
        cfg = _load('trusted_proxies = ["127.0.0.1"]\nzabbix_token_header = " X-Zabbix-Token "')
        self.assertEqual(cfg.server.zabbix_token_header, "X-Zabbix-Token")

    def test_requires_trusted_proxies(self):
        with self.assertRaises(ConfigError) as ctx:
            _load('zabbix_token_header = "X-Zabbix-Token"')
        self.assertIn("trusted_proxies", str(ctx.exception))

    def test_rejects_empty_and_non_string(self):
        for bad in ('zabbix_token_header = ""', 'zabbix_token_header = 5'):
            with self.assertRaises(ConfigError):
                _load('trusted_proxies = ["127.0.0.1"]\n' + bad)


# ------------------------------------------------------------ middleware

def _scope(peer="127.0.0.1", **headers):
    return {
        "type": "http",
        "client": (peer, 51234),
        "headers": [(k.replace("_", "-").encode(), v.encode()) for k, v in headers.items()],
    }


def _observe(scope, trusted_proxies=("127.0.0.1",), header="X-Zabbix-Token"):
    """Run one request and report what the inner app saw."""
    seen = {}

    async def inner(scope, receive, send):
        seen["token"] = current_zabbix_token.get()
        seen["headers"] = list(scope["headers"])

    app = make_zabbix_token_middleware(inner, header, list(trusted_proxies))
    asyncio.run(app(scope, None, None))
    return seen


class TestMiddleware(unittest.TestCase):

    def test_trusted_proxy_token_is_published_and_header_stripped(self):
        seen = _observe(_scope(x_zabbix_token=" user-token ", host="mcp.example.com"))
        self.assertEqual(seen["token"], "user-token")
        self.assertEqual(seen["headers"], [(b"host", b"mcp.example.com")])

    def test_untrusted_peer_header_is_dropped(self):
        with self.assertLogs("zabbix_mcp.gateway_auth", level="WARNING"):
            seen = _observe(_scope(peer="203.0.113.9", x_zabbix_token="user-token"))
        self.assertIsNone(seen["token"])
        self.assertEqual(seen["headers"], [])

    def test_no_header_means_no_identity(self):
        seen = _observe(_scope(host="mcp.example.com"))
        self.assertIsNone(seen["token"])

    def test_empty_header_from_trusted_proxy_is_distinguishable(self):
        # The client must refuse this rather than run as the shared token.
        seen = _observe(_scope(x_zabbix_token=""))
        self.assertEqual(seen["token"], "")

    def test_header_name_is_case_insensitive(self):
        seen = _observe(_scope(x_zabbix_token="user-token"), header="x-ZABBIX-token")
        self.assertEqual(seen["token"], "user-token")

    def test_cidr_entry_matches_a_peer_inside_it(self):
        seen = _observe(_scope(peer="10.0.0.7", x_zabbix_token="t"),
                        trusted_proxies=["10.0.0.0/24"])
        self.assertEqual(seen["token"], "t")
        seen = _observe(_scope(peer="10.0.1.7", x_zabbix_token="t"),
                        trusted_proxies=["10.0.0.0/24"])
        self.assertIsNone(seen["token"])

    def test_token_does_not_survive_the_request(self):
        _observe(_scope(x_zabbix_token="user-token"))
        self.assertIsNone(current_zabbix_token.get())

    def test_concurrent_requests_keep_their_own_token(self):
        seen = []

        async def inner(scope, receive, send):
            before = current_zabbix_token.get()
            await asyncio.sleep(0)
            seen.append((before, current_zabbix_token.get()))

        app = make_zabbix_token_middleware(inner, "X-Zabbix-Token", ["127.0.0.1"])

        async def main():
            await asyncio.gather(
                app(_scope(x_zabbix_token="alice"), None, None),
                app(_scope(x_zabbix_token="bob"), None, None),
            )

        asyncio.run(main())
        for before, after in seen:
            self.assertEqual(before, after)
        self.assertEqual(sorted(b for b, _ in seen), ["alice", "bob"])


# --------------------------------------------------------- client manager

class _FakeAPI:
    """Stands in for zabbix_utils.ZabbixAPI; records the token it was given."""

    instances: list["_FakeAPI"] = []

    def __init__(self, url, ssl_context=None, skip_version_check=False, timeout=None):
        self.url = url
        self.token = None
        self.calls: list[tuple[str, dict]] = []
        self.fail_with: Exception | None = None
        _FakeAPI.instances.append(self)

    def login(self, token=None, **_):
        self.token = token

    def api_version(self):
        return "7.0.0"

    def __getattr__(self, obj):
        api = self

        class _Obj:
            def __getattr__(self, meth):
                def _call(*args, **params):
                    api.calls.append((f"{obj}.{meth}", params))
                    if api.fail_with is not None:
                        exc, api.fail_with = api.fail_with, None
                        raise exc
                    return {"as": api.token}
                return _call

        return _Obj()


def _manager() -> ClientManager:
    cfg = AppConfig(
        server=ServerConfig(),
        zabbix_servers={
            "a": ZabbixServerConfig(name="a", url="http://a", api_token="shared-a"),
            "b": ZabbixServerConfig(name="b", url="http://b", api_token="shared-b"),
        },
    )
    return ClientManager(cfg)


def _as_user(token, fn, *args):
    """Run fn(*args) with the gateway token set, as the middleware would."""
    ctx = current_zabbix_token.set(token)
    try:
        return fn(*args)
    finally:
        current_zabbix_token.reset(ctx)


@mock.patch("zabbix_mcp.client.ZabbixAPI", _FakeAPI)
class TestClientManagerAsUser(unittest.TestCase):

    def setUp(self):
        _FakeAPI.instances.clear()

    def test_call_runs_as_the_user_and_never_opens_the_shared_client(self):
        mgr = _manager()
        result = _as_user("alice", mgr.call, "a", "host.get", {"limit": 1})
        self.assertEqual(result, {"as": "alice"})
        self.assertEqual([i.token for i in _FakeAPI.instances], ["alice"])
        self.assertEqual(mgr._clients, {})

    def test_get_version_follows_the_same_path(self):
        mgr = _manager()
        self.assertEqual(_as_user("alice", mgr.get_version, "a"), "7.0.0")
        self.assertEqual([i.token for i in _FakeAPI.instances], ["alice"])
        self.assertEqual(mgr._clients, {})

    def test_no_token_means_the_shared_path_as_before(self):
        mgr = _manager()
        self.assertEqual(mgr.call("a", "host.get", {}), {"as": "shared-a"})
        self.assertEqual(list(mgr._clients), ["a"])
        self.assertEqual(mgr._user_clients, {})

    def test_one_client_per_token_and_server(self):
        mgr = _manager()
        _as_user("alice", mgr.call, "a", "host.get", {})
        _as_user("alice", mgr.call, "a", "item.get", {})
        _as_user("bob", mgr.call, "a", "host.get", {})
        _as_user("alice", mgr.call, "b", "host.get", {})
        self.assertEqual([(i.url, i.token) for i in _FakeAPI.instances],
                         [("http://a", "alice"), ("http://a", "bob"), ("http://b", "alice")])

    def test_empty_token_is_refused_without_touching_zabbix(self):
        mgr = _manager()
        with self.assertRaises(ZabbixTokenRejected):
            _as_user("", mgr.call, "a", "host.get", {})
        with self.assertRaises(ZabbixTokenRejected):
            _as_user("", mgr.get_version, "a")
        self.assertEqual(_FakeAPI.instances, [])
        self.assertEqual(mgr._clients, {})

    def test_auth_failure_drops_the_entry_and_does_not_fall_back(self):
        mgr = _manager()
        _as_user("alice", mgr.call, "a", "host.get", {})
        _FakeAPI.instances[0].fail_with = APIRequestError("Invalid params. Not authorised.")
        with self.assertRaises(ZabbixTokenRejected) as ctx:
            _as_user("alice", mgr.call, "a", "host.get", {})
        self.assertIn("rejected", str(ctx.exception))
        self.assertEqual(mgr._user_clients, {})
        self.assertEqual(mgr._clients, {})
        # No retry happened with any client.
        self.assertEqual(len(_FakeAPI.instances), 1)

    def test_other_zabbix_errors_pass_through_unchanged(self):
        mgr = _manager()
        _as_user("alice", mgr.call, "a", "host.get", {})
        _FakeAPI.instances[0].fail_with = APIRequestError(
            "No permissions to call \"host.create\".")
        with self.assertRaises(APIRequestError):
            _as_user("alice", mgr.call, "a", "host.create", {})
        # Still cached: the token is fine, the action was not allowed.
        self.assertEqual(len(mgr._user_clients), 1)

    def test_dead_socket_is_retried_once_with_the_same_token(self):
        mgr = _manager()
        _as_user("alice", mgr.call, "a", "host.get", {})
        _FakeAPI.instances[0].fail_with = ConnectionResetError("gone")
        result = _as_user("alice", mgr.call, "a", "host.get", {})
        self.assertEqual(result, {"as": "alice"})
        self.assertEqual([i.token for i in _FakeAPI.instances], ["alice", "alice"])

    def test_idle_entries_are_evicted(self):
        mgr = _manager()
        _as_user("alice", mgr.call, "a", "host.get", {})
        _as_user("bob", mgr.call, "a", "host.get", {})
        for entry in mgr._user_clients.values():
            entry[1] -= ClientManager._USER_CLIENT_IDLE + 1
        _as_user("alice", mgr.call, "a", "host.get", {})
        self.assertEqual([i.token for i in _FakeAPI.instances], ["alice", "bob", "alice"])
        self.assertEqual(len(mgr._user_clients), 1)

    def test_close_forgets_user_clients(self):
        mgr = _manager()
        _as_user("alice", mgr.call, "a", "host.get", {})
        mgr.close()
        self.assertEqual(mgr._user_clients, {})


@mock.patch("zabbix_mcp.client.ZabbixAPI", _FakeAPI)
class TestToolHandler(unittest.TestCase):
    """The rejection reaches the model as a tool error, not a generic failure."""

    def setUp(self):
        _FakeAPI.instances.clear()

    def _host_get(self, mgr):
        from zabbix_mcp.api import ALL_METHODS
        from zabbix_mcp.server import _make_tool_handler
        method_def = next(m for m in ALL_METHODS if m.tool_name == "host_get")
        return _make_tool_handler(method_def, mgr, ["a", "b"])

    def test_rejected_token_is_a_tool_error_with_the_reason(self):
        from mcp.server.mcpserver.exceptions import ToolError
        handler = self._host_get(_manager())
        with self.assertRaises(ToolError) as ctx:
            _as_user("", lambda: asyncio.run(handler(server="a", limit=1)))
        self.assertIn("empty Zabbix token", str(ctx.exception))

    def test_tool_call_runs_as_the_user(self):
        mgr = _manager()
        handler = self._host_get(mgr)
        _as_user("alice", lambda: asyncio.run(handler(server="a", limit=1)))
        self.assertEqual([i.token for i in _FakeAPI.instances], ["alice"])
        self.assertEqual(mgr._clients, {})


# ------------------------------------------------------------ end to end

class TestThroughTheRealServer(unittest.TestCase):
    """The header must cross the whole stack: uvicorn, both middlewares,
    the SDK's session task, ``asyncio.to_thread`` and the client.

    Sends an empty token, the one case whose outcome is unmistakable
    without a Zabbix backend: the tool must refuse with the token
    message, not attempt (and fail) a connection as the shared token.
    Both protocol generations are driven, as in test_protocol_e2e.
    """

    @classmethod
    def setUpClass(cls):
        import subprocess
        import sys
        from pathlib import Path as _P
        from tests.test_protocol_e2e import BEARER, _free_port, _wait_for_health

        cls.port = _free_port()
        cls.url = f"http://127.0.0.1:{cls.port}/mcp"
        cfg = f"""
[server]
transport = "http"
host = "127.0.0.1"
port = {cls.port}
auth_token = "{BEARER}"
trusted_proxies = ["127.0.0.1"]
zabbix_token_header = "X-Zabbix-Token"

[zabbix.dev]
url = "https://zabbix-e2e.example.invalid"
api_token = "dummy"
"""
        cls._cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        cls._cfg.write(cfg)
        cls._cfg.close()
        cls._log = open(_P(tempfile.gettempdir()) / "zmcp-gateway-e2e.log", "w")
        cls._proc = subprocess.Popen(
            [sys.executable, "-c", "from zabbix_mcp.cli import main; main()",
             "--config", cls._cfg.name],
            cwd=tempfile.gettempdir(), stdout=cls._log, stderr=subprocess.STDOUT,
        )
        try:
            _wait_for_health(f"http://127.0.0.1:{cls.port}/health")
        except Exception:
            cls._proc.terminate()
            raise

    @classmethod
    def tearDownClass(cls):
        cls._proc.terminate()
        cls._proc.wait(timeout=10)
        cls._log.close()
        os.unlink(cls._cfg.name)

    def _legacy_session(self) -> str:
        from tests.test_protocol_e2e import _post
        # _post drops response headers, so the handshake is issued by hand
        # to read Mcp-Session-Id.
        import json
        import urllib.request
        from tests.test_protocol_e2e import BEARER
        req = urllib.request.Request(self.url, data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "gateway-e2e", "version": "0"}},
        }).encode(), headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {BEARER}",
        })
        with urllib.request.urlopen(req, timeout=15) as r:
            session_id = r.headers.get("Mcp-Session-Id")
            r.read()
        _post(self.url, {"jsonrpc": "2.0", "method": "notifications/initialized"},
              {"Mcp-Session-Id": session_id})
        return session_id

    @staticmethod
    def _text(resp) -> str:
        return " ".join(c.get("text", "") for c in resp["result"]["content"])

    def test_stateful_session_sees_the_token(self):
        from tests.test_protocol_e2e import _post
        session_id = self._legacy_session()
        status, resp = _post(self.url, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "host_get", "arguments": {"limit": 1}},
        }, {"Mcp-Session-Id": session_id, "MCP-Protocol-Version": "2025-11-25",
            "X-Zabbix-Token": ""})
        self.assertEqual(status, 200)
        self.assertTrue(resp["result"].get("isError"))
        self.assertIn("empty Zabbix token", self._text(resp))

    def test_stateless_request_sees_the_token(self):
        from tests.test_protocol_e2e import _META_ENVELOPE, _post
        status, resp = _post(self.url, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"_meta": _META_ENVELOPE, "name": "host_get",
                       "arguments": {"limit": 1}},
        }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call",
            "Mcp-Name": "host_get", "X-Zabbix-Token": ""})
        self.assertEqual(status, 200)
        self.assertTrue(resp["result"].get("isError"))
        self.assertIn("empty Zabbix token", self._text(resp))

    def test_without_the_header_the_shared_path_is_used(self):
        from tests.test_protocol_e2e import _META_ENVELOPE, _post
        status, resp = _post(self.url, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"_meta": _META_ENVELOPE, "name": "host_get",
                       "arguments": {"limit": 1}},
        }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call",
            "Mcp-Name": "host_get"})
        self.assertEqual(status, 200)
        self.assertTrue(resp["result"].get("isError"))
        # Upstream's generic failure: it tried the shared token against the
        # unreachable backend, which is exactly the point.
        self.assertNotIn("Zabbix token", self._text(resp))


if __name__ == "__main__":
    unittest.main()
