#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

"""Per-request Zabbix identity handed over by an authentication gateway.

A gateway that sits in front of this server authenticates the human user,
holds that user's own Zabbix API token, and forwards every ``/mcp``
request with two credentials: its MCP bearer in ``Authorization`` and the
user's Zabbix token in the header named by ``[server].zabbix_token_header``.
The middleware below publishes that token in :data:`current_zabbix_token`
for the duration of the request; :class:`zabbix_mcp.client.ClientManager`
then runs every Zabbix call as that user instead of the shared
``[zabbix.<name>].api_token``, so Zabbix itself decides what the user may
see and do.

The token travels in a header, never as a tool argument, so the model
never sees it. It is only honoured when the TCP peer is listed in
``[server].trusted_proxies``; from anybody else the header is dropped.
"""

from __future__ import annotations

import contextvars
import ipaddress
import logging

logger = logging.getLogger("zabbix_mcp.gateway_auth")

# ``None``: no gateway identity on this request, use the shared token.
# ``""``: the header was present but empty; the client must refuse rather
# than silently run as the shared token.
current_zabbix_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_zabbix_token", default=None)


def make_zabbix_token_middleware(inner_app, header_name: str, trusted_proxies: list[str]):
    """ASGI middleware that moves the gateway's Zabbix token into a contextvar.

    ``trusted_proxies`` entries are addresses or networks, matched the same
    way ``_make_request_context_middleware`` in ``server.py`` matches them.
    """
    header = header_name.lower().encode("latin-1")

    nets = []
    for entry in trusted_proxies:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning(
                "trusted_proxies entry %r is not an IP address or network; "
                "%s will not be honoured from it.", entry, header_name)

    def _is_trusted(addr: str | None) -> bool:
        if not addr:
            return False
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(parsed in net for net in nets)

    async def _middleware(scope, receive, send):
        token = None
        if scope["type"] == "http":
            headers = scope.get("headers", [])
            values = [v for k, v in headers if k == header]
            if values:
                client = scope.get("client")
                peer = client[0] if client else None
                if _is_trusted(peer):
                    token = values[0].decode("latin-1").strip()
                else:
                    logger.warning(
                        "Dropping %s header from untrusted peer %s", header_name, peer)
                # Either way the header does not travel further: the
                # contextvar is the only channel a handler may read it from.
                scope["headers"] = [(k, v) for k, v in headers if k != header]
        current_zabbix_token.set(token)
        try:
            await inner_app(scope, receive, send)
        finally:
            current_zabbix_token.set(None)

    return _middleware
