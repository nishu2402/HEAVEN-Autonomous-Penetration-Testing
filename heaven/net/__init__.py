"""HEAVEN network-egress helpers.

:mod:`heaven.net.egress` routes HEAVEN's outbound *scanning* traffic through an
operator-configured anonymity path (WireGuard tunnel, HTTP proxy, SOCKS5 proxy
or Tor) while the dashboard / API stay bound to localhost. See that module's
docstring for the full contract.
"""
from __future__ import annotations

__all__ = ["egress"]
