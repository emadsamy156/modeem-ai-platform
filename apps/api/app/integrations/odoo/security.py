"""Centralized outbound network security policy for Odoo connectivity.

Every outbound Odoo request MUST pass through this policy first.

Protections:
- scheme restricted to http/https (https required in production)
- no embedded credentials, query strings, or fragments
- hostname resolved and ALL resolved IPs inspected; loopback, private,
  link-local, multicast, unspecified, reserved, and cloud-metadata
  destinations are rejected by default
- DNS is validated immediately before the request; redirects are disabled
  at the HTTP client level

Known limitation (documented, not hidden): full DNS-rebinding protection
via IP pinning is NOT implemented in this phase. We validate DNS right
before connecting and never follow redirects, but a malicious resolver
could still rotate records between validation and connection. Private or
internal Odoo servers will require an explicit allowlist or the Modeem
Bridge/Gateway design in a later phase.
"""

import ipaddress
import socket
from urllib.parse import urlsplit

from .errors import ConnectorError

# Cloud metadata endpoints commonly targeted by SSRF.
_METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or str(ip) in _METADATA_ADDRESSES
    )


def validate_outbound_url(url: str, *, environment: str) -> None:
    """Validate URL shape. Raises ConnectorError('invalid_configuration')."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ConnectorError("invalid_configuration", "scheme")
    if environment == "production" and parts.scheme != "https":
        raise ConnectorError("invalid_configuration", "https required")
    if not parts.hostname:
        raise ConnectorError("invalid_configuration", "host missing")
    if parts.username is not None or parts.password is not None:
        raise ConnectorError("invalid_configuration", "userinfo in url")
    if parts.query or parts.fragment:
        raise ConnectorError("invalid_configuration", "query/fragment in url")


def resolve_and_check_host(hostname: str, port: int) -> list[str]:
    """Resolve the hostname and reject any blocked destination.

    Returns the list of resolved IP strings. A single blocked address in a
    mixed DNS answer blocks the whole destination.
    """
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ConnectorError("dns_resolution_failed") from exc
    if not infos:
        raise ConnectorError("dns_resolution_failed")
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise ConnectorError("dns_resolution_failed") from exc
        if _is_blocked_ip(ip):
            raise ConnectorError("blocked_destination")
        ips.append(addr)
    return ips


def enforce_outbound_policy(url: str, *, environment: str) -> None:
    """Full pre-connection check: URL shape + DNS/IP inspection."""
    validate_outbound_url(url, environment=environment)
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    resolve_and_check_host(parts.hostname, port)
