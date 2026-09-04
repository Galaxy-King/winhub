"""Central outbound destination policy for credentialed integrations."""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import socket
import threading
from contextlib import contextmanager
from urllib.parse import urlsplit

from core.config import Config


log = logging.getLogger("winhub.outbound")
_dns_pin_lock = threading.RLock()


class OutboundPolicyError(ValueError):
    pass


def _allowed_patterns():
    return [item.strip().lower() for item in str(getattr(Config, "OUTBOUND_ALLOWED_HOSTS", "") or "").split(",") if item.strip()]


def _host_allowlisted(hostname, addresses):
    hostname = str(hostname or "").rstrip(".").lower()
    for pattern in _allowed_patterns():
        if "/" in pattern:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
                if any(address in network for address in addresses):
                    return True
            except ValueError:
                continue
        elif fnmatch.fnmatchcase(hostname, pattern):
            return True
    return False


def validate_outbound_host(hostname, port=None, purpose="outbound request"):
    hostname = str(hostname or "").strip().rstrip(".")
    if not hostname or any(character in hostname for character in ("/", "\\", "@", "#")):
        raise OutboundPolicyError("Invalid outbound hostname")
    try:
        infos = socket.getaddrinfo(hostname, int(port or 443), type=socket.SOCK_STREAM)
        addresses = {ipaddress.ip_address(info[4][0]) for info in infos}
    except (OSError, ValueError) as exc:
        raise OutboundPolicyError(f"Cannot resolve outbound host {hostname}") from exc
    if not addresses:
        raise OutboundPolicyError(f"Cannot resolve outbound host {hostname}")

    allowlisted = _host_allowlisted(hostname, addresses)
    dangerous = any(
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address.is_private
        for address in addresses
    )
    reason = None
    if dangerous and not allowlisted:
        reason = f"private/special destination {hostname} ({', '.join(sorted(map(str, addresses)))}) is not allowlisted"
    elif _allowed_patterns() and not allowlisted:
        reason = f"destination {hostname} is not in OUTBOUND_ALLOWED_HOSTS"

    if reason:
        mode = str(getattr(Config, "OUTBOUND_POLICY_MODE", "audit") or "audit").lower()
        if mode == "enforce":
            raise OutboundPolicyError(f"Blocked {purpose}: {reason}")
        if mode == "audit":
            log.warning("Outbound policy audit purpose=%s reason=%s", purpose, reason)
    return addresses


def _parse_outbound_url(url, allowed_schemes):
    parsed = urlsplit(str(url or "").strip())
    if parsed.scheme.lower() not in allowed_schemes or not parsed.hostname or parsed.username or parsed.password:
        raise OutboundPolicyError("Invalid outbound URL")
    try:
        parsed.port
    except ValueError as exc:
        raise OutboundPolicyError("Invalid outbound URL port") from exc
    return parsed


def _outbound_port(parsed):
    return parsed.port or {
        "http": 80,
        "https": 443,
        "ldap": 389,
        "ldaps": 636,
    }.get(parsed.scheme.lower(), 0)


def validate_outbound_url(url, purpose="outbound request", allowed_schemes=("https",)):
    parsed = _parse_outbound_url(url, allowed_schemes)
    validate_outbound_host(parsed.hostname, _outbound_port(parsed), purpose)
    return parsed


def _normalized_dns_name(value):
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="ignore")
    return str(value or "").strip().rstrip(".").lower()


@contextmanager
def pinned_outbound_host(hostname, port=None, purpose="outbound request"):
    """Validate once and connect only to those approved IP addresses."""
    normalized_host = _normalized_dns_name(hostname)
    addresses = validate_outbound_host(normalized_host, port, purpose)
    mode = str(getattr(Config, "OUTBOUND_POLICY_MODE", "audit") or "audit").lower()
    if mode != "enforce":
        yield addresses
        return

    ordered_addresses = tuple(sorted((str(address) for address in addresses), key=lambda value: (":" in value, value)))
    with _dns_pin_lock:
        original_getaddrinfo = socket.getaddrinfo

        def pinned_getaddrinfo(host, service, family=0, type=0, proto=0, flags=0):
            if _normalized_dns_name(host) != normalized_host:
                return original_getaddrinfo(host, service, family, type, proto, flags)

            answers = []
            numeric_flag = flags | getattr(socket, "AI_NUMERICHOST", 0)
            for address in ordered_addresses:
                address_family = socket.AF_INET6 if ":" in address else socket.AF_INET
                if family not in (0, socket.AF_UNSPEC, address_family):
                    continue
                answers.extend(original_getaddrinfo(address, service, address_family, type, proto, numeric_flag))
            if not answers:
                raise socket.gaierror(socket.EAI_NONAME, "No approved address matches the requested socket family")
            return answers

        socket.getaddrinfo = pinned_getaddrinfo
        try:
            yield addresses
        finally:
            socket.getaddrinfo = original_getaddrinfo


@contextmanager
def pinned_outbound_url(url, purpose="outbound request", allowed_schemes=("https",)):
    parsed = _parse_outbound_url(url, allowed_schemes)
    with pinned_outbound_host(parsed.hostname, _outbound_port(parsed), purpose):
        yield parsed


def normalized_origin(url):
    parsed = urlsplit(str(url or "").strip())
    if not parsed.scheme or not parsed.hostname:
        return ""
    default_port = {
        "http": 80,
        "https": 443,
        "ldap": 389,
        "ldaps": 636,
    }.get(parsed.scheme.lower(), 0)
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}:{parsed.port or default_port}"
