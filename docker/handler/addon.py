"""Membrane mitmproxy L7 filter addon.

Reads allow rules from /etc/membrane/allow.json (or MEMBRANE_ALLOW_FILE
env var) at startup and enforces http rules on intercepted requests.

All requests fail closed: unknown hostname → 403, unknown IP (when no
hostname) → 403, URL rule mismatch → 403.
"""

import json
import os
import socket
import struct

from mitmproxy import http as mhttp


def _load_rules():
    allow_file = os.environ.get("MEMBRANE_ALLOW_FILE", "/etc/membrane/allow.json")
    with open(allow_file) as f:
        rules = json.load(f)

    allowed_hosts = set()
    allowed_cidrs = []
    url_rules = {}

    for rule in rules:
        if rule.get("type") == "cidr":
            cidr = rule.get("cidr", "")
            if "/" not in cidr:
                cidr = cidr + "/32"
            addr, prefix_len = cidr.split("/", 1)
            http_rules = rule.get("http") or []
            allowed_cidrs.append((addr, int(prefix_len), http_rules))
            continue

        host = rule.get("host", "").lower()
        if not host:
            continue

        allowed_hosts.add(host)

        if rule.get("path") or rule.get("http"):
            url_path = rule.get("path", "") or "/"
            http_rules = rule.get("http") or []
            if host not in url_rules:
                url_rules[host] = []
            url_rules[host].append((url_path, http_rules))

    return allowed_hosts, allowed_cidrs, url_rules


ALLOWED_HOSTS, ALLOWED_CIDRS, URL_RULES = _load_rules()


def _effective_path(url_path, rule_path):
    """Resolve rule_path against url_path.
    Absolute paths (starting with /) are used as-is.
    Relative paths are prepended with url_path.
    """
    if rule_path.startswith("/"):
        return rule_path
    return url_path.rstrip("/") + "/" + rule_path


def _matches_rule(url_path, rule, method, path):
    """Return True if the request matches this http rule."""
    # Method check
    methods = rule.get("methods")
    if methods and method.upper() not in [m.upper() for m in methods]:
        return False

    # Path check
    paths = rule.get("paths")
    if paths:
        for p in paths:
            effective = _effective_path(url_path, p["path"])
            if path == effective or path.startswith(effective.rstrip("/") + "/"):
                return True
        return False

    # No path constraint — check url_path as prefix
    if path != url_path and not path.startswith(url_path.rstrip("/") + "/"):
        return False

    return True


def _match_cidr(ip_int, method, path):
    """Check ip_int against ALLOWED_CIDRS with optional http rule
    enforcement. Returns 'allow', 'block', or None (no match).
    """
    for net_addr, prefix_len, http_rules in ALLOWED_CIDRS:
        try:
            net_int = struct.unpack("!I", socket.inet_aton(net_addr))[0]
        except OSError:
            continue
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        if (ip_int & mask) == (net_int & mask):
            if not http_rules:
                return "allow"
            for rule in http_rules:
                if _matches_rule("/", rule, method, path):
                    return "allow"
            return "block"
    return None


def request(flow: mhttp.HTTPFlow) -> None:
    host = flow.request.pretty_host.lower() if flow.request.pretty_host else ""

    if not host:
        # No hostname — check destination IP against ALLOWED_CIDRS
        peername = flow.server_conn.peername
        if not peername:
            flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})
            return
        ip = peername[0]
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        except OSError:
            flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})
            return
        result = _match_cidr(ip_int, flow.request.method, flow.request.path)
        if result == "allow":
            return
        if result == "block":
            flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})
            return
        # result is None — no CIDR matched, fall through to outer 403
        flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})
        return

    if host not in ALLOWED_HOSTS:
        # Before blocking, check if the destination IP matches a CIDR entry
        peername = flow.server_conn.peername
        if peername:
            try:
                ip_int = struct.unpack("!I", socket.inet_aton(peername[0]))[0]
            except OSError:
                ip_int = None
            if ip_int is not None:
                result = _match_cidr(ip_int, flow.request.method, flow.request.path)
                if result == "allow":
                    return
                if result == "block":
                    flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})
                    return
        # No CIDR match — block
        flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})
        return

    if host not in URL_RULES:
        return  # hostname allowed, no URL-level constraints

    method = flow.request.method
    path = flow.request.path

    for url_path, http_rules in URL_RULES[host]:
        if not http_rules:
            # No http rules — any method/path under url_path is allowed
            if path == url_path or path.startswith(url_path.rstrip("/") + "/"):
                return
            continue
        for rule in http_rules:
            if _matches_rule(url_path, rule, method, path):
                return  # matched — allow

    # No rule matched — block
    flow.response = mhttp.Response.make(
        403,
        b"",
        {"Content-Type": "text/plain"},
    )
