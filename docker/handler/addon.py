"""Membrane mitmproxy L7 filter addon.

Reads allow rules from /etc/membrane/allow.json (or MEMBRANE_ALLOW_FILE
env var) at startup and enforces http rules on intercepted requests.

All requests fail closed: unknown hostname → 403, unknown IP (when no
hostname) → 403, URL rule mismatch → 403.
"""

import json
import os
import posixpath
import socket
import struct
import urllib.parse

from mitmproxy import http as mhttp
from mitmproxy.net.tls import starts_like_tls_record
from mitmproxy.proxy import commands, events
from mitmproxy.proxy import layer as proxy_layer
from mitmproxy.proxy.utils import expect


class RejectLayer(proxy_layer.Layer):
    """Immediately closes a connection without forwarding any data."""
    def _handle_event(self, event: events.Event):
        if isinstance(event, events.Start):
            yield commands.CloseConnection(self.context.client)
        # ignore all subsequent events — connection is already closed


def _load_rules():
    allow_file = os.environ.get("MEMBRANE_ALLOW_FILE", "/etc/membrane/allow.json")
    with open(allow_file) as f:
        rules = json.load(f)

    allowed_hosts = set()
    allowed_cidrs = []
    url_rules = {}
    tcp_allowed = {}  # hostname → list of allowed ports ([] means any port)

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

        if not rule.get("http") and host:
            ports = rule.get("ports") or []
            if host not in tcp_allowed:
                tcp_allowed[host] = []
            if not ports:
                tcp_allowed[host] = None  # None means any port allowed
            elif tcp_allowed[host] is not None:
                for pr in ports:
                    tcp_allowed[host].append(pr)

    # Remove hosts from tcp_allowed that also have http rules
    for host in list(tcp_allowed.keys()):
        if host not in url_rules:
            continue
        # Host has http rules — rebuild tcp_allowed from explicit port
        # entries only (ignore plain no-port entries for this host)
        explicit_ports = []
        for rule in rules:
            if rule.get("host", "").lower() != host:
                continue
            if rule.get("http"):
                continue
            for pr in rule.get("ports") or []:
                explicit_ports.append(pr)
        if explicit_ports:
            tcp_allowed[host] = explicit_ports
        else:
            del tcp_allowed[host]

    return allowed_hosts, allowed_cidrs, url_rules, tcp_allowed


ALLOWED_HOSTS, ALLOWED_CIDRS, URL_RULES, TCP_ALLOWED = _load_rules()


def _is_http_or_tls(data: bytes) -> bool:
    """Return True if the first bytes look like TLS or plain HTTP."""
    if starts_like_tls_record(data):
        return True
    if data and data[:8].split(b" ")[0].isalpha() and b" " in data[:16]:
        return True
    return False


def _reverse_lookup(ip: str) -> str:
    """Look up hostname for an IP from the dns-proxy reverse map.
    Returns empty string if not found."""
    try:
        with open("/tmp/membrane-dns-map.json") as f:
            m = json.load(f)
        return m.get(ip, "")
    except Exception:
        return ""


def next_layer(nextlayer: proxy_layer.NextLayer) -> None:
    """Block non-HTTP/TLS connections to hosts with http-only rules."""
    if nextlayer.layer is not None:
        return  # another addon already decided

    host = (nextlayer.context.server.sni or "").lower()
    addr = nextlayer.context.server.address

    # No SNI — try reverse lookup from dns-proxy map
    if not host and addr:
        host = _reverse_lookup(addr[0])

    if host and host in ALLOWED_HOSTS and host in URL_RULES:
        # Host has http-only rules — check if raw TCP is permitted
        if host in TCP_ALLOWED:
            port = addr[1] if addr else 0
            allowed_ports = TCP_ALLOWED[host]
            if allowed_ports is None:
                return  # any port allowed
            for pr in allowed_ports:
                if pr["port"] == port:
                    return  # this port explicitly allowed
            # Port not in TCP_ALLOWED — block
            nextlayer.layer = RejectLayer(nextlayer.context)
            return

        # No TCP_ALLOWED entry — check if data looks like TLS or HTTP
        if _is_http_or_tls(nextlayer.data_client()):
            return  # TLS or HTTP — allow through

        # Empty data or non-HTTP/TLS — block immediately
        nextlayer.layer = RejectLayer(nextlayer.context)
        return

    # No hostname match — check ALLOWED_CIDRS for http-only entries
    if addr:
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(addr[0]))[0]
        except OSError:
            return
        for net_addr, prefix_len, http_rules in ALLOWED_CIDRS:
            try:
                net_int = struct.unpack("!I", socket.inet_aton(net_addr))[0]
            except OSError:
                continue
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            if (ip_int & mask) == (net_int & mask):
                if not http_rules:
                    return  # CIDR with no http rules — allow raw TCP
                # CIDR has http rules — check if TLS or HTTP
                if _is_http_or_tls(nextlayer.data_client()):
                    return  # TLS or HTTP — allow through
                # Non-HTTP/TLS — block
                nextlayer.layer = RejectLayer(nextlayer.context)
                return


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


def normalize_path(path):
    """Normalize a request path by iteratively percent-decoding and
    resolving dot-segments until the result stabilizes. Preserves a
    trailing slash if the original path had one.
    """
    trailing_slash = path.endswith("/")
    prev = None
    while prev != path:
        prev = path
        path = urllib.parse.unquote(path)
        path = posixpath.normpath(path)
    # posixpath.normpath strips trailing slash; restore if original had one
    if trailing_slash and not path.endswith("/"):
        path += "/"
    return path


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
    path = normalize_path(flow.request.path)

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
        result = _match_cidr(ip_int, flow.request.method, path)
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
                result = _match_cidr(ip_int, flow.request.method, path)
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
