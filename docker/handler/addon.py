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
from fnmatch import fnmatchcase

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

    allowed_cidrs = []
    # url_rules: host → [(url_path, http_rules), ...]
    # Hosts with no url-level constraints get a sentinel ("/", []) entry.
    url_rules = {}
    # host_patterns: [(pattern, rule_list), ...]
    host_patterns = []
    # any_rules: [(url_path, http_rules), ...] — empty list means no * rule
    any_rules = []
    # any_tcp: True if any bare-* rule exists with no http constraints
    any_tcp = False

    # First pass: collect all rules by type
    for rule in rules:
        rtype = rule.get("type")

        if rtype == "cidr":
            cidr = rule.get("cidr", "")
            if "/" not in cidr:
                cidr = cidr + "/32"
            addr, prefix_len = cidr.split("/", 1)
            http_rules = rule.get("http") or []
            allowed_cidrs.append((addr, int(prefix_len), http_rules))
            continue

        if rtype == "any":
            http_rules = rule.get("http") or []
            url_path = rule.get("path", "") or "/"
            if not http_rules and not rule.get("path"):
                any_tcp = True
                any_rules.append(("/", []))
            else:
                any_rules.append((url_path, http_rules))
            continue

        if rtype == "host-pattern":
            host = rule.get("host", "").lower()
            if not host:
                continue
            http_rules = rule.get("http") or []
            url_path = rule.get("path", "") or "/"
            # Find existing pattern entry or create new one
            found = False
            for i, (pat, rl) in enumerate(host_patterns):
                if pat == host:
                    if not http_rules and not rule.get("path"):
                        host_patterns[i] = (pat, rl + [("/", [])])
                    else:
                        host_patterns[i] = (pat, rl + [(url_path, http_rules)])
                    found = True
                    break
            if not found:
                if not http_rules and not rule.get("path"):
                    host_patterns.append((host, [("/", [])]))
                else:
                    host_patterns.append((host, [(url_path, http_rules)]))
            continue

        # host or url types
        host = rule.get("host", "").lower()
        if not host:
            continue

        if rule.get("path") or rule.get("http"):
            url_path = rule.get("path", "") or "/"
            http_rules = rule.get("http") or []
            if host not in url_rules:
                url_rules[host] = []
            url_rules[host].append((url_path, http_rules))
        else:
            # No constraints — add sentinel entry
            if host not in url_rules:
                url_rules[host] = []
            url_rules[host].append(("/", []))

    return allowed_cidrs, url_rules, host_patterns, any_rules, any_tcp


ALLOWED_CIDRS, URL_RULES, HOST_PATTERNS, ANY_RULES, ANY_TCP = _load_rules()


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


def _collect_matching_sources(host, addr):
    """Collect all rule_lists that match the given host or IP.
    Returns a list of rule_lists."""
    matched = []

    if host and host in URL_RULES:
        matched.append(URL_RULES[host])

    for pattern, rule_list in HOST_PATTERNS:
        if host and fnmatchcase(host, pattern):
            matched.append(rule_list)

    if addr:
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(addr[0]))[0]
        except OSError:
            ip_int = None
        if ip_int is not None:
            for net_addr, prefix_len, http_rules in ALLOWED_CIDRS:
                try:
                    net_int = struct.unpack("!I", socket.inet_aton(net_addr))[0]
                except OSError:
                    continue
                mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
                if (ip_int & mask) == (net_int & mask):
                    if not http_rules:
                        matched.append([("/", [])])
                    else:
                        matched.append([("/", http_rules)])

    if ANY_RULES:
        matched.append(ANY_RULES)

    return matched


def next_layer(nextlayer: proxy_layer.NextLayer) -> None:
    """Block non-HTTP/TLS connections to hosts with http-only rules."""
    if nextlayer.layer is not None:
        return  # another addon already decided

    host = (nextlayer.context.server.sni or "").lower()
    addr = nextlayer.context.server.address

    # No SNI — try reverse lookup from dns-proxy map
    if not host and addr:
        host = _reverse_lookup(addr[0])

    matching_sources = _collect_matching_sources(host, addr)

    if not matching_sources:
        return  # no rules matched — nftables handles L3/L4

    # If any matching rule has no http constraints, allow raw TCP.
    has_unconstrained = any(
        any(http_rules == [] for (_, http_rules) in rl)
        for rl in matching_sources
    )

    if has_unconstrained:
        return  # raw TCP permitted

    # If TLS has already been established for this connection, we've
    # committed to the HTTP path. The decrypted buffer may be transiently
    # empty at inner layer boundaries (especially for HTTP/2 before the
    # preface arrives); byte-sniffing it would spuriously reject valid
    # flows. Let mitmproxy pick the inner layer.
    layer_names = [type(l).__name__ for l in nextlayer.context.layers]
    if "ClientTLSLayer" in layer_names:
        return

    # All matching rules require HTTP/TLS; check bytes.
    if _is_http_or_tls(nextlayer.data_client()):
        return  # HTTP/TLS — allow through

    # Non-HTTP bytes to an http-only dest — block immediately
    nextlayer.layer = RejectLayer(nextlayer.context)


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


def request(flow: mhttp.HTTPFlow) -> None:
    host = flow.request.pretty_host.lower() if flow.request.pretty_host else ""
    path = normalize_path(flow.request.path)
    method = flow.request.method

    # Collect all matching rule lists
    peername = flow.server_conn.peername
    addr = peername if peername else None

    matched = _collect_matching_sources(host, addr)

    if not matched:
        flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})
        return

    for rule_list in matched:
        for url_path, http_rules in rule_list:
            if not http_rules:
                # No http constraints — permit anything under url_path
                if path == url_path or path.startswith(url_path.rstrip("/") + "/"):
                    return
            else:
                for rule in http_rules:
                    if _matches_rule(url_path, rule, method, path):
                        return  # matched — allow

    # No rule matched — block
    flow.response = mhttp.Response.make(
        403,
        b"",
        {"Content-Type": "text/plain"},
    )


# Signal to entrypoint.sh that the addon has fully loaded.
# Must come at the bottom of the module — anything after this line
# would not be initialized when the file appears.
open("/tmp/mitmproxy-addon-loaded", "w").close()
