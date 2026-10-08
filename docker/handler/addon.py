"""Membrane mitmproxy L7 filter addon.

Reads /etc/membrane/network-rules.json (or MEMBRANE_NETWORK_RULES_FILE)
at startup. Matching denies veto allows before requests are forwarded.

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
from mitmproxy.proxy.layers import HttpLayer, TCPLayer
from mitmproxy.proxy.layers.http import HTTPMode
from mitmproxy.proxy.layers.tls import HTTP_ALPNS
from mitmproxy.proxy.utils import expect


class RejectLayer(proxy_layer.Layer):
    """Immediately closes a connection without forwarding any data."""
    def _handle_event(self, event: events.Event):
        if isinstance(event, events.Start):
            yield commands.CloseConnection(self.context.client)
        # ignore all subsequent events — connection is already closed


class InspectLayer(proxy_layer.NextLayer):
    """Buffer protocol bytes so fragmented HTTP cannot fall back to raw TCP."""
    method_chars = b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def __init__(self, context, allow_raw):
        super().__init__(context)
        self.allow_raw = allow_raw

    def _ask(self):
        # HTTP/2 can send server SETTINGS before the client preface. Honor
        # ALPN before sniffing bytes so those frames cannot select raw TCP.
        if self.context.client.alpn in HTTP_ALPNS:
            yield from super()._ask()
            return
        data = self.data_client()
        token, space, _ = data.partition(b" ")
        method = bool(token) and all(c in self.method_chars for c in token)
        if not self.data_server() and (not data or (method and not space) or
                                       b"\x16\x03".startswith(data)):
            return  # Wait for a method delimiter or a complete TLS signature.
        if starts_like_tls_record(data):
            # Let mitmproxy negotiate TLS, then inspect the decrypted protocol.
            yield from super()._ask()
            return
        if method and space and not self.data_server():
            self.layer = HttpLayer(self.context, HTTPMode.transparent)
        elif self.allow_raw:
            self.layer = TCPLayer(self.context)
        else:
            self.layer = RejectLayer(self.context)
        yield from super()._ask()


def _load_rules(rules):

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


with open(os.environ.get("MEMBRANE_NETWORK_RULES_FILE", "/etc/membrane/network-rules.json")) as f:
    network_rules = json.load(f)
if not isinstance(network_rules, dict) or any(
        not isinstance(network_rules.get(key), list) for key in ("allow", "deny")):
    raise ValueError("network rules must contain allow and deny lists")
for rule in network_rules["deny"]:
    if rule["type"] not in ("host", "url", "cidr", "host-pattern", "any") or (
            rule["type"] in ("host", "url", "host-pattern") and not rule.get("host")):
        raise ValueError("deny rule missing a valid destination")
    if (rule.get("http") or rule.get("path", "").rstrip("/")) and any(
            p["proto"] == "udp" for p in rule.get("ports", [])):
        raise ValueError("UDP deny ports cannot be combined with HTTP or path constraints")
ALLOWED_CIDRS, URL_RULES, HOST_PATTERNS, ANY_RULES, ANY_TCP = _load_rules(network_rules["allow"])
DENY_POLICIES = [(rule.get("ports") or [], _load_rules([rule])) for rule in network_rules["deny"]]


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


def _collect_matching_sources(host, addr, policy=None):
    """Collect all rule_lists that match the given host or IP.
    Returns a list of rule_lists."""
    matched = []
    cidrs, urls, patterns, any_rules, _ = policy if policy is not None else (
        ALLOWED_CIDRS, URL_RULES, HOST_PATTERNS, ANY_RULES, ANY_TCP)

    if host and host in urls:
        matched.append(urls[host])
    # Numeric URL/host destinations need no DNS query. Match their original
    # address even when the HTTP Host names a different site on that IP.
    if policy is not None and addr and addr[0] != host and addr[0] in urls:
        matched.append(urls[addr[0]])

    for pattern, rule_list in patterns:
        if host and fnmatchcase(host, pattern):
            matched.append(rule_list)

    if addr:
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(addr[0]))[0]
        except OSError:
            ip_int = None
        if ip_int is not None:
            for net_addr, prefix_len, http_rules in cidrs:
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

    if any_rules:
        matched.append(any_rules)

    return matched


def _matches_tcp_port(ports, port):
    return not ports or any(p["proto"] == "tcp" and p["port"] == port for p in ports)


def _collect_denies(host, addr, port):
    matched = []
    for ports, policy in DENY_POLICIES:
        if not _matches_tcp_port(ports, port):
            continue
        matched.extend(_collect_matching_sources(host, addr, policy))
    return matched


def next_layer(nextlayer: proxy_layer.NextLayer) -> None:
    """Block non-HTTP/TLS connections to hosts with http-only rules."""
    host = (nextlayer.context.server.sni or "").lower()
    addr = nextlayer.context.server.address

    # No SNI — try reverse lookup from dns-proxy map
    if not host and addr:
        host = _reverse_lookup(addr[0])

    denied = _collect_denies(host, addr, addr[1] if addr else None)
    if any(not rules and path in ("", "/")
           for source in denied for path, rules in source):
        nextlayer.layer = RejectLayer(nextlayer.context)
        return

    if nextlayer.layer is not None:
        return  # another addon already decided

    matching_sources = _collect_matching_sources(host, addr)

    # If any matching rule has no http constraints, allow raw TCP.
    has_unconstrained = any(
        any(http_rules == [] for (_, http_rules) in rl)
        for rl in matching_sources
    )

    # A broad host allow must not bypass HTTP vetoes. Reuse NextLayer's
    # buffering before deciding between HTTP and genuinely raw protocols.
    # The HTTP Host may only become known after protocol inspection. Do not
    # rely on the reverse DNS map to decide whether inspection is necessary.
    inspect = any(_matches_tcp_port(ports, addr[1] if addr else None)
                  for ports, _ in DENY_POLICIES)
    if inspect and not isinstance(nextlayer, InspectLayer):
        nextlayer.layer = InspectLayer(nextlayer.context, has_unconstrained or not matching_sources)
        return

    if not matching_sources:
        return  # no rules matched — nftables handles L3/L4

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


def _matches_prefix(path, prefix):
    """Match the base path or a descendant, ignoring prefix trailing slashes."""
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


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
            if _matches_prefix(path, effective):
                return True
        return False

    # No path constraint — check url_path as prefix
    return _matches_prefix(path, url_path)


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
    # Split the raw target before decoding: query data cannot change the path.
    path = normalize_path(flow.request.path.partition("?")[0])
    method = flow.request.method

    # Collect all matching rule lists
    peername = flow.server_conn.peername
    addr = peername if peername else None

    # Transparent mode preserves the original target in server_conn.address;
    # the client socket's local port is the redirect listener (8080).
    destination = flow.server_conn.address
    denied = _collect_denies(host, addr or destination,
                            destination[1] if destination else None)
    if _matches_sources(denied, method, path):
        flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})
        return

    matched = _collect_matching_sources(host, addr)

    if not matched:
        flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})
        return

    if _matches_sources(matched, method, path):
        return

    flow.response = mhttp.Response.make(403, b"", {"Content-Type": "text/plain"})


def _matches_sources(matched, method, path):
    for rule_list in matched:
        for url_path, http_rules in rule_list:
            if not http_rules:
                # No http constraints — permit anything under url_path
                if _matches_prefix(path, url_path):
                    return True
            else:
                for rule in http_rules:
                    if _matches_rule(url_path, rule, method, path):
                        return True
    return False


# Signal to entrypoint.sh that the addon has fully loaded.
# Must come at the bottom of the module — anything after this line
# would not be initialized when the file appears.
open("/tmp/mitmproxy-addon-loaded", "w").close()
