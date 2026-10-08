package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const reverseMapFile = "/tmp/membrane-dns-map.json"

type portRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // "tcp" or "udp"
}

type networkRule struct {
	Type  string     `json:"type"`
	Host  string     `json:"host"`
	Ports []portRule `json:"ports"`
	Path  string     `json:"path"`
	HTTP  []struct {
		Methods []string `json:"methods"`
		Paths   []struct {
			Path string `json:"path"`
		} `json:"paths"`
	} `json:"http"`
}

type patternEntry struct {
	pattern string
	ports   []portRule // nil = any-port
}

type allowedSet struct {
	exact    map[string][]portRule
	patterns []patternEntry
	anyHost  bool
	anyPorts []portRule // from bare-* rule; nil = any-port
}

// unionPorts merges src into dst. nil means any-port and wins over specific ports.
// Returns nil if either side is nil (any-port).
func unionPorts(dst []portRule, src []portRule) []portRule {
	if dst == nil || src == nil {
		return nil
	}
	return appendUniquePorts(dst, src...)
}

func buildHostSet(rules []networkRule) *allowedSet {
	as := &allowedSet{exact: make(map[string][]portRule)}
	for _, r := range rules {
		switch r.Type {
		case "any":
			if as.anyHost {
				as.anyPorts = unionPorts(as.anyPorts, r.Ports)
			} else {
				as.anyHost = true
				if len(r.Ports) == 0 {
					as.anyPorts = nil
				} else {
					as.anyPorts = append([]portRule(nil), r.Ports...)
				}
			}
		case "host-pattern":
			pattern := strings.ToLower(r.Host)
			if pattern == "" {
				continue
			}
			var ports []portRule
			if len(r.Ports) > 0 {
				ports = append([]portRule(nil), r.Ports...)
			}
			// Check if pattern already exists; union ports
			found := false
			for i := range as.patterns {
				if as.patterns[i].pattern == pattern {
					as.patterns[i].ports = unionPorts(as.patterns[i].ports, ports)
					found = true
					break
				}
			}
			if !found {
				as.patterns = append(as.patterns, patternEntry{pattern: pattern, ports: ports})
			}
		case "host", "url":
			host := strings.ToLower(r.Host)
			if host == "" {
				continue
			}
			if existing, ok := as.exact[host]; ok && existing == nil {
				continue
			}
			if len(r.Ports) == 0 {
				as.exact[host] = nil
			} else {
				as.exact[host] = appendUniquePorts(as.exact[host], r.Ports...)
			}
		}
	}
	return as
}

// Only transport-only hostname rules belong in firewall sets. HTTP and URL
// path constraints are evaluated by the proxy, never by refusing DNS answers.
func buildDeniedHosts(rules []networkRule) []allowedSet {
	var transport []allowedSet
	for _, rule := range rules {
		if len(rule.HTTP) == 0 && (rule.Path == "" || rule.Path == "/") &&
			(rule.Type == "host" || rule.Type == "url" || rule.Type == "host-pattern") {
			transport = append(transport, *buildHostSet([]networkRule{rule}))
		}
	}
	return transport
}

func addDeniedIP(ip net.IP, ports []portRule) error {
	if len(ports) == 0 {
		return exec.Command("nft", "add", "element", "ip", "membrane",
			"denied-any-port", "{", ip.String()+"/32", "}").Run()
	}
	for _, pr := range ports {
		elem := fmt.Sprintf("%s . %s . %d", ip.String(), pr.Proto, pr.Port)
		if err := exec.Command("nft", "add", "element", "ip", "membrane",
			"denied", "{", elem, "}").Run(); err != nil {
			return err
		}
	}
	return nil
}

func updateReverseMap(ip, hostname string) {
	existing := map[string]string{}
	if data, err := os.ReadFile(reverseMapFile); err == nil {
		json.Unmarshal(data, &existing)
	}
	existing[ip] = hostname

	tmp := reverseMapFile + ".tmp"
	data, err := json.Marshal(existing)
	if err != nil {
		return
	}
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	os.Rename(tmp, reverseMapFile)
}

func appendUniquePorts(s []portRule, vals ...portRule) []portRule {
	for _, v := range vals {
		found := false
		for _, x := range s {
			if x == v {
				found = true
				break
			}
		}
		if !found {
			s = append(s, v)
		}
	}
	return s
}

func main() {
	upstream := os.Getenv("MEMBRANE_DNS_RESOLVER")
	if upstream == "" {
		upstream = "1.1.1.1"
	}
	if !strings.Contains(upstream, ":") {
		upstream += ":53"
	}

	rulesFile := os.Getenv("MEMBRANE_NETWORK_RULES_FILE")
	if rulesFile == "" {
		rulesFile = "/etc/membrane/network-rules.json"
	}
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		log.Fatalf("dns-proxy: read network rules: %v", err)
	}
	var rules struct {
		Allow []networkRule `json:"allow"`
		Deny  []networkRule `json:"deny"`
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		log.Fatalf("dns-proxy: parse network rules: %v", err)
	}
	if rules.Allow == nil || rules.Deny == nil {
		log.Fatal("dns-proxy: network rules must contain allow and deny lists")
	}
	allowed := buildHostSet(rules.Allow)
	denied := buildDeniedHosts(rules.Deny)
	log.Printf("dns-proxy: tracking %d hostnames, %d patterns, anyHost=%v, upstream=%s",
		len(allowed.exact), len(allowed.patterns), allowed.anyHost, upstream)

	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:53")
	if err != nil {
		log.Fatalf("dns-proxy: resolve listen addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("dns-proxy: listen: %v", err)
	}
	defer conn.Close()
	if err := os.WriteFile("/tmp/dns-proxy-ready", nil, 0644); err != nil {
		log.Fatalf("dns-proxy: signal readiness: %v", err)
	}
	defer os.Remove("/tmp/dns-proxy-ready")

	log.Printf("dns-proxy: listening on UDP :53")

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("dns-proxy: recv: %v", err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go handleQuery(pkt, clientAddr, conn, upstream, *allowed, denied)
	}
}

func extractQueryName(pkt []byte) string {
	if len(pkt) < 12 {
		return ""
	}
	if binary.BigEndian.Uint16(pkt[4:6]) == 0 {
		return ""
	}
	name, _ := parseDNSName(pkt, 12)
	return strings.TrimRight(strings.ToLower(name), ".")
}

// match preserves the allow resolver's exact/pattern union and any-host fallback.
func (allowed allowedSet) match(name string) (ports []portRule, matched, populateSets bool) {
	// populateSets indicates whether resolved IPs should be added to nftables.

	// 1. Exact match
	if p, ok := allowed.exact[name]; ok {
		ports = p
		matched = true
		populateSets = true
	}

	// 2. Pattern matches — union ports from all matching patterns
	for _, pe := range allowed.patterns {
		if ok, _ := filepath.Match(pe.pattern, name); ok {
			if !matched {
				ports = pe.ports
				matched = true
				populateSets = true
			} else {
				ports = unionPorts(ports, pe.ports)
				populateSets = true
			}
		}
	}

	// 3. Any-host fallback — resolve but do NOT populate nftables sets
	if !matched && allowed.anyHost {
		matched = true
		populateSets = false
	}

	return
}

func handleQuery(query []byte, clientAddr *net.UDPAddr, conn *net.UDPConn, upstream string, allowed allowedSet, denied []allowedSet) {
	// Reject packets with more than one question — we only validate the
	// first question name, so additional questions are an exfiltration
	// channel. Standard DNS always uses QDCOUNT=1.
	if len(query) >= 6 && binary.BigEndian.Uint16(query[4:6]) != 1 {
		resp := make([]byte, len(query))
		copy(resp, query)
		resp[2] = (query[2] & 0x01) | 0x80
		resp[3] = 0x83
		resp[6], resp[7] = 0, 0
		resp[8], resp[9] = 0, 0
		resp[10], resp[11] = 0, 0
		conn.WriteToUDP(resp, clientAddr)
		log.Printf("dns-proxy: blocked multi-question packet from %s", clientAddr)
		return
	}

	name := extractQueryName(query)

	ports, matched, populateSets := allowed.match(name)

	if !matched {
		resp := make([]byte, len(query))
		copy(resp, query)
		resp[2] = (query[2] & 0x01) | 0x80 // QR=1 (response), preserve RD bit
		resp[3] = 0x83                     // RA=1, RCODE=3 (NXDOMAIN)
		resp[6], resp[7] = 0, 0            // ANCOUNT = 0
		resp[8], resp[9] = 0, 0            // NSCOUNT = 0
		resp[10], resp[11] = 0, 0          // ARCOUNT = 0
		conn.WriteToUDP(resp, clientAddr)
		log.Printf("dns-proxy: blocked %s (not in allow list)", name)
		return
	}

	upstreamAddr, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		log.Printf("dns-proxy: resolve upstream: %v", err)
		return
	}
	upConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		log.Printf("dns-proxy: dial upstream: %v", err)
		return
	}
	defer upConn.Close()

	if _, err := upConn.Write(query); err != nil {
		log.Printf("dns-proxy: write upstream: %v", err)
		return
	}

	resp := make([]byte, 4096)
	upConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	rn, err := upConn.Read(resp)
	if err != nil {
		log.Printf("dns-proxy: read upstream: %v", err)
		return
	}
	resp = resp[:rn]

	// Parse response and update nftables before returning to client
	respName, ips := extractARecords(resp)
	for _, ip := range ips {
		for _, policy := range denied {
			denyPorts, denyMatch, _ := policy.match(name)
			if !denyMatch {
				continue
			}
			if err := addDeniedIP(ip, denyPorts); err != nil {
				// Never release a usable answer before its veto is installed.
				log.Printf("dns-proxy: install deny for %s: %v", name, err)
				return
			}
		}
	}
	if respName != "" && len(ips) > 0 && populateSets {
		respName = strings.ToLower(strings.TrimRight(respName, "."))
		for _, ip := range ips {
			if ports == nil {
				// any port: add to allowed-any-port
				if err := exec.Command("nft", "add", "element", "ip", "membrane",
					"allowed-any-port", "{", ip.String()+"/32", "}").Run(); err != nil {
					log.Printf("dns-proxy: nft add %s to allowed-any-port: %v", ip, err)
				}
				updateReverseMap(ip.String(), respName)
			} else {
				// port-constrained: add ip . proto . port triples
				for _, pr := range ports {
					elem := fmt.Sprintf("%s . %s . %d", ip.String(), pr.Proto, pr.Port)
					if err := exec.Command("nft", "add", "element", "ip", "membrane",
						"allowed", "{", elem, "}").Run(); err != nil {
						log.Printf("dns-proxy: nft add %s to allowed: %v", elem, err)
					}
				}
				updateReverseMap(ip.String(), respName)
			}
		}
		log.Printf("dns-proxy: %s → %v (ports=%v)", respName, ips, ports)
	}

	conn.WriteToUDP(resp, clientAddr)
}

// parseDNSName parses a DNS name from pkt at offset off,
// following compression pointers.
func parseDNSName(pkt []byte, off int) (string, int) {
	var parts []string
	jumped := false
	retOff := off
	seen := make(map[int]bool)
	for off < len(pkt) {
		if seen[off] {
			break
		}
		seen[off] = true
		length := int(pkt[off])
		if length == 0 {
			off++
			if !jumped {
				retOff = off
			}
			break
		}
		if length&0xC0 == 0xC0 {
			if off+1 >= len(pkt) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(pkt[off:off+2])) & 0x3FFF
			if !jumped {
				retOff = off + 2
			}
			jumped = true
			off = ptr
			continue
		}
		off++
		if off+length > len(pkt) {
			break
		}
		parts = append(parts, string(pkt[off:off+length]))
		off += length
	}
	if !jumped {
		retOff = off
	}
	return strings.Join(parts, "."), retOff
}

// extractARecords parses a DNS response and returns the queried name
// and all A record IPs from the answer section.
func extractARecords(pkt []byte) (string, []net.IP) {
	if len(pkt) < 12 {
		return "", nil
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags>>15 != 1 {
		return "", nil // not a response
	}
	qdcount := int(binary.BigEndian.Uint16(pkt[4:6]))
	ancount := int(binary.BigEndian.Uint16(pkt[6:8]))

	off := 12
	var queryName string
	for i := 0; i < qdcount; i++ {
		name, newOff := parseDNSName(pkt, off)
		if i == 0 {
			queryName = name
		}
		off = newOff + 4 // skip QTYPE + QCLASS
		if off > len(pkt) {
			return "", nil
		}
	}

	var ips []net.IP
	for i := 0; i < ancount; i++ {
		if off >= len(pkt) {
			break
		}
		_, newOff := parseDNSName(pkt, off)
		off = newOff
		if off+10 > len(pkt) {
			break
		}
		rtype := binary.BigEndian.Uint16(pkt[off : off+2])
		rclass := binary.BigEndian.Uint16(pkt[off+2 : off+4])
		rdlength := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		off += 10
		if off+rdlength > len(pkt) {
			break
		}
		if rtype == 1 && rclass == 1 && rdlength == 4 {
			ips = append(ips, net.IPv4(pkt[off], pkt[off+1], pkt[off+2], pkt[off+3]))
		}
		off += rdlength
	}
	return queryName, ips
}
