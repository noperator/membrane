package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const reverseMapFile = "/tmp/membrane-dns-map.json"

type portRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // "tcp" or "udp"
}

type allowRule struct {
	Type  string     `json:"type"`
	Host  string     `json:"host"`
	Ports []portRule `json:"ports"`
}

// buildAllowedHosts parses MEMBRANE_ALLOW JSON and returns a map of
// hostname → allowed ports. A nil ports slice means any port is allowed.
func buildAllowedHosts(allowJSON string) map[string][]portRule {
	var rules []allowRule
	if err := json.Unmarshal([]byte(allowJSON), &rules); err != nil {
		log.Printf("dns-proxy: parse MEMBRANE_ALLOW: %v", err)
		return make(map[string][]portRule)
	}
	allowed := make(map[string][]portRule)
	for _, r := range rules {
		if r.Type != "host" && r.Type != "url" {
			continue
		}
		host := strings.ToLower(r.Host)
		if host == "" {
			continue
		}
		// If already any-port, no further expansion needed
		if existing, ok := allowed[host]; ok && existing == nil {
			continue
		}
		if len(r.Ports) == 0 {
			allowed[host] = nil
		} else {
			allowed[host] = appendUniquePorts(allowed[host], r.Ports...)
		}
	}
	return allowed
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

	allowFile := os.Getenv("MEMBRANE_ALLOW_FILE")
	if allowFile == "" {
		allowFile = "/etc/membrane/allow.json"
	}
	data, err := os.ReadFile(allowFile)
	if err != nil {
		log.Fatalf("dns-proxy: read allow file: %v", err)
	}
	allowed := buildAllowedHosts(string(data))
	log.Printf("dns-proxy: tracking %d hostnames, upstream=%s", len(allowed), upstream)

	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:53")
	if err != nil {
		log.Fatalf("dns-proxy: resolve listen addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("dns-proxy: listen: %v", err)
	}
	defer conn.Close()
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
		go handleQuery(pkt, clientAddr, conn, upstream, allowed)
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

func handleQuery(query []byte, clientAddr *net.UDPAddr, conn *net.UDPConn, upstream string, allowed map[string][]portRule) {
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
	if _, ok := allowed[name]; !ok {
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
	name, ips := extractARecords(resp)
	if name != "" && len(ips) > 0 {
		name = strings.ToLower(strings.TrimRight(name, "."))
		if ports, ok := allowed[name]; ok {
			for _, ip := range ips {
				if ports == nil {
					// any port: add to allowed-any-port
					if err := exec.Command("nft", "add", "element", "ip", "membrane",
						"allowed-any-port", "{", ip.String()+"/32", "}").Run(); err != nil {
						log.Printf("dns-proxy: nft add %s to allowed-any-port: %v", ip, err)
					}
					updateReverseMap(ip.String(), name)
				} else {
					// port-constrained: add ip . proto . port triples
					for _, pr := range ports {
						elem := fmt.Sprintf("%s . %s . %d", ip.String(), pr.Proto, pr.Port)
						if err := exec.Command("nft", "add", "element", "ip", "membrane",
							"allowed", "{", elem, "}").Run(); err != nil {
							log.Printf("dns-proxy: nft add %s to allowed: %v", elem, err)
						}
					}
					updateReverseMap(ip.String(), name)
				}
			}
			log.Printf("dns-proxy: %s → %v (ports=%v)", name, ips, ports)
		}
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
