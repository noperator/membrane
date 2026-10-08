package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dnsPacket(name string, answer bool) []byte {
	packet := make([]byte, 12)
	packet[0], packet[1], packet[2], packet[5] = 0x12, 0x34, 1, 1
	for _, label := range strings.Split(name, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 1, 0, 1)
	if answer {
		packet[2], packet[3], packet[7] = 0x81, 0x80, 1
		packet = append(packet, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
	}
	return packet
}

func TestDNSDenyInstalledBeforeAnswer(t *testing.T) {
	for _, mode := range []string{"success", "nft-failure", "deny-only"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			logfile := filepath.Join(dir, "nft.log")
			t.Setenv("NFT_LOG", logfile)
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			exit := "0"
			if mode == "nft-failure" {
				exit = "1"
			}
			if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\necho \"$*\" >> \"$NFT_LOG\"\nexit "+exit+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			listen := func() *net.UDPConn {
				c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				return c
			}
			upstream, proxy, client := listen(), listen(), listen()
			go func() {
				buf := make([]byte, 512)
				_, addr, err := upstream.ReadFromUDP(buf)
				if err == nil {
					upstream.WriteToUDP(dnsPacket("blocked.test", true), addr)
				}
			}()
			allowed := buildHostSet([]networkRule{{Type: "any"}})
			if mode == "deny-only" {
				allowed = buildHostSet(nil)
			}
			denied := buildHostSet([]networkRule{{Type: "host", Host: "blocked.test", Ports: []portRule{{53, "udp"}, {443, "tcp"}}}})
			allTCP := buildHostSet([]networkRule{{Type: "host", Host: "blocked.test"}})
			handleQuery(dnsPacket("blocked.test", false), client.LocalAddr().(*net.UDPAddr), proxy, upstream.LocalAddr().String(), *allowed, []allowedSet{*allTCP, *denied})
			client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			buf := make([]byte, 512)
			n, _, err := client.ReadFromUDP(buf)
			log, _ := os.ReadFile(logfile)
			switch mode {
			case "success":
				if err != nil || n == 0 || binary.BigEndian.Uint16(buf[6:8]) != 1 {
					t.Fatalf("answer: %d %v", n, err)
				}
				if !strings.Contains(string(log), "denied-any-port { 192.0.2.1/32 }") {
					t.Fatalf("missing all-TCP deny alongside UDP deny: %s", log)
				}
				for _, elem := range []string{"192.0.2.1 . udp . 53", "192.0.2.1 . tcp . 443"} {
					if !strings.Contains(string(log), "denied { "+elem+" }") {
						t.Fatalf("deny not installed before answer: %s", log)
					}
				}
			case "nft-failure":
				if err == nil {
					t.Fatal("DNS answer escaped failed deny update")
				}
			case "deny-only":
				if err != nil || buf[3]&0xf != 3 || len(log) != 0 {
					t.Fatalf("deny authorized resolution: %v %s", err, log)
				}
			}
		})
	}
}
