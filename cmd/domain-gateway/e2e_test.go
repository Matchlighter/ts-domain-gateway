package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

func TestE2EAuthorizedDNSOverUDP(t *testing.T) {
	authKey := os.Getenv("DOMAIN_GATEWAY_E2E_AUTHKEY")
	controlURL := os.Getenv("DOMAIN_GATEWAY_E2E_CONTROL_URL")
	if authKey == "" || controlURL == "" {
		t.Skip("set DOMAIN_GATEWAY_E2E_AUTHKEY and DOMAIN_GATEWAY_E2E_CONTROL_URL")
	}
	server := &tsnet.Server{Dir: t.TempDir(), Hostname: "e2e-client", AuthKey: authKey, ControlURL: controlURL}
	if _, err := server.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := server.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.EditPrefs(context.Background(), &ipn.MaskedPrefs{Prefs: ipn.Prefs{RouteAll: true}, RouteAllSet: true}); err != nil {
		t.Fatal(err)
	}
	name := dnsmessage.MustNewName("example.com.")
	request, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 1, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := server.Dial(context.Background(), "udp", "100.64.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(response[:n]); err != nil {
		t.Fatal(err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	_, err = parser.AnswerHeader()
	if err != nil {
		t.Fatal(err)
	}
	a, err := parser.AResource()
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.AddrFrom4(a.A)
	if !netip.MustParsePrefix("10.254.0.0/18").Contains(ip) {
		t.Fatalf("synthetic address %s outside gateway prefix", ip)
	}
}

func TestE2EAuthorizedTLS(t *testing.T) {
	authKey := os.Getenv("DOMAIN_GATEWAY_E2E_AUTHKEY")
	controlURL := os.Getenv("DOMAIN_GATEWAY_E2E_CONTROL_URL")
	if authKey == "" || controlURL == "" {
		t.Skip("set DOMAIN_GATEWAY_E2E_AUTHKEY and DOMAIN_GATEWAY_E2E_CONTROL_URL")
	}
	server := &tsnet.Server{Dir: t.TempDir(), Hostname: "e2e-tls-client", AuthKey: authKey, ControlURL: controlURL}
	if _, err := server.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := server.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.EditPrefs(context.Background(), &ipn.MaskedPrefs{Prefs: ipn.Prefs{RouteAll: true}, RouteAllSet: true}); err != nil {
		t.Fatal(err)
	}

	// The allocation is owned by DNS; this test deliberately asks the live DNS
	// service first instead of manufacturing a synthetic destination.
	ip := lookupE2EA(t, server, "example.com.")
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := server.Dial(dialCtx, "tcp", netip.AddrPortFrom(ip, 443).String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12})
	defer tlsConn.Close()
	if err := tlsConn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tlsConn, "HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) == 0 {
		t.Fatal("TLS backend returned no HTTP response")
	}
}

func TestE2EAdvertisedDNSPTR(t *testing.T) {
	authKey, controlURL := os.Getenv("DOMAIN_GATEWAY_E2E_AUTHKEY"), os.Getenv("DOMAIN_GATEWAY_E2E_CONTROL_URL")
	if authKey == "" || controlURL == "" {
		t.Skip("set DOMAIN_GATEWAY_E2E_AUTHKEY and DOMAIN_GATEWAY_E2E_CONTROL_URL")
	}
	server := &tsnet.Server{Dir: t.TempDir(), Hostname: "e2e-ptr-client", AuthKey: authKey, ControlURL: controlURL}
	if _, err := server.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := server.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.EditPrefs(context.Background(), &ipn.MaskedPrefs{Prefs: ipn.Prefs{RouteAll: true}, RouteAllSet: true}); err != nil {
		t.Fatal(err)
	}
	ip := lookupE2EA(t, server, "example.com.")
	octets := ip.As4()
	name := dnsmessage.MustNewName(fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", octets[3], octets[2], octets[1], octets[0]))
	request, err := (&dnsmessage.Message{Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	dnsConfig, err := client.DNSConfig(context.Background())
	if err != nil || len(dnsConfig.Resolvers) == 0 {
		t.Fatal("advertised DNS resolver unavailable", err)
	}
	dnsAddr := dnsConfig.Resolvers[0].Addr
	if _, _, err := net.SplitHostPort(dnsAddr); err != nil {
		dnsAddr = net.JoinHostPort(dnsAddr, "53")
	}
	conn, err := server.Dial(context.Background(), "udp", dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AnswerHeader(); err != nil {
		t.Fatal(err)
	}
	ptr, err := p.PTRResource()
	if err != nil {
		t.Fatal(err)
	}
	if ptr.PTR.String() != "example.com." {
		t.Fatalf("PTR = %s", ptr.PTR)
	}
}

func lookupE2EA(t *testing.T, server *tsnet.Server, domain string) netip.Addr {
	t.Helper()
	name := dnsmessage.MustNewName(domain)
	request, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 2, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := server.Dial(dialCtx, "udp", "100.64.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	if _, err := parser.AnswerHeader(); err != nil {
		t.Fatal(err)
	}
	a, err := parser.AResource()
	if err != nil {
		t.Fatal(err)
	}
	return netip.AddrFrom4(a.A)
}
