package domain

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestProxyTCPUsesConfiguredPTRLookup(t *testing.T) {
	called := false
	s := &Service{PTRLookup: func(_ context.Context, ip netip.Addr) ([]string, error) {
		called = true
		if ip != netip.MustParseAddr("10.254.0.1") {
			t.Fatalf("PTR lookup IP = %v", ip)
		}
		return nil, errors.New("stop after lookup")
	}}
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	s.ProxyTCP(context.Background(), client, netip.MustParseAddrPort("100.64.0.2:40000"), netip.MustParseAddrPort("10.254.0.1:443"))
	if !called {
		t.Fatal("configured PTR lookup was not called")
	}
}

func TestProxyTCPResolvesThroughResourcePolicyResolver(t *testing.T) {
	resolver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	queried := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 1500)
		n, address, err := resolver.ReadFrom(buf)
		if err != nil {
			return
		}
		var parser dnsmessage.Parser
		header, err := parser.Start(buf[:n])
		if err != nil {
			return
		}
		question, err := parser.Question()
		if err != nil {
			return
		}
		response, err := (&dnsmessage.Message{
			Header:    dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true},
			Questions: []dnsmessage.Question{question},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1},
				Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			}},
		}).Pack()
		if err == nil {
			_, _ = resolver.WriteTo(response, address)
			select {
			case queried <- struct{}{}:
			default:
			}
		}
	}()

	source := netip.MustParseAddr("100.64.0.2")
	service := &Service{
		Identity: fakeIdentity{source: map[string]json.RawMessage{Capability: json.RawMessage(`[
			{"gateway":"tag:home","resources":[{"domain":"app.example.com","upstreamDNS":"` + resolver.LocalAddr().String() + `"}]}
		]`)}},
		Gateways: map[string]Gateway{"tag:home": {
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")},
			Resolver: "127.0.0.1:1",
		}},
		PTRLookup: func(context.Context, netip.Addr) ([]string, error) { return []string{"app.example.com."}, nil },
	}
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	go service.ProxyTCP(context.Background(), client, netip.AddrPortFrom(source, 40000), netip.MustParseAddrPort("10.254.0.2:40443"))

	select {
	case <-queried:
	case <-time.After(time.Second):
		t.Fatal("proxy did not query the resource policy resolver")
	}
}
