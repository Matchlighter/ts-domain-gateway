package domain

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
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
