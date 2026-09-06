package domain

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
)

func TestNodeAttrConfiguresTagKeyedMultiRangeGateway(t *testing.T) {
	got, ok := ConfigFromNodeAttrs(map[string]json.RawMessage{NodeConfigCapability: json.RawMessage(`[{"upstreamDNS":"system","gateways":{"tag:home":{"range":["10.254.0.0/30","10.254.1.0/30"]}}}]`)})
	if !ok || got.UpstreamDNS != "system" || len(got.Gateways["tag:home"]) != 2 {
		t.Fatal(got, ok)
	}
	if got.Gateways["tag:home"][1] != netip.MustParsePrefix("10.254.1.0/30") {
		t.Fatalf("second range = %s", got.Gateways["tag:home"][1])
	}
	if _, ok := ConfigFromNodeAttrs(map[string]json.RawMessage{NodeConfigCapability: json.RawMessage(`[{"upstreamDNS":"not-an-address","gateways":{"tag:home":{"range":["10.254.0.0/24"]}}}]`)}); ok {
		t.Fatal("accepted malformed resolver")
	}
}

func TestNodeAttrsRejectInvalidDuplicateAndOverlappingRanges(t *testing.T) {
	tests := []string{
		`[{"upstreamDNS":"system","gateways":{"tag:home":{"range":["10.254.0.0/24","10.254.0.0/24"]}}}]`,
		`[{"upstreamDNS":"system","gateways":{"tag:home":{"range":["10.254.0.0/24"]},"tag:work":{"range":["10.254.0.128/25"]}}}]`,
		`[{"upstreamDNS":"system","gateways":{"tag:home":{"range":["not-a-prefix"]}}}]`,
	}
	for _, raw := range tests {
		if _, ok := ConfigFromNodeAttrs(map[string]json.RawMessage{NodeConfigCapability: json.RawMessage(raw)}); ok {
			t.Fatalf("accepted ambiguous gateway configuration: %s", raw)
		}
	}
}

func TestServiceAllocatesAndAuthorizesAcrossGatewayRanges(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/30"), netip.MustParsePrefix("10.254.1.0/30")}}}
	source := netip.MustParseAddr("100.64.0.2")
	caps := map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"one.example.com"},{"domain":"two.example.com"},{"domain":"three.example.com"},{"domain":"four.example.com"}]}]`)}
	service := &Service{Identity: fakeIdentity{source: caps}, Gateways: gateways, Allocations: NewAllocator()}
	for _, name := range []string{"one.example.com", "two.example.com", "three.example.com", "four.example.com"} {
		ip, ok := service.DNS(context.Background(), source, name)
		if !ok {
			t.Fatalf("DNS did not allocate %s", name)
		}
		if name == "four.example.com" {
			if !gateways["tag:home"].Prefixes[1].Contains(ip) {
				t.Fatalf("fourth allocation %s did not use second range", ip)
			}
			if mapping, _, ok := service.Flow(context.Background(), source, ip, "tcp", 443); !ok || mapping.Domain != name {
				t.Fatalf("second-range reverse mapping/flow = %#v, %v", mapping, ok)
			}
			if _, ok := service.FlowDomain(context.Background(), source, ip, name, "tcp", 443); !ok {
				t.Fatalf("second-range flow for %s was denied", ip)
			}
		}
	}
}
