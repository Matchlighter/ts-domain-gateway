package domain

import (
	"encoding/json"
	"testing"
)

func TestUpstreamNodeAttr(t *testing.T) {
	if got, ok := ConfigFromNodeAttrs(map[string]json.RawMessage{NodeConfigCapability: json.RawMessage(`[{"upstreamDNS":"system","gateways":[{"tag":"tag:home","prefix":"10.254.0.0/24"}]}]`)}); !ok || got.UpstreamDNS != "system" || len(got.Gateways) != 1 {
		t.Fatal(got, ok)
	}
	if _, ok := ConfigFromNodeAttrs(map[string]json.RawMessage{NodeConfigCapability: json.RawMessage(`[{"upstreamDNS":"not-an-address","gateways":[{"tag":"tag:home","prefix":"10.254.0.0/24"}]}]`)}); ok {
		t.Fatal("accepted malformed resolver")
	}
}

func TestNodeAttrsRejectAmbiguousGatewaySegments(t *testing.T) {
	tests := []string{
		`[{"upstreamDNS":"system","gateways":[{"tag":"tag:home","prefix":"10.254.0.0/24"},{"tag":"tag:work","prefix":"10.254.0.128/25"}]}]`,
		`[{"upstreamDNS":"system","gateways":[{"tag":"tag:home","prefix":"10.254.0.0/24"}]},{"upstreamDNS":"system","gateways":[{"tag":"tag:home","prefix":"10.254.1.0/24"}]}]`,
	}
	for _, raw := range tests {
		if _, ok := ConfigFromNodeAttrs(map[string]json.RawMessage{NodeConfigCapability: json.RawMessage(raw)}); ok {
			t.Fatalf("accepted ambiguous gateway configuration: %s", raw)
		}
	}
}
