package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/matchlighter/headscale-domain-proxies/internal/domain"
	"github.com/tailscale/hujson"
)

func TestSampleUsesValuedNodeAttrAppPayload(t *testing.T) {
	path := filepath.Join("..", "..", "sample.jsonc")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	standard, err := hujson.Standardize(b)
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		NodeAttrs []struct {
			App map[string]json.RawMessage `json:"app"`
		}
	}
	if err := json.Unmarshal(standard, &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.NodeAttrs) == 0 {
		t.Fatal("sample has no NodeAttrs")
	}
	for _, nodeAttr := range policy.NodeAttrs {
		raw, ok := nodeAttr.App[domain.NodeConfigCapability]
		if !ok {
			t.Fatalf("NodeAttr must use app.%s for its valued payload", domain.NodeConfigCapability)
		}
		if _, ok := domain.ConfigFromNodeAttrs(map[string]json.RawMessage{domain.NodeConfigCapability: raw}); !ok {
			t.Fatal("sample app payload is not a valid domain gateway configuration")
		}
	}
}

func TestSampleDomainGrantUsesIPPortPolicy(t *testing.T) {
	path := filepath.Join("..", "..", "sample.jsonc")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	standard, err := hujson.Standardize(b)
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Grants []struct {
			App map[string]json.RawMessage `json:"app"`
		}
	}
	if err := json.Unmarshal(standard, &policy); err != nil {
		t.Fatal(err)
	}
	gateways := map[string]domain.Gateway{"tag:gateway1": {}}
	for _, grant := range policy.Grants {
		raw, ok := grant.App[domain.Capability]
		if !ok {
			continue
		}
		parsed := domain.Parse(map[string]json.RawMessage{domain.Capability: raw}, gateways)
		if !domain.Authorize(parsed, "tag:gateway1", "example.org", "udp", 5000) {
			t.Fatal("sample ip entry did not authorize its UDP port")
		}
		if domain.Authorize(parsed, "tag:gateway1", "example.org", "tcp", 5000) {
			t.Fatal("sample ip entry authorized an unlisted protocol")
		}
		gateway, ok := domain.GatewayFor(parsed, gateways, "tag:gateway1", "example.org", "udp", 5000)
		if !ok || gateway.Resolver != "192.0.2.54:53" {
			t.Fatalf("sample resource resolver = %#v, %v", gateway, ok)
		}
		return
	}
	t.Fatal("sample has no domain gateway grant")
}

func TestAuthKeyDoesNotAdvertiseTags(t *testing.T) {
	server, err := newTSNet(config{TSNet: tsnetConfig{Dir: t.TempDir(), AuthKey: "tskey-auth-test", Tags: []string{"tag:dns"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(server.AdvertiseTags) != 0 {
		t.Fatalf("auth-key node must not request tags: %v", server.AdvertiseTags)
	}
}
