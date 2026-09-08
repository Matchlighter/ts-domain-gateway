package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matchlighter/headscale-domain-proxies/internal/domain"
	"github.com/tailscale/hujson"
)

func readReadmePolicy(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	const start = "### Policy\n```jsonc\n"
	startAt := strings.Index(string(b), start)
	if startAt < 0 {
		t.Fatal("README policy block not found")
	}
	policy, _, ok := strings.Cut(string(b)[startAt+len(start):], "\n```")
	if !ok {
		t.Fatal("README policy block is not terminated")
	}
	return []byte(policy)
}

func TestReadmePolicyUsesValuedNodeAttrAppPayload(t *testing.T) {
	standard, err := hujson.Standardize(readReadmePolicy(t))
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
		t.Fatal("README policy has no NodeAttrs")
	}
	for _, nodeAttr := range policy.NodeAttrs {
		raw, ok := nodeAttr.App[domain.NodeConfigCapability]
		if !ok {
			t.Fatalf("README NodeAttr must use app.%s for its valued payload", domain.NodeConfigCapability)
		}
		if _, ok := domain.ConfigFromNodeAttrs(map[string]json.RawMessage{domain.NodeConfigCapability: raw}); !ok {
			t.Fatal("README app payload is not a valid domain gateway configuration")
		}
	}
}

func TestReadmePolicyDomainGrantUsesIPPortPolicy(t *testing.T) {
	standard, err := hujson.Standardize(readReadmePolicy(t))
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
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.254.0.0/18")}
	for _, grant := range policy.Grants {
		raw, ok := grant.App[domain.Capability]
		if !ok {
			continue
		}
		parsed := domain.Parse(map[string]json.RawMessage{domain.Capability: raw})
		if !domain.Authorize(parsed, prefixes, "example.org", "tcp", 443) {
			t.Fatal("README ip entry did not authorize its TCP port")
		}
		if domain.Authorize(parsed, prefixes, "example.org", "udp", 443) {
			t.Fatal("README ip entry authorized an unsupported protocol")
		}
		return
	}
	t.Fatal("README policy has no domain gateway grant")
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
