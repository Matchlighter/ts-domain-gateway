package domain

import (
	"encoding/json"
	"net"
	"net/netip"
	"strings"
)

// NodeConfigCapability is a NodeAttr (not a peer-grant capability).
const NodeConfigCapability = "matchlighter.net/cap/domain-gateway-config"

type NodeGateway struct {
	Tag    string `json:"tag"`
	Prefix string `json:"prefix"`
}
type NodeConfig struct {
	UpstreamDNS string        `json:"upstreamDNS"`
	Gateways    []NodeGateway `json:"gateways"`
}

// ConfigFromNodeAttrs accepts typed objects. Values merge additively, but
// conflicting resolver or prefix definitions fail closed.
func ConfigFromNodeAttrs(caps map[string]json.RawMessage) (NodeConfig, bool) {
	raw, ok := caps[NodeConfigCapability]
	if !ok {
		return NodeConfig{}, false
	}
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) == 0 {
		return NodeConfig{}, false
	}
	result := NodeConfig{}
	seen := map[string]netip.Prefix{}
	for _, raw := range values {
		var config NodeConfig
		if json.Unmarshal(raw, &config) != nil || config.UpstreamDNS == "" || len(config.Gateways) == 0 {
			return NodeConfig{}, false
		}
		resolver := config.UpstreamDNS
		if resolver != "system" {
			host, port, err := net.SplitHostPort(resolver)
			if err != nil || host == "" || port == "" {
				return NodeConfig{}, false
			}
		}
		if result.UpstreamDNS != "" && result.UpstreamDNS != resolver {
			return NodeConfig{}, false
		}
		result.UpstreamDNS = resolver
		for _, gateway := range config.Gateways {
			prefix, err := netip.ParsePrefix(gateway.Prefix)
			if err != nil || !prefix.Addr().Is4() || gateway.Tag == "" {
				return NodeConfig{}, false
			}
			if prior, exists := seen[gateway.Tag]; exists && prior != prefix {
				return NodeConfig{}, false
			}
			for tag, prior := range seen {
				if tag != gateway.Tag && prefix.Overlaps(prior) {
					return NodeConfig{}, false
				}
			}
			if _, exists := seen[gateway.Tag]; !exists {
				seen[gateway.Tag] = prefix
				result.Gateways = append(result.Gateways, gateway)
			}
		}
	}
	return result, true
}

func IsSystemResolver(resolver string) bool { return strings.EqualFold(resolver, "system") }
