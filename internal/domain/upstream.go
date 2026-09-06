package domain

import (
	"encoding/json"
	"net"
	"net/netip"
	"strings"
)

// NodeConfigCapability is a NodeAttr (not a peer-grant capability).
const NodeConfigCapability = "matchlighter.net/cap/domain-gateway-config"

type NodeConfig struct {
	UpstreamDNS string `json:"upstreamDNS"`
	Gateways    map[string][]netip.Prefix
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
	seen := []netip.Prefix{}
	for _, raw := range values {
		var config struct {
			UpstreamDNS string `json:"upstreamDNS"`
			Gateways    map[string]struct {
				Ranges []string `json:"range"`
			} `json:"gateways"`
		}
		if json.Unmarshal(raw, &config) != nil || config.UpstreamDNS == "" || (config.Gateways != nil && len(config.Gateways) == 0) {
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
		for tag, gateway := range config.Gateways {
			if result.Gateways == nil {
				// A nil map means no administrator override was supplied, so DNS
				// must discover active gateway routes. Allocate it only once an
				// actual gateway entry is encountered.
				result.Gateways = map[string][]netip.Prefix{}
			}
			if tag == "" || len(gateway.Ranges) == 0 {
				return NodeConfig{}, false
			}
			for _, value := range gateway.Ranges {
				prefix, err := netip.ParsePrefix(value)
				if err != nil || !prefix.Addr().Is4() {
					return NodeConfig{}, false
				}
				for _, prior := range seen {
					if prefix.Overlaps(prior) {
						return NodeConfig{}, false
					}
				}
				seen = append(seen, prefix)
				result.Gateways[tag] = append(result.Gateways[tag], prefix)
			}
		}
	}
	return result, true
}

func IsSystemResolver(resolver string) bool { return strings.EqualFold(resolver, "system") }
