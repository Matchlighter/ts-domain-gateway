package domain

import (
	"encoding/json"
	"net"
	"strings"
)

// NodeConfigCapability is a NodeAttr (not a peer-grant capability).
const NodeConfigCapability = "matchlighter.net/domain-gateway"

type NodeConfig struct {
	UpstreamDNS    string `json:"upstreamDNS"`
	HasUpstreamDNS bool   `json:"-"`
}

// ConfigFromNodeAttrs accepts typed resolver configuration. Gateway ranges
// belong to the egress configuration and the policy grants, not NodeAttrs.
func ConfigFromNodeAttrs(caps map[string]json.RawMessage) (NodeConfig, bool) {
	raw, ok := caps[NodeConfigCapability]
	if !ok {
		return NodeConfig{UpstreamDNS: "system"}, true
	}
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) == 0 {
		return NodeConfig{}, false
	}
	result := NodeConfig{}
	for _, raw := range values {
		var config struct {
			UpstreamDNS string          `json:"upstreamDNS"`
			Gateways    json.RawMessage `json:"gateways"`
		}
		if json.Unmarshal(raw, &config) != nil || config.UpstreamDNS == "" || config.Gateways != nil {
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
		result.HasUpstreamDNS = true
	}
	return result, true
}

func IsSystemResolver(resolver string) bool { return strings.EqualFold(resolver, "system") }
