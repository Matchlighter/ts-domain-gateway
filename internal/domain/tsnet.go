package domain

import (
	"context"
	"encoding/json"
	"net/netip"

	"tailscale.com/client/local"
)

// TSNetIdentity adapts an embedded tsnet node's in-process LocalClient to the
// same authorization boundary used by a host tailscaled daemon.
type TSNetIdentity struct{ Client *local.Client }

func capMap(values map[string]json.RawMessage) map[string]json.RawMessage { return values }

func (i TSNetIdentity) Capabilities(ctx context.Context, source, destination netip.Addr) (map[string]json.RawMessage, error) {
	response, err := i.Client.WhoIs(ctx, source.String())
	if err != nil {
		return nil, err
	}
	result := make(map[string]json.RawMessage, len(response.CapMap))
	for capability, values := range response.CapMap {
		raw, err := json.Marshal(values)
		if err != nil {
			return nil, err
		}
		result[string(capability)] = raw
	}
	return result, nil
}

func (i TSNetIdentity) IsGateway(ctx context.Context, source netip.Addr, gateways map[string]Gateway) (bool, error) {
	response, err := i.Client.WhoIs(ctx, source.String())
	if err != nil {
		return false, err
	}
	for _, tag := range response.Node.Tags {
		if _, ok := gateways[tag]; ok {
			return true, nil
		}
	}
	return false, nil
}

func (i TSNetIdentity) NodeConfig(ctx context.Context) (NodeConfig, error) {
	status, err := i.Client.Status(ctx)
	if err != nil {
		return NodeConfig{}, err
	}
	raw := make(map[string]json.RawMessage, len(status.Self.CapMap))
	for capability, values := range status.Self.CapMap {
		encoded, err := json.Marshal(values)
		if err != nil {
			return NodeConfig{}, err
		}
		raw[string(capability)] = encoded
	}
	config, ok := ConfigFromNodeAttrs(raw)
	if !ok {
		return NodeConfig{}, context.DeadlineExceeded
	}
	return config, nil
}
