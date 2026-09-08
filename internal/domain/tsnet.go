package domain

import (
	"context"
	"encoding/json"
	"net/netip"

	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
)

// TSNetIdentity adapts an embedded tsnet node's in-process LocalClient to the
// same authorization boundary used by a host tailscaled daemon.
type TSNetIdentity struct{ Client *local.Client }

func encodeCapMap[K ~string, M ~map[K][]tailcfg.RawMessage](values M) (map[string]json.RawMessage, error) {
	result := make(map[string]json.RawMessage, len(values))
	for capability, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		result[string(capability)] = raw
	}
	return result, nil
}

func (i TSNetIdentity) Capabilities(ctx context.Context, source, destination netip.Addr) (map[string]json.RawMessage, error) {
	response, err := i.Client.WhoIs(ctx, source.String())
	if err != nil {
		return nil, err
	}
	return encodeCapMap(response.CapMap)
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
	raw, err := encodeCapMap(status.Self.CapMap)
	if err != nil {
		return NodeConfig{}, err
	}
	config, ok := ConfigFromNodeAttrs(raw)
	if !ok {
		return NodeConfig{}, context.DeadlineExceeded
	}
	return config, nil
}

// TaggedNodes returns tsnet's current stable LocalClient status inventory.
func (i TSNetIdentity) TaggedNodes(ctx context.Context) ([]TaggedNode, error) {
	status, err := i.Client.Status(ctx)
	if err != nil {
		return nil, err
	}
	nodes := make([]statusNode, 0, len(status.Peer)+1)
	if status.Self != nil {
		node := statusNode{TailscaleIPs: status.Self.TailscaleIPs}
		if status.Self.Tags != nil {
			node.Tags = status.Self.Tags.AsSlice()
		}
		nodes = append(nodes, node)
	}
	for _, peer := range status.Peer {
		if peer != nil {
			node := statusNode{TailscaleIPs: peer.TailscaleIPs}
			if peer.Tags != nil {
				node.Tags = peer.Tags.AsSlice()
			}
			nodes = append(nodes, node)
		}
	}
	return taggedNodes(nodes), nil
}
