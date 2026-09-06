package domain

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"sync/atomic"
	"time"
)

type Identity interface {
	Capabilities(context.Context, netip.Addr, netip.Addr) (map[string]json.RawMessage, error)
}
type GatewaySource interface {
	IsGateway(context.Context, netip.Addr, map[string]Gateway) (bool, error)
}
type LocalAPI struct{ client *http.Client }

func NewLocalAPI(socket string) *LocalAPI {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	return &LocalAPI{&http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}}}
}
func (l *LocalAPI) Capabilities(ctx context.Context, source, destination netip.Addr) (map[string]json.RawMessage, error) {
	v := url.Values{"addr": {source.String()}}
	if destination.IsValid() {
		v.Set("dst_ip", destination.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled/localapi/v0/whois?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}
	res, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, &url.Error{Op: "whois", URL: req.URL.String(), Err: context.DeadlineExceeded}
	}
	var response struct{ CapMap map[string]json.RawMessage }
	err = json.NewDecoder(res.Body).Decode(&response)
	if err != nil || response.CapMap == nil {
		return nil, context.DeadlineExceeded
	}
	return response.CapMap, nil
}

func (l *LocalAPI) IsGateway(ctx context.Context, source netip.Addr, gateways map[string]Gateway) (bool, error) {
	v := url.Values{"addr": {source.String()}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled/localapi/v0/whois?"+v.Encode(), nil)
	if err != nil {
		return false, err
	}
	res, err := l.client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	var response struct{ Node struct{ Tags []string } }
	if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&response) != nil {
		return false, context.DeadlineExceeded
	}
	for _, tag := range response.Node.Tags {
		if _, ok := gateways[tag]; ok {
			return true, nil
		}
	}
	return false, nil
}

// NodeConfig reads this process's typed NodeAttrs from local tailscaled.
func (l *LocalAPI) NodeConfig(ctx context.Context) (NodeConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled/localapi/v0/status", nil)
	if err != nil {
		return NodeConfig{}, err
	}
	res, err := l.client.Do(req)
	if err != nil {
		return NodeConfig{}, err
	}
	defer res.Body.Close()
	var status struct {
		Self struct{ CapMap map[string]json.RawMessage }
	}
	if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&status) != nil {
		return NodeConfig{}, context.DeadlineExceeded
	}
	if config, ok := ConfigFromNodeAttrs(status.Self.CapMap); ok {
		return config, nil
	}
	return NodeConfig{}, context.DeadlineExceeded
}

// TailscaleIP returns the first IPv4 address assigned to the host daemon.
// DNS binds this address so it is reachable only through the selected
// tailscaled transport rather than an arbitrary host interface.
func (l *LocalAPI) TailscaleIP(ctx context.Context) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled/localapi/v0/status", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	res, err := l.client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer res.Body.Close()
	var status struct{ TailscaleIPs []netip.Addr }
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&status) != nil {
		return netip.Addr{}, context.DeadlineExceeded
	}
	for _, ip := range status.TailscaleIPs {
		if ip.Is4() {
			return ip, nil
		}
	}
	return netip.Addr{}, context.DeadlineExceeded
}

// TaggedNodes reads the local daemon's current, control-plane-authoritative
// tailnet status. Tag DNS deliberately does not participate in authorization.
func (l *LocalAPI) TaggedNodes(ctx context.Context) ([]TaggedNode, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled/localapi/v0/status", nil)
	if err != nil {
		return nil, err
	}
	res, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var status struct {
		Self *statusNode            `json:"Self"`
		Peer map[string]*statusNode `json:"Peer"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&status) != nil {
		return nil, context.DeadlineExceeded
	}
	nodes := make([]statusNode, 0, len(status.Peer)+1)
	if status.Self != nil {
		nodes = append(nodes, *status.Self)
	}
	for _, node := range status.Peer {
		if node != nil {
			nodes = append(nodes, *node)
		}
	}
	return taggedNodes(nodes), nil
}

type statusNode struct {
	TailscaleIPs []netip.Addr `json:"TailscaleIPs"`
	Tags         []string     `json:"Tags"`
}

func taggedNodes(nodes []statusNode) []TaggedNode {
	result := make([]TaggedNode, 0, len(nodes))
	for _, node := range nodes {
		if len(node.Tags) == 0 {
			continue
		}
		tags := make(map[string]struct{}, len(node.Tags))
		for _, tag := range node.Tags {
			tags[tag] = struct{}{}
		}
		for _, address := range node.TailscaleIPs {
			if address.Is4() {
				result = append(result, TaggedNode{Address: address.String(), Tags: tags})
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Address < result[j].Address })
	return result
}

type Service struct {
	Identity    Identity
	Gateways    map[string]Gateway
	Allocations *Allocator
	// AllocationStore is owned only by the DNS role. Gateways are deliberately
	// stateless and recover mappings through DNS PTR records.
	AllocationStore AllocationStore
	StatePath       string
	// PTRLookup resolves synthetic addresses through the DNS authority. It is
	// overridden by tsnet gateways so lookup stays on the tailnet DNS path.
	PTRLookup   func(context.Context, netip.Addr) ([]string, error)
	Synthesized atomic.Uint64
	Passthrough atomic.Uint64
	Allowed     atomic.Uint64
	Denied      atomic.Uint64
	Lease       time.Duration
	Now         func() time.Time
}

func (s *Service) lease() time.Duration {
	if s.Lease > 0 {
		return s.Lease
	}
	return time.Hour
}
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) DNS(ctx context.Context, source netip.Addr, name string) (netip.Addr, bool) {
	if checker, ok := s.Identity.(GatewaySource); ok {
		if gateway, err := checker.IsGateway(ctx, source, s.Gateways); err != nil || gateway {
			s.Passthrough.Add(1)
			return netip.Addr{}, false
		}
	}
	name, ok := NormalName(name)
	if !ok {
		s.Passthrough.Add(1)
		return netip.Addr{}, false
	}
	caps, err := s.Identity.Capabilities(ctx, source, netip.Addr{})
	if err != nil {
		s.Passthrough.Add(1)
		return netip.Addr{}, false
	}
	grants := Parse(caps, s.Gateways)
	gateway := ""
	for _, g := range grants {
		for _, r := range g.Resources {
			if match(r.Domain, name) {
				if gateway != "" && gateway != g.Gateway {
					s.Passthrough.Add(1)
					return netip.Addr{}, false
				}
				gateway = g.Gateway
			}
		}
	}
	if gateway == "" {
		s.Passthrough.Add(1)
		return netip.Addr{}, false
	}
	var ip netip.Addr
	if s.AllocationStore != nil {
		ip, err = s.AllocationStore.Allocate(ctx, s.Allocations, gateway, s.Gateways[gateway].Prefixes, name, s.now(), s.lease())
	} else {
		ip, err = s.Allocations.Allocate(gateway, s.Gateways[gateway].Prefixes, name)
	}
	if err != nil {
		s.Passthrough.Add(1)
		return netip.Addr{}, false
	}
	// StatePath remains for callers using the original JSON file API.
	if s.AllocationStore == nil && s.StatePath != "" && s.Allocations.Save(s.StatePath) != nil {
		s.Passthrough.Add(1)
		return netip.Addr{}, false
	}
	s.Synthesized.Add(1)
	return ip, true
}

// PTRMapping resolves a synthetic address locally first, then through the
// shared allocation authority so any DNS replica can answer a peer's PTR.
func (s *Service) PTRMapping(ctx context.Context, ip netip.Addr) (Mapping, bool) {
	if s.AllocationStore == nil {
		return s.Allocations.Lookup(ip)
	}
	mapping, ok, err := s.AllocationStore.Lookup(ctx, s.Allocations, ip, s.now(), s.lease())
	return mapping, err == nil && ok
}
func (s *Service) Flow(ctx context.Context, source, destination netip.Addr, proto string, port uint16) (Mapping, Gateway, bool) {
	m, ok := s.PTRMapping(ctx, destination)
	if !ok {
		s.Denied.Add(1)
		return Mapping{}, Gateway{}, false
	}
	caps, err := s.Identity.Capabilities(ctx, source, destination)
	if err != nil || !Authorize(Parse(caps, s.Gateways), m.Gateway, m.Domain, proto, port) {
		s.Denied.Add(1)
		return Mapping{}, Gateway{}, false
	}
	s.Allowed.Add(1)
	return m, s.Gateways[m.Gateway], true
}

// FlowDomain is for stateless gateway instances. DNS is the allocation authority:
// the gateway obtains domain from a PTR lookup and derives its segment from the IP prefix.
func (s *Service) FlowDomain(ctx context.Context, source, destination netip.Addr, name, proto string, port uint16) (Gateway, bool) {
	name, ok := NormalName(name)
	if !ok {
		s.Denied.Add(1)
		return Gateway{}, false
	}
	var tag string
	for candidate, gateway := range s.Gateways {
		if containsPrefix(gateway.Prefixes, destination) {
			if tag != "" {
				s.Denied.Add(1)
				return Gateway{}, false
			}
			tag = candidate
		}
	}
	if tag == "" {
		s.Denied.Add(1)
		return Gateway{}, false
	}
	caps, err := s.Identity.Capabilities(ctx, source, destination)
	if err != nil || !Authorize(Parse(caps, s.Gateways), tag, name, proto, port) {
		s.Denied.Add(1)
		return Gateway{}, false
	}
	s.Allowed.Add(1)
	return s.Gateways[tag], true
}

func containsPrefix(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
