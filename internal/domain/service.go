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

// ResolverDial reaches the DNS resolver selected for an egress flow. tsnet
// gateways use it to send resolver traffic through their userspace tailnet;
// daemon-backed gateways leave it nil and use the host network.
type ResolverDial func(context.Context, string, string) (net.Conn, error)
type LocalAPI struct{ client *http.Client }

func NewLocalAPI(socket string) *LocalAPI {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	return &LocalAPI{&http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}}}
}

type localWhoIs struct {
	CapMap map[string]json.RawMessage
	Node   struct{ Tags []string }
}

func (l *LocalAPI) whoIs(ctx context.Context, source, destination netip.Addr) (localWhoIs, error) {
	v := url.Values{"addr": {source.String()}}
	if destination.IsValid() {
		v.Set("dst_ip", destination.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled/localapi/v0/whois?"+v.Encode(), nil)
	if err != nil {
		return localWhoIs{}, err
	}
	res, err := l.client.Do(req)
	if err != nil {
		return localWhoIs{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return localWhoIs{}, &url.Error{Op: "whois", URL: req.URL.String(), Err: context.DeadlineExceeded}
	}
	var response localWhoIs
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return localWhoIs{}, context.DeadlineExceeded
	}
	return response, nil
}

func (l *LocalAPI) Capabilities(ctx context.Context, source, destination netip.Addr) (map[string]json.RawMessage, error) {
	response, err := l.whoIs(ctx, source, destination)
	if err != nil {
		return nil, err
	}
	if response.CapMap == nil {
		return nil, context.DeadlineExceeded
	}
	return response.CapMap, nil
}

func (l *LocalAPI) IsGateway(ctx context.Context, source netip.Addr, gateways map[string]Gateway) (bool, error) {
	response, err := l.whoIs(ctx, source, netip.Addr{})
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

type localStatus struct {
	Self         statusNode             `json:"Self"`
	Peer         map[string]*statusNode `json:"Peer"`
	TailscaleIPs []netip.Addr           `json:"TailscaleIPs"`
}

func (l *LocalAPI) status(ctx context.Context) (localStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled/localapi/v0/status", nil)
	if err != nil {
		return localStatus{}, err
	}
	res, err := l.client.Do(req)
	if err != nil {
		return localStatus{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return localStatus{}, context.DeadlineExceeded
	}
	var status localStatus
	if err := json.NewDecoder(res.Body).Decode(&status); err != nil {
		return localStatus{}, context.DeadlineExceeded
	}
	return status, nil
}

// NodeConfig reads this process's typed NodeAttrs from local tailscaled.
func (l *LocalAPI) NodeConfig(ctx context.Context) (NodeConfig, error) {
	status, err := l.status(ctx)
	if err != nil {
		return NodeConfig{}, err
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
	status, err := l.status(ctx)
	if err != nil {
		return netip.Addr{}, err
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
	status, err := l.status(ctx)
	if err != nil {
		return nil, err
	}
	nodes := make([]statusNode, 0, len(status.Peer)+1)
	nodes = append(nodes, status.Self)
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
	CapMap       map[string]json.RawMessage
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
	Lifecycle       *AllocationLifecycle
	// PTRLookup resolves synthetic addresses through the DNS authority. It is
	// overridden by tsnet gateways so lookup stays on the tailnet DNS path.
	PTRLookup    func(context.Context, netip.Addr) ([]string, error)
	ResolverDial ResolverDial
	// SystemResolver returns the host's safe resolver endpoint for a policy
	// upstreamDNS value of "system".
	SystemResolver func(context.Context) (string, error)
	Synthesized    atomic.Uint64
	Passthrough    atomic.Uint64
	Allowed        atomic.Uint64
	Denied         atomic.Uint64
	Lease          time.Duration
	Now            func() time.Time
}

type DNSOutcome uint8

const (
	DNSPassthrough DNSOutcome = iota
	DNSSynthesized
	DNSUnavailable
)

func (s *Service) DNS(ctx context.Context, source netip.Addr, name string) (netip.Addr, bool) {
	ip, outcome := s.DNSAnswer(ctx, source, name)
	return ip, outcome == DNSSynthesized
}

func (s *Service) lifecycle() AllocationLifecycle {
	if s.Lifecycle != nil {
		return *s.Lifecycle
	}
	return AllocationLifecycle{Allocator: s.Allocations, Store: s.AllocationStore, StatePath: s.StatePath, Lease: s.Lease, Now: s.Now}
}

// DNSAnswer distinguishes an ordinary passthrough name from an authorized
// protected name whose route topology is unavailable.
func (s *Service) DNSAnswer(ctx context.Context, source netip.Addr, name string) (netip.Addr, DNSOutcome) {
	if checker, ok := s.Identity.(GatewaySource); ok {
		if gateway, err := checker.IsGateway(ctx, source, s.Gateways); err != nil || gateway {
			s.Passthrough.Add(1)
			return netip.Addr{}, DNSPassthrough
		}
	}
	name, ok := NormalName(name)
	if !ok {
		s.Passthrough.Add(1)
		return netip.Addr{}, DNSPassthrough
	}
	caps, err := s.Identity.Capabilities(ctx, source, netip.Addr{})
	if err != nil {
		s.Passthrough.Add(1)
		return netip.Addr{}, DNSPassthrough
	}
	grants := Parse(caps)
	ranges, authorized := RangesForName(grants, name)
	if !authorized {
		s.Passthrough.Add(1)
		return netip.Addr{}, DNSPassthrough
	}
	gateway := rangeKey(ranges)
	ip, err := s.lifecycle().Allocate(ctx, gateway, ranges, name)
	if err != nil {
		s.Passthrough.Add(1)
		return netip.Addr{}, DNSUnavailable
	}
	s.Synthesized.Add(1)
	return ip, DNSSynthesized
}

// PTRMapping resolves a synthetic address locally first, then through the
// shared allocation authority so any DNS replica can answer a peer's PTR.
func (s *Service) PTRMapping(ctx context.Context, ip netip.Addr) (Mapping, bool) {
	return s.lifecycle().Lookup(ctx, ip)
}
func (s *Service) Flow(ctx context.Context, source, destination netip.Addr, proto string, port uint16) (Mapping, Gateway, bool) {
	m, ok := s.PTRMapping(ctx, destination)
	if !ok {
		s.Denied.Add(1)
		return Mapping{}, Gateway{}, false
	}
	caps, err := s.Identity.Capabilities(ctx, source, destination)
	if err != nil {
		s.Denied.Add(1)
		return Mapping{}, Gateway{}, false
	}
	gateway, ok := s.gatewayForDestination(destination)
	if ok {
		gateway, ok = GatewayFor(Parse(caps), gateway, m.Domain, proto, port)
	}
	if !ok {
		s.Denied.Add(1)
		return Mapping{}, Gateway{}, false
	}
	s.Allowed.Add(1)
	return m, gateway, true
}

// FlowDomain is for stateless gateway instances. DNS is the allocation authority:
// the gateway obtains domain from a PTR lookup and derives its segment from the IP prefix.
func (s *Service) FlowDomain(ctx context.Context, source, destination netip.Addr, name, proto string, port uint16) (Gateway, bool) {
	name, ok := NormalName(name)
	if !ok {
		s.Denied.Add(1)
		return Gateway{}, false
	}
	gateway, ok := s.gatewayForDestination(destination)
	if !ok {
		s.Denied.Add(1)
		return Gateway{}, false
	}
	caps, err := s.Identity.Capabilities(ctx, source, destination)
	if err != nil {
		s.Denied.Add(1)
		return Gateway{}, false
	}
	gateway, ok = GatewayFor(Parse(caps), gateway, name, proto, port)
	if !ok {
		s.Denied.Add(1)
		return Gateway{}, false
	}
	s.Allowed.Add(1)
	return gateway, true
}

func (s *Service) gatewayForDestination(destination netip.Addr) (Gateway, bool) {
	var selected Gateway
	for _, gateway := range s.Gateways {
		if !containsPrefix(gateway.Prefixes, destination) {
			continue
		}
		if selected.Prefixes != nil {
			return Gateway{}, false
		}
		selected = gateway
	}
	return selected, selected.Prefixes != nil
}

func containsPrefix(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
