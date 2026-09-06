package domain

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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

type Service struct {
	Identity    Identity
	Gateways    map[string]Gateway
	Allocations *Allocator
	StatePath   string
	// PTRLookup resolves synthetic addresses through the DNS authority. It is
	// overridden by tsnet gateways so lookup stays on the tailnet DNS path.
	PTRLookup   func(context.Context, netip.Addr) ([]string, error)
	Synthesized atomic.Uint64
	Passthrough atomic.Uint64
	Allowed     atomic.Uint64
	Denied      atomic.Uint64
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
	ip, err := s.Allocations.Allocate(gateway, s.Gateways[gateway].Prefix, name)
	if err != nil {
		s.Passthrough.Add(1)
		return netip.Addr{}, false
	}
	if s.StatePath != "" && s.Allocations.Save(s.StatePath) != nil {
		s.Passthrough.Add(1)
		return netip.Addr{}, false
	}
	s.Synthesized.Add(1)
	return ip, true
}
func (s *Service) Flow(ctx context.Context, source, destination netip.Addr, proto string, port uint16) (Mapping, Gateway, bool) {
	m, ok := s.Allocations.Lookup(destination)
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
		if gateway.Prefix.Contains(destination) {
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
