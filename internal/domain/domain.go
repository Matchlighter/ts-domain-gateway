// Package domain contains the allocation-free authorization hot path.
package domain

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Capability = "matchlighter.net/domain-gateway"

type Port struct {
	Protocol string
	Number   uint16
}
type Resource struct {
	Domain      string   `json:"domain"`
	IP          []string `json:"ip"`
	UpstreamDNS string   `json:"upstreamDNS"`
}

// UnmarshalJSON accepts either the standard resource object or the concise
// domain:port[,port...] form, whose listed ports are TCP.
func (r *Resource) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var shorthand string
		if err := json.Unmarshal(data, &shorthand); err != nil {
			return err
		}
		domain, ports, ok := strings.Cut(shorthand, ":")
		if !ok || domain == "" || ports == "" || strings.Contains(ports, ":") {
			return errors.New("invalid resource shorthand")
		}
		parts := strings.Split(ports, ",")
		for i, port := range parts {
			if port == "" {
				return errors.New("invalid resource shorthand")
			}
			parts[i] = "tcp:" + port
		}
		r.Domain, r.IP = domain, parts
		return nil
	}
	var resource struct {
		Domain      string          `json:"domain"`
		IP          []string        `json:"ip"`
		UpstreamDNS string          `json:"upstreamDNS"`
		Ports       json.RawMessage `json:"ports"`
	}
	if err := json.Unmarshal(data, &resource); err != nil {
		return err
	}
	if resource.Ports != nil {
		return errors.New("resource ports field is unsupported; use ip")
	}
	r.Domain, r.IP, r.UpstreamDNS = resource.Domain, resource.IP, resource.UpstreamDNS
	return nil
}

type Grant struct {
	UpstreamDNS string     `json:"upstreamDNS"`
	Resources   []Resource `json:"resources"`
	Ranges      []netip.Prefix
}

func (g *Grant) UnmarshalJSON(data []byte) error {
	var grant struct {
		UpstreamDNS string          `json:"upstreamDNS"`
		Resources   []Resource      `json:"resources"`
		Ranges      json.RawMessage `json:"range"`
	}
	if err := json.Unmarshal(data, &grant); err != nil {
		return err
	}
	g.UpstreamDNS, g.Resources = grant.UpstreamDNS, grant.Resources
	var values []string
	if err := json.Unmarshal(grant.Ranges, &values); err != nil || len(values) == 0 {
		return errors.New("invalid gateway range")
	}
	g.Ranges = make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return errors.New("invalid gateway range")
		}
		for _, prior := range g.Ranges {
			if prefix.Overlaps(prior) {
				return errors.New("overlapping gateway range")
			}
		}
		g.Ranges = append(g.Ranges, prefix)
	}
	return nil
}

type Gateway struct {
	Prefixes       []netip.Prefix
	Resolver       string
	SystemResolver bool // Resolver must use the host's non-Tailscale DNS path.
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func NormalName(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name, validName(name)
}
func match(pattern, name string) bool {
	// **.suffix matches one or more labels below suffix; it never matches the
	// bare suffix. *.suffix remains a single-label wildcard.
	if strings.HasPrefix(pattern, "**.") {
		suffix := pattern[3:]
		return strings.HasSuffix(name, "."+suffix)
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(name, "."+suffix) && strings.Count(name, ".") == strings.Count(suffix, ".")+1
	}
	return pattern == name
}
func allowedPort(ports []string, proto string, port uint16) bool {
	if len(ports) == 0 {
		return true
	}
	expected := proto + ":"
	for _, p := range ports {
		if strings.HasPrefix(p, expected) {
			var n uint64
			for _, c := range p[len(expected):] {
				if c < '0' || c > '9' {
					n = 0
					break
				}
				n = n*10 + uint64(c-'0')
			}
			if n == uint64(port) {
				return true
			}
		}
	}
	return false
}

func validPorts(ports []string) bool {
	for _, p := range ports {
		parts := strings.Split(p, ":")
		if len(parts) != 2 || (parts[0] != "tcp" && parts[0] != "udp") || parts[1] == "" {
			return false
		}
		var n uint64
		for _, c := range parts[1] {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + uint64(c-'0')
			if n > 65535 {
				return false
			}
		}
		if n == 0 {
			return false
		}
	}
	return true
}

// normalizeResolver accepts a concrete DNS endpoint with an optional port, or
// the fixed system sentinel. It returns an address suitable for net.Dial so
// policy must never turn an unvalidated string into an outbound connection.
func normalizeResolver(resolver string) (string, bool) {
	if IsSystemResolver(resolver) {
		return resolver, true
	}
	host, port, err := net.SplitHostPort(resolver)
	if err != nil {
		if strings.Contains(resolver, ":") && net.ParseIP(resolver) == nil {
			return "", false
		}
		return net.JoinHostPort(resolver, "53"), true
	}
	if host == "" {
		return "", false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", false
	}
	return net.JoinHostPort(host, port), true
}

// Parse validates each independent opaque capability; invalid entries cannot authorize.
// A capability range is both its synthetic allocation pool and its egress
// assignment; the policy no longer carries a separate gateway selector.
func Parse(capmap map[string]json.RawMessage) []Grant {
	raw, ok := capmap[Capability]
	if !ok {
		return nil
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	grants := make([]Grant, 0, len(entries))
	for _, entry := range entries {
		var g Grant
		if json.Unmarshal(entry, &g) != nil || len(g.Ranges) == 0 || len(g.Resources) == 0 {
			continue
		}
		valid := true
		if g.UpstreamDNS != "" {
			g.UpstreamDNS, valid = normalizeResolver(g.UpstreamDNS)
		}
		for i := range g.Resources {
			d := strings.ToLower(strings.TrimSuffix(g.Resources[i].Domain, "."))
			if strings.HasPrefix(d, "**.") {
				valid = valid && validName(d[3:])
			} else if strings.HasPrefix(d, "*.") {
				valid = valid && validName(d[2:])
			} else {
				valid = valid && validName(d)
			}
			g.Resources[i].Domain = d
			valid = valid && validPorts(g.Resources[i].IP)
			if g.Resources[i].UpstreamDNS != "" {
				var resolverValid bool
				g.Resources[i].UpstreamDNS, resolverValid = normalizeResolver(g.Resources[i].UpstreamDNS)
				valid = valid && resolverValid
			}
		}
		if valid {
			grants = append(grants, g)
		}
	}
	return grants
}

// GatewayFor returns the policy-selected gateway for an authorized flow. A
// resource override wins over a grant override, which wins over the gateway's
// NodeAttr resolver. Conflicting equally-specific policy choices fail closed.
func GatewayFor(grants []Grant, gateway Gateway, name, proto string, port uint16) (Gateway, bool) {
	resolver, priority := gateway.Resolver, 0
	systemResolver := gateway.SystemResolver
	matched := false
	for _, grant := range grants {
		if !samePrefixSlice(grant.Ranges, gateway.Prefixes) {
			continue
		}
		for _, resource := range grant.Resources {
			if !match(resource.Domain, name) || !allowedPort(resource.IP, proto, port) {
				continue
			}
			candidate, candidatePriority := grant.UpstreamDNS, 1
			if resource.UpstreamDNS != "" {
				candidate, candidatePriority = resource.UpstreamDNS, 2
			}
			if candidate == "" {
				candidate, candidatePriority = gateway.Resolver, 0
			}
			if !matched || candidatePriority > priority {
				resolver, priority, matched = candidate, candidatePriority, true
				if candidatePriority > 0 {
					systemResolver = IsSystemResolver(candidate)
				}
				continue
			}
			if candidatePriority == priority && candidate != resolver {
				return Gateway{}, false
			}
			matched = true
		}
	}
	if !matched {
		return Gateway{}, false
	}
	gateway.Resolver = resolver
	gateway.SystemResolver = systemResolver
	return gateway, true
}

func Authorize(grants []Grant, prefixes []netip.Prefix, name, proto string, port uint16) bool {
	for _, g := range grants {
		if !samePrefixSlice(g.Ranges, prefixes) {
			continue
		}
		for _, r := range g.Resources {
			if match(r.Domain, name) && allowedPort(r.IP, proto, port) {
				return true
			}
		}
	}
	return false
}

// RangesForName selects a capability's synthetic allocation pool. Conflicting
// matching assignments fail closed.
func RangesForName(grants []Grant, name string) ([]netip.Prefix, bool) {
	var ranges []netip.Prefix
	for _, grant := range grants {
		for _, resource := range grant.Resources {
			if !match(resource.Domain, name) {
				continue
			}
			if ranges != nil && !samePrefixSlice(ranges, grant.Ranges) {
				return nil, false
			}
			ranges = grant.Ranges
		}
	}
	return ranges, ranges != nil
}

func rangeKey(prefixes []netip.Prefix) string {
	parts := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		parts[i] = prefix.String()
	}
	return strings.Join(parts, ",")
}

func samePrefixSlice(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Allocator assigns monotonic addresses. Entries are never reused during a process;
// production instances should keep the process/state owner stable across restarts.
type Allocator struct {
	mu        sync.RWMutex
	persistMu sync.Mutex
	byKey     map[string]netip.Addr
	byIP      map[netip.Addr]Mapping
	next      map[string]netip.Addr
	expires   map[netip.Addr]time.Time
}
type Mapping struct{ Gateway, Domain string }

func NewAllocator() *Allocator {
	return &Allocator{byKey: map[string]netip.Addr{}, byIP: map[netip.Addr]Mapping{}, next: map[string]netip.Addr{}, expires: map[netip.Addr]time.Time{}}
}
func (a *Allocator) Allocate(gateway string, prefixes []netip.Prefix, name string) (netip.Addr, error) {
	key := gateway + "\x00" + name
	a.mu.RLock()
	ip, ok := a.byKey[key]
	a.mu.RUnlock()
	if ok {
		return ip, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if ip, ok = a.byKey[key]; ok {
		return ip, nil
	}
	ip = a.next[gateway]
	start := 0
	if ip.IsValid() {
		for i, prefix := range prefixes {
			if prefix.Contains(ip) {
				start = i
				break
			}
			if previous := ip.Prev(); previous.IsValid() && prefix.Contains(previous) {
				start = i + 1
				break
			}
		}
	}
	if len(prefixes) == 0 || start == len(prefixes) {
		return netip.Addr{}, errors.New("synthetic ranges exhausted")
	}
	if !ip.IsValid() {
		ip = prefixes[0].Masked().Addr().Next()
	}
	for i := start; i < len(prefixes); i++ {
		prefix := prefixes[i]
		if i != start || !prefix.Contains(ip) {
			ip = prefix.Masked().Addr().Next()
		}
		if prefix.Contains(ip) && ip != prefix.Masked().Addr() {
			break
		}
		ip = netip.Addr{}
	}
	if !ip.IsValid() {
		return netip.Addr{}, errors.New("synthetic ranges exhausted")
	}
	a.byKey[key] = ip
	a.byIP[ip] = Mapping{gateway, name}
	a.next[gateway] = ip.Next()
	return ip, nil
}
func (a *Allocator) Lookup(ip netip.Addr) (Mapping, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	m, ok := a.byIP[ip]
	return m, ok
}

func (a *Allocator) LookupLive(ip netip.Addr, now time.Time) (Mapping, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m, ok := a.byIP[ip]
	if !ok || (!a.expires[ip].IsZero() && !now.Before(a.expires[ip])) {
		if ok {
			delete(a.byIP, ip)
			delete(a.byKey, m.Gateway+"\x00"+m.Domain)
			delete(a.expires, ip)
		}
		return Mapping{}, false
	}
	return m, true
}

func (a *Allocator) LookupKey(gateway, domain string) (netip.Addr, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	ip, ok := a.byKey[gateway+"\x00"+domain]
	return ip, ok
}

func (a *Allocator) LookupKeyLive(gateway, domain string, now time.Time) (netip.Addr, bool) {
	ip, ok := a.LookupKey(gateway, domain)
	if !ok {
		return netip.Addr{}, false
	}
	_, ok = a.LookupLive(ip, now)
	return ip, ok
}

// Remember updates a local cache with an allocation established by the shared
// registry. It never changes an existing mapping.
func (a *Allocator) Remember(gateway, domain string, ip netip.Addr) {
	a.RememberUntil(gateway, domain, ip, time.Time{})
}

func (a *Allocator) RememberUntil(gateway, domain string, ip netip.Addr, expiry time.Time) {
	key := gateway + "\x00" + domain
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.byKey[key]; ok {
		return
	}
	if _, ok := a.byIP[ip]; ok {
		return
	}
	a.byKey[key] = ip
	a.byIP[ip] = Mapping{gateway, domain}
	a.expires[ip] = expiry
	if next := ip.Next(); !a.next[gateway].IsValid() || a.next[gateway].Less(next) {
		a.next[gateway] = next
	}
}
