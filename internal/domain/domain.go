// Package domain contains the allocation-free authorization hot path.
package domain

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const Capability = "matchlighter.net/cap/domain-gateway"

type Port struct {
	Protocol string
	Number   uint16
}
type Resource struct {
	Domain string   `json:"domain"`
	IP     []string `json:"ip"`
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
		Domain string          `json:"domain"`
		IP     []string        `json:"ip"`
		Ports  json.RawMessage `json:"ports"`
	}
	if err := json.Unmarshal(data, &resource); err != nil {
		return err
	}
	if resource.Ports != nil {
		return errors.New("resource ports field is unsupported; use ip")
	}
	r.Domain, r.IP = resource.Domain, resource.IP
	return nil
}

type Grant struct {
	Gateway   string     `json:"gateway"`
	Resources []Resource `json:"resources"`
}
type Gateway struct {
	Prefix   netip.Prefix
	Resolver string
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

// Parse validates each independent opaque capability; invalid entries cannot authorize.
func Parse(capmap map[string]json.RawMessage, gateways map[string]Gateway) []Grant {
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
		if json.Unmarshal(entry, &g) != nil || g.Gateway == "" || len(g.Resources) == 0 {
			continue
		}
		if _, ok := gateways[g.Gateway]; !ok {
			continue
		}
		valid := true
		for i := range g.Resources {
			d := strings.ToLower(strings.TrimSuffix(g.Resources[i].Domain, "."))
			if strings.HasPrefix(d, "*.") {
				valid = valid && validName(d[2:])
			} else {
				valid = valid && validName(d)
			}
			g.Resources[i].Domain = d
			valid = valid && validPorts(g.Resources[i].IP)
		}
		if valid {
			grants = append(grants, g)
		}
	}
	return grants
}
func Authorize(grants []Grant, gateway, name, proto string, port uint16) bool {
	for _, g := range grants {
		if g.Gateway != gateway {
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
func (a *Allocator) Allocate(gateway string, prefix netip.Prefix, name string) (netip.Addr, error) {
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
	if !ip.IsValid() {
		ip = prefix.Addr().Next()
	}
	if !prefix.Contains(ip) || ip == prefix.Masked().Addr() {
		return netip.Addr{}, errors.New("synthetic prefix exhausted")
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
	if !ok { return netip.Addr{}, false }
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
