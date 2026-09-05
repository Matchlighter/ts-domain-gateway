// Package domain contains the allocation-free authorization hot path.
package domain

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
)

const Capability = "matchlighter.net/cap/domain-gateway"

type Port struct {
	Protocol string
	Number   uint16
}
type Resource struct {
	Domain string   `json:"domain"`
	Ports  []string `json:"ports"`
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
			valid = valid && validPorts(g.Resources[i].Ports)
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
			if match(r.Domain, name) && allowedPort(r.Ports, proto, port) {
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
}
type Mapping struct{ Gateway, Domain string }

func NewAllocator() *Allocator {
	return &Allocator{byKey: map[string]netip.Addr{}, byIP: map[netip.Addr]Mapping{}, next: map[string]netip.Addr{}}
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
