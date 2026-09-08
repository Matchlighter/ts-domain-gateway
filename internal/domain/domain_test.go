package domain

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

type fakeIdentity map[netip.Addr]map[string]json.RawMessage

func (f fakeIdentity) Capabilities(_ context.Context, src, _ netip.Addr) (map[string]json.RawMessage, error) {
	return f[src], nil
}

type gatewayIdentity struct {
	fakeIdentity
	tagged map[netip.Addr]bool
}

func (g gatewayIdentity) IsGateway(_ context.Context, source netip.Addr, _ map[string]Gateway) (bool, error) {
	return g.tagged[source], nil
}

func TestCapabilitiesAndAllocation(t *testing.T) {
	g := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	raw := json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"*.dev.example.com","ip":["tcp:443"]}]}]`)
	grants := Parse(map[string]json.RawMessage{Capability: raw}, g)
	if !Authorize(grants, "tag:home", "a.dev.example.com", "tcp", 443) || Authorize(grants, "tag:home", "a.b.dev.example.com", "tcp", 443) {
		t.Fatal("wildcard or port matcher incorrect")
	}
	a := NewAllocator()
	one, _ := a.Allocate("tag:home", g["tag:home"].Prefixes, "one.dev.example.com")
	two, _ := a.Allocate("tag:home", g["tag:home"].Prefixes, "two.dev.example.com")
	if one == two {
		t.Fatal("resources shared an address")
	}
}

func TestAuthorizeDomainWildcardsAtTheirDefinedDepths(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	for _, test := range []struct {
		name    string
		pattern string
		domain  string
		allowed bool
	}{
		{"single wildcard permits one label", "*.dev.example.com", "api.dev.example.com", true},
		{"single wildcard rejects multiple labels", "*.dev.example.com", "api.eu.dev.example.com", false},
		{"single wildcard rejects apex", "*.dev.example.com", "dev.example.com", false},
		{"recursive wildcard permits one label", "**.dev.example.com", "api.dev.example.com", true},
		{"recursive wildcard permits multiple labels", "**.dev.example.com", "api.eu.dev.example.com", true},
		{"recursive wildcard rejects apex", "**.dev.example.com", "dev.example.com", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[
				{"gateway":"tag:home","resources":[{"domain":"` + test.pattern + `","ip":["tcp:443"]}]}
			]`)}, gateways)
			if got := Authorize(grants, "tag:home", test.domain, "tcp", 443); got != test.allowed {
				t.Fatalf("Authorize(%q, %q) = %v, want %v", test.pattern, test.domain, got, test.allowed)
			}
		})
	}
}

func TestParseRejectsMalformedDomainWildcards(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	for _, pattern := range []string{"**", "**.", "***.example.com", "foo.**.example.com", "*.*.example.com"} {
		t.Run(pattern, func(t *testing.T) {
			grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[
				{"gateway":"tag:home","resources":[{"domain":"` + pattern + `","ip":["tcp:443"]}]}
			]`)}, gateways)
			if len(grants) != 0 {
				t.Fatalf("malformed wildcard %q produced a grant", pattern)
			}
		})
	}
}

func TestMalformedPortFailsClosed(t *testing.T) {
	g := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"a.example.com","ip":["tcp:70000"]}]}]`)}, g)
	if len(grants) != 0 {
		t.Fatal("invalid port authorized")
	}
}

func TestMalformedCapabilityRangesFailClosed(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	for _, value := range []string{
		`[]`, `["10.254.0.1/24"]`, `["2001:db8::/64"]`,
		`["10.254.0.0/24","10.254.0.128/25"]`,
	} {
		t.Run(value, func(t *testing.T) {
			grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[
				{"gateway":"tag:home","range":` + value + `,"resources":[{"domain":"app.example.com"}]}
			]`)}, gateways)
			if len(grants) != 0 {
				t.Fatalf("malformed range %s produced a grant", value)
			}
		})
	}
}

func TestResourceIPAuthorizesListedTCPAndUDPPorts(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[
		{"gateway":"tag:home","resources":[{"domain":"app.example.com","ip":["tcp:443","udp:53"]}]}
	]`)}, gateways)
	if !Authorize(grants, "tag:home", "app.example.com", "tcp", 443) || !Authorize(grants, "tag:home", "app.example.com", "udp", 53) {
		t.Fatal("ip entries did not authorize their listed protocol and port")
	}
	if Authorize(grants, "tag:home", "app.example.com", "tcp", 53) || Authorize(grants, "tag:home", "app.example.com", "udp", 443) {
		t.Fatal("ip entries authorized an unlisted protocol or port")
	}
}

func TestLegacyResourcePortsFailClosed(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	for _, resource := range []string{
		`{"domain":"app.example.com","ports":["tcp:443"]}`,
		`{"domain":"app.example.com","ip":["tcp:443"],"ports":["udp:53"]}`,
	} {
		t.Run(resource, func(t *testing.T) {
			grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[
				{"gateway":"tag:home","resources":[` + resource + `]}
			]`)}, gateways)
			if Authorize(grants, "tag:home", "app.example.com", "tcp", 443) {
				t.Fatal("legacy ports field authorized traffic")
			}
		})
	}
}

func TestResourceWithoutIPAuthorizesAllPorts(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[
		{"gateway":"tag:home","resources":[{"domain":"app.example.com"}]}
	]`)}, gateways)
	if !Authorize(grants, "tag:home", "app.example.com", "tcp", 443) || !Authorize(grants, "tag:home", "app.example.com", "udp", 53) {
		t.Fatal("resource without ip did not authorize all ports")
	}
}

func TestGatewayForUsesResourceResolverBeforeGrantResolverAndFallback(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")},
		Resolver: "127.0.0.1:53",
	}}
	grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[
		{
			"gateway":"tag:home",
			"upstreamDNS":"127.0.0.2:53",
			"resources":[
				{"domain":"resource.example.com","upstreamDNS":"127.0.0.3:53"},
				{"domain":"grant.example.com"}
			]
		},
		{"gateway":"tag:home","resources":[{"domain":"fallback.example.com"}]}
	]`)}, gateways)

	for _, test := range []struct {
		name, want string
	}{
		{"resource.example.com", "127.0.0.3:53"},
		{"grant.example.com", "127.0.0.2:53"},
		{"fallback.example.com", "127.0.0.1:53"},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway, ok := GatewayFor(grants, gateways, "tag:home", test.name, "tcp", 443)
			if !ok || gateway.Resolver != test.want {
				t.Fatalf("GatewayFor(%q) = %#v, %v; want resolver %q", test.name, gateway, ok, test.want)
			}
		})
	}
}

func TestMalformedPolicyResolverFailsClosed(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	for _, policy := range []string{
		`{"gateway":"tag:home","upstreamDNS":"system","resources":[{"domain":"app.example.com"}]}`,
		`{"gateway":"tag:home","upstreamDNS":"resolver.example.com","resources":[{"domain":"app.example.com"}]}`,
		`{"gateway":"tag:home","resources":[{"domain":"app.example.com","upstreamDNS":"127.0.0.1:0"}]}`,
	} {
		t.Run(policy, func(t *testing.T) {
			grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage("[" + policy + "]")}, gateways)
			if len(grants) != 0 {
				t.Fatalf("invalid resolver policy parsed as %#v", grants)
			}
		})
	}
}

func TestResourceStringShorthandNormalizesForAuthorization(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[
		{"gateway":"tag:home","resources":[
			{"domain":"object.example.net","ip":["udp:53"]},
			"example.net:443,80"
		]}
	]`)}, gateways)
	if len(grants) != 1 {
		t.Fatalf("parsed grants = %d, want 1", len(grants))
	}
	if !Authorize(grants, "tag:home", "example.net", "tcp", 443) || !Authorize(grants, "tag:home", "example.net", "tcp", 80) {
		t.Fatal("string shorthand did not authorize its TCP ports")
	}
	if Authorize(grants, "tag:home", "example.net", "udp", 443) || Authorize(grants, "tag:home", "example.net", "tcp", 53) {
		t.Fatal("string shorthand authorized an unlisted protocol or port")
	}
	if !Authorize(grants, "tag:home", "object.example.net", "udp", 53) {
		t.Fatal("object resource semantics changed when mixed with shorthand")
	}
}

func TestResourceStringShorthandFailsClosed(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	for _, resource := range []string{
		"example:443", "example.net", ":443", "example.net:",
		"example.net:443,", "example.net:443,,80", "example.net:443:80",
		"example.net:http", "example.net:0", "example.net:65536",
	} {
		t.Run(resource, func(t *testing.T) {
			grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":["` + resource + `"]}]`)}, gateways)
			if Authorize(grants, "tag:home", "example.net", "tcp", 443) {
				t.Fatalf("malformed shorthand %q authorized traffic", resource)
			}
		})
	}
}

func TestServiceReauthorizesFlowsAndRestoresAllocations(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	source := netip.MustParseAddr("100.64.0.2")
	other := netip.MustParseAddr("100.64.0.3")
	caps := map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"app.example.com","ip":["tcp:443"]}]}]`)}
	service := &Service{Identity: fakeIdentity{source: caps, other: {}}, Gateways: gateways, Allocations: NewAllocator()}
	ip, ok := service.DNS(context.Background(), source, "app.example.com")
	if !ok {
		t.Fatal("authorized DNS was not synthesized")
	}
	if _, _, ok := service.Flow(context.Background(), other, ip, "tcp", 443); ok {
		t.Fatal("unauthorized source reached synthetic mapping")
	}
	if _, _, ok := service.Flow(context.Background(), source, ip, "tcp", 80); ok {
		t.Fatal("unauthorized port reached synthetic mapping")
	}
	path := filepath.Join(t.TempDir(), "allocations.json")
	if err := service.Allocations.Save(path); err != nil {
		t.Fatal(err)
	}
	reloaded := NewAllocator()
	if err := reloaded.Load(path); err != nil {
		t.Fatal(err)
	}
	if mapping, ok := reloaded.Lookup(ip); !ok || mapping.Domain != "app.example.com" {
		t.Fatal("persistent mapping lost")
	}
}

func TestSQLiteAllocationStoreRestoresAllocations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allocations.db")
	store, err := OpenAllocationStore(context.Background(), "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	allocated := NewAllocator()
	ip, err := allocated.Allocate("tag:home", []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}, "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), allocated); err != nil {
		t.Fatal(err)
	}
	reloaded := NewAllocator()
	if err := store.Load(context.Background(), reloaded); err != nil {
		t.Fatal(err)
	}
	if mapping, ok := reloaded.Lookup(ip); !ok || mapping.Gateway != "tag:home" || mapping.Domain != "app.example.com" {
		t.Fatalf("SQLite mapping = %#v, %v", mapping, ok)
	}
}

func TestSQLiteAllocationStoreSharesDNSReplicaAllocations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allocations.db")
	first, err := OpenAllocationStore(context.Background(), "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenAllocationStore(context.Background(), "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	prefix := netip.MustParsePrefix("10.254.0.0/29")
	firstCache, secondCache := NewAllocator(), NewAllocator()
	now := time.Now()
	firstIP, err := first.Allocate(context.Background(), firstCache, "tag:home", []netip.Prefix{prefix}, "app.example.com", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	secondIP, err := second.Allocate(context.Background(), secondCache, "tag:home", []netip.Prefix{prefix}, "app.example.com", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if firstIP != secondIP {
		t.Fatalf("replicas allocated %s and %s for one domain", firstIP, secondIP)
	}
	otherIP, err := second.Allocate(context.Background(), NewAllocator(), "tag:home", []netip.Prefix{prefix}, "other.example.com", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if otherIP == firstIP {
		t.Fatalf("replicas reused %s for distinct domains", firstIP)
	}
	thirdCache := NewAllocator()
	mapping, found, err := second.Lookup(context.Background(), thirdCache, firstIP, now, time.Hour)
	if err != nil || !found || mapping.Domain != "app.example.com" {
		t.Fatalf("replica PTR lookup = %#v, %v, %v", mapping, found, err)
	}
}

func TestSQLiteAllocationStoreAllocatesAcrossRanges(t *testing.T) {
	store, err := OpenAllocationStore(context.Background(), "sqlite://"+filepath.Join(t.TempDir(), "allocations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.254.0.0/30"), netip.MustParsePrefix("10.254.1.0/30")}
	for _, name := range []string{"one.example.com", "two.example.com", "three.example.com", "four.example.com"} {
		ip, err := store.Allocate(context.Background(), NewAllocator(), "tag:home", prefixes, name, time.Now(), time.Hour)
		if err != nil {
			t.Fatalf("allocate %s: %v", name, err)
		}
		if name == "four.example.com" && !prefixes[1].Contains(ip) {
			t.Fatalf("fourth allocation %s did not use second range", ip)
		}
	}
}

func TestSQLiteAllocationStoreExpiresAndRenewsLeases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allocations.db")
	store, err := OpenAllocationStore(context.Background(), "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lease := time.Hour
	first := NewAllocator()
	ip, err := store.Allocate(context.Background(), first, "tag:home", []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}, "app.example.com", clock, lease)
	if err != nil {
		t.Fatal(err)
	}
	// A second replica has no RAM entry, so this proves the database is queried
	// and a qualifying PTR query renews the lease.
	second := NewAllocator()
	if mapping, found, err := store.Lookup(context.Background(), second, ip, clock.Add(59*time.Minute), lease); err != nil || !found || mapping.Domain != "app.example.com" {
		t.Fatalf("renewed lookup = %#v, %v, %v", mapping, found, err)
	}
	third := NewAllocator()
	if _, found, err := store.Lookup(context.Background(), third, ip, clock.Add(119*time.Minute), lease); err != nil || found {
		t.Fatalf("expired lookup found = %v, err = %v", found, err)
	}
	reused, err := store.Allocate(context.Background(), NewAllocator(), "tag:home", []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}, "other.example.com", clock.Add(119*time.Minute), lease)
	if err != nil {
		t.Fatal(err)
	}
	if reused != ip {
		t.Fatalf("expired address was not reused: got %s, want %s", reused, ip)
	}
}

func TestAllocationStoreRejectsUnsupportedURL(t *testing.T) {
	if _, err := OpenAllocationStore(context.Background(), "file:///tmp/allocations.db"); err == nil {
		t.Fatal("unsupported database scheme was accepted")
	}
}

func TestStatelessGatewayAuthorizesPTRDomain(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	source := netip.MustParseAddr("100.64.0.2")
	caps := map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"app.example.com","ip":["tcp:443"]}]}]`)}
	service := &Service{Identity: fakeIdentity{source: caps}, Gateways: gateways}
	if _, ok := service.FlowDomain(context.Background(), source, netip.MustParseAddr("10.254.0.2"), "app.example.com.", "tcp", 443); !ok {
		t.Fatal("PTR-reconstructed domain was not authorized")
	}
	if _, ok := service.FlowDomain(context.Background(), source, netip.MustParseAddr("10.254.0.2"), "other.example.com", "tcp", 443); ok {
		t.Fatal("PTR name bypassed domain policy")
	}
}

func TestFlowDomainReturnsPolicySelectedResolver(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")},
		Resolver: "127.0.0.1:53",
	}}
	source := netip.MustParseAddr("100.64.0.2")
	caps := map[string]json.RawMessage{Capability: json.RawMessage(`[
		{"gateway":"tag:home","upstreamDNS":"127.0.0.2:53","resources":[
			{"domain":"resource.example.com","upstreamDNS":"127.0.0.3:53"},
			{"domain":"grant.example.com"}
		]},
		{"gateway":"tag:home","resources":[{"domain":"fallback.example.com"}]}
	]`)}
	service := &Service{Identity: fakeIdentity{source: caps}, Gateways: gateways}
	for _, test := range []struct{ name, want string }{
		{"resource.example.com", "127.0.0.3:53"},
		{"grant.example.com", "127.0.0.2:53"},
		{"fallback.example.com", "127.0.0.1:53"},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway, ok := service.FlowDomain(context.Background(), source, netip.MustParseAddr("10.254.0.2"), test.name, "tcp", 443)
			if !ok || gateway.Resolver != test.want {
				t.Fatalf("FlowDomain(%q) = %#v, %v; want resolver %q", test.name, gateway, ok, test.want)
			}
		})
	}
}

func TestGatewaySourceNeverReceivesSyntheticForwardAnswer(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefixes: []netip.Prefix{netip.MustParsePrefix("10.254.0.0/29")}}}
	source := netip.MustParseAddr("100.64.0.2")
	caps := map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"app.example.com"}]}]`)}
	service := &Service{Identity: gatewayIdentity{fakeIdentity: fakeIdentity{source: caps}, tagged: map[netip.Addr]bool{source: true}}, Gateways: gateways, Allocations: NewAllocator()}
	if _, ok := service.DNS(context.Background(), source, "app.example.com"); ok {
		t.Fatal("gateway source received synthetic DNS")
	}
}
