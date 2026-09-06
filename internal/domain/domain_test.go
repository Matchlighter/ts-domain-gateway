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
	g := map[string]Gateway{"tag:home": {Prefix: netip.MustParsePrefix("10.254.0.0/29")}}
	raw := json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"*.dev.example.com","ports":["tcp:443"]}]}]`)
	grants := Parse(map[string]json.RawMessage{Capability: raw}, g)
	if !Authorize(grants, "tag:home", "a.dev.example.com", "tcp", 443) || Authorize(grants, "tag:home", "a.b.dev.example.com", "tcp", 443) {
		t.Fatal("wildcard or port matcher incorrect")
	}
	a := NewAllocator()
	one, _ := a.Allocate("tag:home", g["tag:home"].Prefix, "one.dev.example.com")
	two, _ := a.Allocate("tag:home", g["tag:home"].Prefix, "two.dev.example.com")
	if one == two {
		t.Fatal("resources shared an address")
	}
}

func TestMalformedPortFailsClosed(t *testing.T) {
	g := map[string]Gateway{"tag:home": {Prefix: netip.MustParsePrefix("10.254.0.0/29")}}
	grants := Parse(map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"a.example.com","ports":["tcp:70000"]}]}]`)}, g)
	if len(grants) != 0 {
		t.Fatal("invalid port authorized")
	}
}

func TestServiceReauthorizesFlowsAndRestoresAllocations(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefix: netip.MustParsePrefix("10.254.0.0/29")}}
	source := netip.MustParseAddr("100.64.0.2")
	other := netip.MustParseAddr("100.64.0.3")
	caps := map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"app.example.com","ports":["tcp:443"]}]}]`)}
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
	ip, err := allocated.Allocate("tag:home", netip.MustParsePrefix("10.254.0.0/29"), "app.example.com")
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
	firstIP, err := first.Allocate(context.Background(), firstCache, "tag:home", prefix, "app.example.com", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	secondIP, err := second.Allocate(context.Background(), secondCache, "tag:home", prefix, "app.example.com", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if firstIP != secondIP {
		t.Fatalf("replicas allocated %s and %s for one domain", firstIP, secondIP)
	}
	otherIP, err := second.Allocate(context.Background(), NewAllocator(), "tag:home", prefix, "other.example.com", now, time.Hour)
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
	ip, err := store.Allocate(context.Background(), first, "tag:home", netip.MustParsePrefix("10.254.0.0/29"), "app.example.com", clock, lease)
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
	reused, err := store.Allocate(context.Background(), NewAllocator(), "tag:home", netip.MustParsePrefix("10.254.0.0/29"), "other.example.com", clock.Add(119*time.Minute), lease)
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
	gateways := map[string]Gateway{"tag:home": {Prefix: netip.MustParsePrefix("10.254.0.0/29")}}
	source := netip.MustParseAddr("100.64.0.2")
	caps := map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"app.example.com","ports":["tcp:443"]}]}]`)}
	service := &Service{Identity: fakeIdentity{source: caps}, Gateways: gateways}
	if _, ok := service.FlowDomain(context.Background(), source, netip.MustParseAddr("10.254.0.2"), "app.example.com.", "tcp", 443); !ok {
		t.Fatal("PTR-reconstructed domain was not authorized")
	}
	if _, ok := service.FlowDomain(context.Background(), source, netip.MustParseAddr("10.254.0.2"), "other.example.com", "tcp", 443); ok {
		t.Fatal("PTR name bypassed domain policy")
	}
}

func TestGatewaySourceNeverReceivesSyntheticForwardAnswer(t *testing.T) {
	gateways := map[string]Gateway{"tag:home": {Prefix: netip.MustParsePrefix("10.254.0.0/29")}}
	source := netip.MustParseAddr("100.64.0.2")
	caps := map[string]json.RawMessage{Capability: json.RawMessage(`[{"gateway":"tag:home","resources":[{"domain":"app.example.com"}]}]`)}
	service := &Service{Identity: gatewayIdentity{fakeIdentity: fakeIdentity{source: caps}, tagged: map[netip.Addr]bool{source: true}}, Gateways: gateways, Allocations: NewAllocator()}
	if _, ok := service.DNS(context.Background(), source, "app.example.com"); ok {
		t.Fatal("gateway source received synthetic DNS")
	}
}
