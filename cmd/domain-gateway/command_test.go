package main

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/matchlighter/headscale-domain-proxies/internal/domain"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
)

func TestParseCommandSeparatesRoleTransportAndConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"tsnet":{"dir":"from-file","hostname":"from-file-host","auth_key":"from-file-key","control_url":"https://headscale.example.test","tags":["tag:file"]},"database":"postgres://from-file","egress":{"ranges":["10.254.0.0/18"],"dns_resolver":"192.0.2.53"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cmd, err := parseCommand([]string{"egress", "-config", path, "-mode", "tailscaled", "-gateway-listen", "127.0.0.1:15001", "-tsnet-control-url", "https://flag.example.test", "-tsnet-tags", "tag:one,tag:two"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Role != "egress" || cmd.Transport != "tailscaled" {
		t.Fatalf("role/transport = %q/%q", cmd.Role, cmd.Transport)
	}
	if cmd.Config.GatewayListen != "127.0.0.1:15001" || len(cmd.Config.TSNet.Tags) != 2 || cmd.Config.TSNet.Dir != "from-file" || cmd.Config.TSNet.Hostname != "from-file-host" || cmd.Config.TSNet.AuthKey != "from-file-key" || cmd.Config.TSNet.ControlURL != "https://flag.example.test" || cmd.Config.Database != "postgres://from-file" || cmd.Config.Egress.DNSResolver != "192.0.2.53" {
		t.Fatalf("flags did not override and retain configuration: %+v", cmd.Config)
	}
}

func TestEgressDNSResolverOverridesPTRResolver(t *testing.T) {
	c := config{Egress: &egressConfig{Ranges: []string{"10.254.0.0/18"}, DNSResolver: "192.0.2.53"}}
	resolver, configured, err := egressPTRResolver(c)
	if err != nil {
		t.Fatal(err)
	}
	if !configured || resolver != "192.0.2.53:53" {
		t.Fatalf("PTR resolver = %q, configured = %v", resolver, configured)
	}
	gateways, err := egressGateways(c, "100.100.100.100:53")
	if err != nil {
		t.Fatal(err)
	}
	if got := gateways[localEgressGatewayKey].Resolver; got != "100.100.100.100:53" {
		t.Fatalf("backend resolver = %q, want appcap fallback", got)
	}
}

func TestEgressDNSResolverRejectsNonIP(t *testing.T) {
	c := config{Egress: &egressConfig{Ranges: []string{"10.254.0.0/18"}, DNSResolver: "resolver.example.test"}}
	if _, _, err := egressPTRResolver(c); err == nil {
		t.Fatal("egress accepted a non-IP DNS resolver")
	}
}

func TestEgressUpstreamDNSInterface(t *testing.T) {
	base := config{Egress: &egressConfig{Ranges: []string{"10.254.0.0/18"}}}
	if got, err := egressUpstreamDNSInterface(base); err != nil || got != "auto" {
		t.Fatalf("default interface = %q, %v", got, err)
	}
	for _, value := range []string{"host", "tailnet"} {
		base.Egress.UpstreamDNSInterface = value
		if got, err := egressUpstreamDNSInterface(base); err != nil || got != value {
			t.Fatalf("interface %q = %q, %v", value, got, err)
		}
	}
	base.Egress.UpstreamDNSInterface = "invalid"
	if _, err := egressUpstreamDNSInterface(base); err == nil {
		t.Fatal("accepted invalid interface")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"egress":{"ranges":["10.254.0.0/18"],"upstream_dns_interface":"invalid"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCommand([]string{"egress", "-config", path}); err == nil {
		t.Fatal("parsed invalid interface")
	}
}

func TestEgressBackendResolverPrecedence(t *testing.T) {
	c := config{UpstreamResolver: "192.0.2.10:53"}
	resolver, system, err := egressBackendResolver(c, domain.NodeConfig{})
	if err != nil || system || resolver != "192.0.2.10:53" {
		t.Fatalf("local fallback = %q, system=%v, err=%v", resolver, system, err)
	}
	resolver, system, err = egressBackendResolver(c, domain.NodeConfig{UpstreamDNS: "192.0.2.11:53", HasUpstreamDNS: true})
	if err != nil || system || resolver != "192.0.2.11:53" {
		t.Fatalf("gateway NodeAttr = %q, system=%v, err=%v", resolver, system, err)
	}
}

func TestEgressRejectsInvalidLocalUpstreamResolver(t *testing.T) {
	c := config{Egress: &egressConfig{Ranges: []string{"10.254.0.0/18"}}, UpstreamResolver: "resolver.example.test"}
	if _, err := configuredResolver(c.UpstreamResolver); err == nil {
		t.Fatal("accepted a local resolver without a port")
	}
}

func TestPTRLookupUsesSelectedDialer(t *testing.T) {
	var addresses []string
	_, _ = lookupPTR(context.Background(), netip.MustParseAddr("10.254.0.1"), []string{"100.72.95.65:53"}, func(_ context.Context, _ string, address string) (net.Conn, error) {
		addresses = append(addresses, address)
		return nil, errors.New("dial stopped")
	})
	if len(addresses) == 0 || addresses[0] != "100.72.95.65:53" {
		t.Fatalf("PTR lookup dialed %v, want the Tailnet DNS authority", addresses)
	}
}

func TestAutoUsesTailnetForControlPlaneAddresses(t *testing.T) {
	status := &ipnstate.Status{TailscaleIPs: []netip.Addr{netip.MustParseAddr("10.77.0.2")}, Self: &ipnstate.PeerStatus{TailscaleIPs: []netip.Addr{netip.MustParseAddr("fd00:1234::2")}}}
	for _, resolver := range []string{"10.77.0.2:53", "[fd00:1234::2]:53"} {
		if !autoUsesTailnet(status, resolver) {
			t.Fatalf("auto did not select tailnet for control-plane address %q", resolver)
		}
	}
	if autoUsesTailnet(status, "100.72.95.65:53") {
		t.Fatal("auto selected tailnet for an address absent from the current Tailnet")
	}
}

func TestPrefixesContainResolver(t *testing.T) {
	routes := []netip.Prefix{netip.MustParsePrefix("10.1.2.0/24")}
	if !prefixesContainResolver(routes, "10.1.2.8:53") {
		t.Fatal("resolver inside route was not detected")
	}
	if prefixesContainResolver(routes, "10.1.3.8:53") {
		t.Fatal("resolver outside route was detected")
	}
	if prefixesContainResolver(routes, "resolver.example:53") {
		t.Fatal("hostname resolver was detected as a routed IP")
	}
}

func TestParseCommandAcceptsHuJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.hujson")
	data := []byte(`{
		// A human-maintained configuration may use comments and trailing commas.
		"tsnet": {"dir": "from-file",},
	}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd, err := parseCommand([]string{"dns", "-config", path})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Config.TSNet.Dir != "from-file" {
		t.Fatalf("tsnet.dir = %q", cmd.Config.TSNet.Dir)
	}
}

func TestServerFailureSetsSERVFAIL(t *testing.T) {
	request := make([]byte, 17)
	binary.BigEndian.PutUint16(request[4:6], 1)
	response := serverFailure(request, 17)
	if got := binary.BigEndian.Uint16(response[2:4]) & 15; got != 2 {
		t.Fatalf("rcode = %d, want SERVFAIL", got)
	}
}

func TestParseCommandRejectsLegacyTopLevelTSNetConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"tsnet_dir":"from-file"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCommand([]string{"dns", "-config", path}); err == nil || !strings.Contains(err.Error(), "no longer supported") {
		t.Fatal("legacy top-level tsnet configuration was accepted")
	}
}

func TestNewTSNetUsesNestedConfiguration(t *testing.T) {
	dir := t.TempDir()
	server, err := newTSNet(config{TSNet: tsnetConfig{
		Dir:        dir,
		Hostname:   "domain-dns",
		AuthKey:    "tskey-auth-test",
		ControlURL: "https://headscale.example.test",
		Tags:       []string{"tag:dns"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if server.Dir != dir || server.Hostname != "domain-dns" || server.AuthKey != "tskey-auth-test" || server.ControlURL != "https://headscale.example.test" || server.AdvertiseTags != nil {
		t.Fatalf("server = %+v", server)
	}
}

func TestParseCommandRejectsLegacyRoleAndInvalidTransport(t *testing.T) {
	if _, err := parseCommand([]string{"-mode", "dns"}); err == nil {
		t.Fatal("legacy role selector was accepted")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCommand([]string{"dns", "-config=" + path, "-mode", "auto"}); err == nil {
		t.Fatal("invalid transport was accepted")
	}
}

func TestParseCommandRejectsInvalidAllocationLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"allocation_lease":"zero"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCommand([]string{"dns", "-config", path}); err == nil {
		t.Fatal("invalid allocation lease was accepted")
	}
}

func TestParseCommandScopesEgressAssignmentToEgressRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"egress":{"ranges":["10.254.0.0/18"]}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCommand([]string{"dns", "-config", path}); err == nil {
		t.Fatal("dns accepted an egress assignment")
	}
	cmd, err := parseCommand([]string{"egress", "-config", path})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Config.Egress.Ranges) != 1 {
		t.Fatalf("egress assignment = %+v", cmd.Config.Egress)
	}
	path = filepath.Join(t.TempDir(), "missing.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCommand([]string{"egress", "-config", path}); err == nil {
		t.Fatal("egress accepted no assignment")
	}
}

func TestParseCommandRejectsRemovedEgressTag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"egress":{"tag":"tag:gateway1","ranges":["10.254.0.0/18"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCommand([]string{"egress", "-config", path}); err == nil || !strings.Contains(err.Error(), "egress.tag is no longer supported") {
		t.Fatalf("legacy egress tag error = %v", err)
	}
}

func TestDNSGatewaysDoNotConfigureRoutes(t *testing.T) {
	got, _, err := dnsGateways(domain.NodeConfig{UpstreamDNS: "127.0.0.1:53"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("DNS gateway routes = %v, want none", got)
	}
}
