package main

import (
	"context"
	"encoding/binary"
	"github.com/matchlighter/headscale-domain-proxies/internal/domain"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type taggedNodes []domain.TaggedNode

func (n taggedNodes) TaggedNodes(context.Context) ([]domain.TaggedNode, error) { return n, nil }

func TestParseCommandSeparatesRoleTransportAndConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"tsnet":{"dir":"from-file","hostname":"from-file-host","auth_key":"from-file-key","control_url":"https://headscale.example.test","tags":["tag:file"]},"database":"postgres://from-file","egress":{"tag":"tag:file","ranges":["10.254.0.0/18"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cmd, err := parseCommand([]string{"egress", "-config", path, "-mode", "tailscaled", "-gateway-listen", "127.0.0.1:15001", "-tsnet-control-url", "https://flag.example.test", "-tsnet-tags", "tag:one,tag:two"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Role != "egress" || cmd.Transport != "tailscaled" {
		t.Fatalf("role/transport = %q/%q", cmd.Role, cmd.Transport)
	}
	if cmd.Config.GatewayListen != "127.0.0.1:15001" || len(cmd.Config.TSNet.Tags) != 2 || cmd.Config.TSNet.Dir != "from-file" || cmd.Config.TSNet.Hostname != "from-file-host" || cmd.Config.TSNet.AuthKey != "from-file-key" || cmd.Config.TSNet.ControlURL != "https://flag.example.test" || cmd.Config.Database != "postgres://from-file" {
		t.Fatalf("flags did not override and retain configuration: %+v", cmd.Config)
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
	data := []byte(`{"egress":{"tag":"tag:gateway1","ranges":["10.254.0.0/18"]}}`)
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
	if cmd.Config.Egress.Tag != "tag:gateway1" || len(cmd.Config.Egress.Ranges) != 1 {
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

func TestDNSGatewayTopologyUsesNodeAttrOverrideOverDiscovery(t *testing.T) {
	override := netip.MustParsePrefix("10.254.0.0/18")
	discovered := netip.MustParsePrefix("10.254.64.0/18")
	config := domain.NodeConfig{UpstreamDNS: "127.0.0.1:53", Gateways: map[string][]netip.Prefix{"tag:gateway1": {override}}}
	got, _, err := dnsGatewayTopology(context.Background(), config, taggedNodes{{Tags: map[string]struct{}{"tag:gateway1": {}}, PrimaryRoutes: []netip.Prefix{discovered}}})
	if err != nil {
		t.Fatal(err)
	}
	if prefixes := got["tag:gateway1"].Prefixes; len(prefixes) != 1 || prefixes[0] != override {
		t.Fatalf("topology = %v, want override %v", prefixes, override)
	}
}
