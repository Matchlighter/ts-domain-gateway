package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCommandSeparatesRoleTransportAndConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"tsnet":{"dir":"from-file","hostname":"from-file-host","auth_key":"from-file-key","tags":["tag:file"]},"database":"postgres://from-file"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cmd, err := parseCommand([]string{"egress", "-config", path, "-mode", "tailscaled", "-gateway-listen", "127.0.0.1:15001", "-tsnet-tags", "tag:one,tag:two"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Role != "egress" || cmd.Transport != "tailscaled" {
		t.Fatalf("role/transport = %q/%q", cmd.Role, cmd.Transport)
	}
	if cmd.Config.GatewayListen != "127.0.0.1:15001" || len(cmd.Config.TSNet.Tags) != 2 || cmd.Config.TSNet.Dir != "from-file" || cmd.Config.TSNet.Hostname != "from-file-host" || cmd.Config.TSNet.AuthKey != "from-file-key" || cmd.Config.Database != "postgres://from-file" {
		t.Fatalf("flags did not override and retain configuration: %+v", cmd.Config)
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
		Dir:      dir,
		Hostname: "domain-dns",
		AuthKey:  "tskey-auth-test",
		Tags:     []string{"tag:dns"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if server.Dir != dir || server.Hostname != "domain-dns" || server.AuthKey != "tskey-auth-test" || server.AdvertiseTags != nil {
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
