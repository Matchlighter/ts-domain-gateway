package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCommandSeparatesRoleTransportAndConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"tsnet_dir":"from-file","tsnet_tags":["tag:file"],"database":"postgres://from-file"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cmd, err := parseCommand([]string{"egress", "-config", path, "-mode", "tailscaled", "-gateway-listen", "127.0.0.1:15001", "-tsnet-tags", "tag:one,tag:two"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Role != "egress" || cmd.Transport != "tailscaled" {
		t.Fatalf("role/transport = %q/%q", cmd.Role, cmd.Transport)
	}
	if cmd.Config.GatewayListen != "127.0.0.1:15001" || len(cmd.Config.TSNetTags) != 2 || cmd.Config.TSNetDir != "from-file" || cmd.Config.Database != "postgres://from-file" {
		t.Fatalf("flags did not override and retain configuration: %+v", cmd.Config)
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
