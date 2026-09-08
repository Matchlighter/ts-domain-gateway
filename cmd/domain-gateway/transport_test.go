package main

import (
	"context"
	"testing"
)

func TestTailnetTransportKeepsSelectedTailscaledAdapter(t *testing.T) {
	transport, err := openTailnetTransport(context.Background(), config{TailscaledSocket: t.TempDir() + "/missing.sock"}, "tailscaled", false)
	if err != nil {
		t.Fatal(err)
	}
	if transport.Server != nil || transport.Client != nil {
		t.Fatal("tailscaled selection constructed a tsnet fallback")
	}
	if transport.NodeConfigErr == nil {
		t.Fatal("tailscaled selection unexpectedly reached a missing daemon")
	}
}
