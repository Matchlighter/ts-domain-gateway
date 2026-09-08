package domain

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/netip"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLocalAPIWhoIsRequestShapes(t *testing.T) {
	requests := 0
	api := &LocalAPI{client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Path != "/localapi/v0/whois" {
			t.Fatalf("whois request path = %q", request.URL.Path)
		}
		if got := request.URL.Query().Get("addr"); got != "100.64.0.2" {
			t.Fatalf("whois addr = %q", got)
		}
		if requests == 1 && request.URL.Query().Get("dst_ip") != "10.0.0.1" {
			t.Fatalf("capability destination = %q", request.URL.Query().Get("dst_ip"))
		}
		if requests == 2 && request.URL.Query().Get("dst_ip") != "" {
			t.Fatalf("gateway destination = %q", request.URL.Query().Get("dst_ip"))
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"CapMap":{"cap":[]},"Node":{"Tags":["tag:egress"]}}`)), Header: make(http.Header)}, nil
	})}}
	source := netip.MustParseAddr("100.64.0.2")
	if caps, err := api.Capabilities(context.Background(), source, netip.MustParseAddr("10.0.0.1")); err != nil || caps == nil {
		t.Fatalf("Capabilities() = %v, %v", caps, err)
	}
	if gateway, err := api.IsGateway(context.Background(), source, map[string]Gateway{"tag:egress": {}}); err != nil || !gateway {
		t.Fatalf("IsGateway() = %v, %v", gateway, err)
	}
}

func TestResolveTagsUsesCurrentTailnetNodeTags(t *testing.T) {
	status := `{"Self":{"TailscaleIPs":["100.64.0.2"],"Tags":["tag:prod"]}}`
	source := &LocalAPI{client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/localapi/v0/status" {
			t.Fatalf("status request path = %q", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(status)), Header: make(http.Header)}, nil
	})}}
	addresses, tagged := ResolveTags(context.Background(), "prod.tags.", source)
	if !tagged || len(addresses) != 1 || addresses[0] != "100.64.0.2" {
		t.Fatalf("initial tag resolution = %v, %v", addresses, tagged)
	}

	// Status is consulted for each request, so control-plane tag changes do
	// not require a second tagged_nodes configuration or a process restart.
	status = `{"Peer":{"node":{"TailscaleIPs":["100.64.0.3"],"Tags":["tag:prod"]}}}`
	addresses, tagged = ResolveTags(context.Background(), "prod.tags.", source)
	if !tagged || len(addresses) != 1 || addresses[0] != "100.64.0.3" {
		t.Fatalf("refreshed tag resolution = %v, %v", addresses, tagged)
	}
}
