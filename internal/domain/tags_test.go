package domain

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
