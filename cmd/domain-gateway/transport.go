package main

import (
	"context"
	"net"
	"net/netip"

	"github.com/matchlighter/headscale-domain-proxies/internal/domain"
	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

// tailnetTransport is the normalized connection to either selected Tailnet
// adapter. It deliberately does not fall back between adapters.
type tailnetTransport struct {
	Identity      domain.Identity
	Nodes         domain.TaggedNodeSource
	NodeConfig    domain.NodeConfig
	NodeConfigErr error
	IP            netip.Addr
	Server        *tsnet.Server
	Client        *local.Client
}

func openTailnetTransport(ctx context.Context, c config, mode string, needIP bool) (tailnetTransport, error) {
	if mode == "tailscaled" {
		api := domain.NewLocalAPI(c.TailscaledSocket)
		transport := tailnetTransport{Identity: api, Nodes: api}
		transport.NodeConfig, transport.NodeConfigErr = api.NodeConfig(ctx)
		if needIP {
			ip, err := api.TailscaleIP(ctx)
			if err != nil {
				return tailnetTransport{}, err
			}
			transport.IP = ip
		}
		return transport, nil
	}

	server, err := newTSNet(c)
	if err != nil {
		return tailnetTransport{}, err
	}
	if _, err := server.Up(ctx); err != nil {
		return tailnetTransport{}, err
	}
	client, err := server.LocalClient()
	if err != nil {
		return tailnetTransport{}, err
	}
	identity := domain.TSNetIdentity{Client: client}
	transport := tailnetTransport{Identity: identity, Nodes: identity, Server: server, Client: client}
	transport.NodeConfig, transport.NodeConfigErr = identity.NodeConfig(ctx)
	if needIP {
		transport.IP, _ = server.TailscaleIPs()
	}
	return transport, nil
}

func (t tailnetTransport) listenUDP(address string) (net.PacketConn, error) {
	if t.Server != nil {
		return t.Server.ListenPacket("udp", address)
	}
	return net.ListenPacket("udp", address)
}
