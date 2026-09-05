package domain

import (
	"context"
	"net"
	"net/netip"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// ServeTSNetGateway advertises prefixes and receives their TCP flows in the
// tsnet userspace netstack. No host route, NAT, or SO_ORIGINAL_DST is involved.
func (s *Service) ServeTSNetGateway(ctx context.Context, server *tsnet.Server) error {
	if err := server.Start(); err != nil {
		return err
	}
	client, err := server.LocalClient()
	if err != nil {
		return err
	}
	routes := make([]netip.Prefix, 0, len(s.Gateways))
	for _, gateway := range s.Gateways {
		routes = append(routes, gateway.Prefix)
	}
	if _, err := client.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{AdvertiseRoutes: routes}, AdvertiseRoutesSet: true}); err != nil {
		return err
	}
	server.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		known := false
		for _, gateway := range s.Gateways {
			if gateway.Prefix.Contains(dst.Addr()) {
				known = true
				break
			}
		}
		if !known {
			return nil, false
		}
		return func(conn net.Conn) { defer conn.Close(); s.ProxyTCP(ctx, conn, src, dst) }, true
	})
	<-ctx.Done()
	return ctx.Err()
}
