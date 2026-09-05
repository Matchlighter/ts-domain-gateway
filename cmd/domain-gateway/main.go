// domain-gateway is a low-allocation UDP synthetic-DNS server.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/matchlighter/headscale-domain-proxies/internal/domain"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/tsnet"
)

type config struct {
	Listen           string   `json:"dns_listen"`
	GatewayListen    string   `json:"gateway_listen"`
	TailscaledSocket string   `json:"tailscaled_socket"`
	StateDB          string   `json:"state_db"`
	TSNetDir         string   `json:"tsnet_dir"`
	TSNetHostname    string   `json:"tsnet_hostname"`
	TSNetAuthKey     string   `json:"tsnet_auth_key"`
	TSNetTags        []string `json:"tsnet_tags"`
	TaggedNodes      []struct {
		Address string   `json:"address"`
		Tags    []string `json:"tags"`
	}
}

func question(b []byte) (string, int, int, bool) {
	if len(b) < 17 || binary.BigEndian.Uint16(b[4:6]) != 1 {
		return "", 0, 0, false
	}
	p := 12
	labels := make([]string, 0, 4)
	for {
		if p >= len(b) {
			return "", 0, 0, false
		}
		n := int(b[p])
		p++
		if n == 0 {
			break
		}
		if n > 63 || p+n > len(b) {
			return "", 0, 0, false
		}
		labels = append(labels, string(b[p:p+n]))
		p += n
	}
	if p+4 > len(b) {
		return "", 0, 0, false
	}
	return strings.Join(labels, "."), int(binary.BigEndian.Uint16(b[p : p+2])), p + 4, true
}
func answer(req []byte, end int, ip netip.Addr) []byte {
	out := make([]byte, end+16)
	copy(out[:end], req[:end])
	binary.BigEndian.PutUint16(out[2:4], 0x8000|(binary.BigEndian.Uint16(req[2:4])&0x0100))
	if ip.IsValid() {
		binary.BigEndian.PutUint16(out[6:8], 1)
		p := end
		out[p] = 0xc0
		out[p+1] = 0x0c
		binary.BigEndian.PutUint16(out[p+2:p+4], 1)
		binary.BigEndian.PutUint16(out[p+4:p+6], 1)
		binary.BigEndian.PutUint32(out[p+6:p+10], 60)
		binary.BigEndian.PutUint16(out[p+10:p+12], 4)
		copy(out[p+12:p+16], ip.AsSlice())
	} else {
		out = out[:end]
	}
	return out
}
func ptrName(name string) (netip.Addr, bool) {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	if len(parts) != 6 || parts[4] != "in-addr" || parts[5] != "arpa" {
		return netip.Addr{}, false
	}
	var octets [4]byte
	for i := 0; i < 4; i++ {
		var n uint16
		for _, c := range parts[3-i] {
			if c < '0' || c > '9' {
				return netip.Addr{}, false
			}
			n = n*10 + uint16(c-'0')
			if n > 255 {
				return netip.Addr{}, false
			}
		}
		octets[i] = byte(n)
	}
	return netip.AddrFrom4(octets), true
}
func encodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}
func ptrAnswer(req []byte, end int, name string) []byte {
	rdata := encodeName(name)
	out := make([]byte, end+12+len(rdata))
	copy(out[:end], req[:end])
	binary.BigEndian.PutUint16(out[2:4], 0x8000|(binary.BigEndian.Uint16(req[2:4])&0x0100))
	binary.BigEndian.PutUint16(out[6:8], 1)
	p := end
	out[p] = 0xc0
	out[p+1] = 0x0c
	binary.BigEndian.PutUint16(out[p+2:p+4], 12)
	binary.BigEndian.PutUint16(out[p+4:p+6], 1)
	binary.BigEndian.PutUint32(out[p+6:p+10], 60)
	binary.BigEndian.PutUint16(out[p+10:p+12], uint16(len(rdata)))
	copy(out[p+12:], rdata)
	return out
}
func main() {
	path := flag.String("config", "config.json", "")
	mode := flag.String("mode", "dns", "dns or gateway")
	space := flag.String("space", "auto", "gateway dataplane: auto, kernel, or user")
	flag.Parse()
	data, err := os.ReadFile(*path)
	if err != nil {
		log.Fatal(err)
	}
	var c config
	if err = json.Unmarshal(data, &c); err != nil {
		log.Fatal(err)
	}
	if *mode == "gateway" {
		runGateway(context.Background(), c, *space)
		return
	}
	runDNS(context.Background(), c)
}

func gateways(nodeConfig domain.NodeConfig) (map[string]domain.Gateway, string, error) {
	upstream := nodeConfig.UpstreamDNS
	var err error
	if domain.IsSystemResolver(upstream) {
		upstream, err = systemUpstream()
		if err != nil {
			return nil, "", err
		}
	}
	gs := make(map[string]domain.Gateway, len(nodeConfig.Gateways))
	for _, gateway := range nodeConfig.Gateways {
		p, err := netip.ParsePrefix(gateway.Prefix)
		if err != nil {
			return nil, "", err
		}
		gs[gateway.Tag] = domain.Gateway{Prefix: p, Resolver: upstream}
	}
	return gs, upstream, nil
}

func newTSNet(c config) (*tsnet.Server, error) {
	if c.TSNetDir == "" {
		return nil, fmt.Errorf("tsnet_dir is required for userspace mode")
	}
	return &tsnet.Server{Dir: c.TSNetDir, Hostname: c.TSNetHostname, AuthKey: c.TSNetAuthKey, AdvertiseTags: c.TSNetTags}, nil
}

func runGateway(ctx context.Context, c config, space string) {
	if space != "auto" && space != "kernel" && space != "user" {
		log.Fatalf("invalid --space %q (want auto, kernel, or user)", space)
	}
	api := domain.NewLocalAPI(c.TailscaledSocket)
	nodeConfig, kernelErr := api.NodeConfig(ctx)
	if space == "kernel" && kernelErr != nil {
		log.Fatalf("--space=kernel requires a usable tailscaled LocalAPI: %v", kernelErr)
	}
	if space == "kernel" || (space == "auto" && kernelErr == nil) {
		gs, _, err := gateways(nodeConfig)
		if err != nil {
			log.Fatal(err)
		}
		s := &domain.Service{Identity: api, Gateways: gs}
		if err := s.ServeTCP(ctx, c.GatewayListen); err != nil {
			log.Fatal(err)
		}
		return
	}
	server, err := newTSNet(c)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := server.Up(ctx); err != nil {
		log.Fatal(err)
	}
	client, err := server.LocalClient()
	if err != nil {
		log.Fatal(err)
	}
	identity := domain.TSNetIdentity{Client: client}
	nodeConfig, err = identity.NodeConfig(ctx)
	if err != nil {
		log.Fatal("missing or invalid domain-gateway NodeAttr: ", err)
	}
	gs, _, err := gateways(nodeConfig)
	if err != nil {
		log.Fatal(err)
	}
	if err := (&domain.Service{Identity: identity, Gateways: gs}).ServeTSNetGateway(ctx, server); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
}

func runDNS(ctx context.Context, c config) {
	server, err := newTSNet(c)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := server.Up(ctx); err != nil {
		log.Fatal(err)
	}
	client, err := server.LocalClient()
	if err != nil {
		log.Fatal(err)
	}
	identity := domain.TSNetIdentity{Client: client}
	nodeConfig, err := identity.NodeConfig(ctx)
	if err != nil {
		log.Fatal("missing or invalid domain-gateway NodeAttr: ", err)
	}
	gs, upstream, err := gateways(nodeConfig)
	if err != nil {
		log.Fatal(err)
	}
	alloc := domain.NewAllocator()
	if c.StateDB != "" {
		if err := alloc.Load(c.StateDB); err != nil {
			log.Fatal(err)
		}
	}
	s := &domain.Service{Identity: identity, Gateways: gs, Allocations: alloc, StatePath: c.StateDB}
	nodes := make([]domain.TaggedNode, 0, len(c.TaggedNodes))
	for _, n := range c.TaggedNodes {
		tags := map[string]struct{}{}
		for _, tag := range n.Tags {
			tags[tag] = struct{}{}
		}
		nodes = append(nodes, domain.TaggedNode{Address: n.Address, Tags: tags})
	}
	ip4, _ := server.TailscaleIPs()
	conn, err := server.ListenPacket("udp", net.JoinHostPort(ip4.String(), "53"))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	upstreamAddr := mustAddr(upstream)
	serveDNS(ctx, conn, s, nodes, upstreamAddr)
}

func serveDNS(ctx context.Context, conn net.PacketConn, s *domain.Service, nodes []domain.TaggedNode, upstreamAddr *net.UDPAddr) {
	pool := sync.Pool{New: func() any { return make([]byte, 65535) }}
	jobs := make(chan struct{}, 256)
	for {
		buf := pool.Get().([]byte)
		n, src, e := conn.ReadFrom(buf)
		if e != nil {
			pool.Put(buf)
			continue
		}
		jobs <- struct{}{}
		go func(b []byte, src net.Addr) {
			defer func() { <-jobs; pool.Put(b) }()
			name, typ, end, ok := question(b)
			if !ok {
				return
			}
			if typ == 12 {
				if synthetic, reverse := ptrName(name); reverse {
					if mapping, found := s.Allocations.Lookup(synthetic); found {
						conn.WriteTo(ptrAnswer(b, end, mapping.Domain), src)
					} else {
						conn.WriteTo(answer(b, end, netip.Addr{}), src)
					}
					return
				}
			}
			if ips, tagged := domain.TagExpression(name, nodes); tagged {
				if typ == 1 && len(ips) > 0 {
					if ip, err := netip.ParseAddr(ips[0]); err == nil {
						conn.WriteTo(answer(b, end, ip), src)
					}
				}
				return
			}
			srcAddr, ok := sourceIP(src)
			if !ok {
				return
			}
			ip, yes := s.DNS(ctx, srcAddr, name)
			if yes {
				if typ == 1 {
					conn.WriteTo(answer(b, end, ip), src)
				} else if typ == 28 {
					conn.WriteTo(answer(b, end, netip.Addr{}), src)
				}
				return
			}
			// Resource misses and unauthorized queries intentionally preserve ordinary DNS.
			forward(conn, b[:n], src, upstreamAddr)
		}(buf[:n], src)
	}
}

func sourceIP(source net.Addr) (netip.Addr, bool) {
	if udp, ok := source.(*net.UDPAddr); ok {
		addr, ok := netip.AddrFromSlice(udp.IP)
		return addr, ok
	}
	addrPort, err := netip.ParseAddrPort(source.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return addrPort.Addr(), true
}

func systemUpstream() (string, error) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "nameserver" || fields[1] == "100.100.100.100" {
			continue
		}
		if net.ParseIP(fields[1]) != nil {
			return net.JoinHostPort(fields[1], strconv.Itoa(53)), nil
		}
	}
	return "", fmt.Errorf("system resolver has no non-Tailscale nameserver")
}
func forward(listener net.PacketConn, request []byte, client net.Addr, upstream *net.UDPAddr) {
	c, e := net.DialUDP("udp", nil, upstream)
	if e != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = c.Write(request); e != nil {
		return
	}
	buf := make([]byte, 65535)
	if n, e := c.Read(buf); e == nil {
		listener.WriteTo(buf[:n], client)
	}
}
func mustAddr(s string) *net.UDPAddr {
	a, e := net.ResolveUDPAddr("udp", s)
	if e != nil {
		log.Fatal(e)
	}
	return a
}
