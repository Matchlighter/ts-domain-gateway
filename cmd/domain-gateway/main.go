// domain-gateway is a low-allocation UDP synthetic-DNS server.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/matchlighter/headscale-domain-proxies/internal/domain"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/tsnet"
)

type config struct {
	Listen           string      `json:"dns_listen"`
	GatewayListen    string      `json:"gateway_listen"`
	TailscaledSocket string      `json:"tailscaled_socket"`
	Database         string      `json:"database"`
	AllocationLease  string      `json:"allocation_lease"`
	Egress            *egressConfig `json:"egress"`
	TSNet            tsnetConfig `json:"tsnet"`
}

// egressConfig is the local startup authority for one egress instance. It is
// deliberately separate from the DNS NodeAttr, which observes active routes.
type egressConfig struct {
	Tag    string   `json:"tag"`
	Ranges []string `json:"ranges"`
}

type tsnetConfig struct {
	Dir      string   `json:"dir"`
	Hostname string   `json:"hostname"`
	AuthKey  string   `json:"auth_key"`
	Tags     []string `json:"tags"`
}

type command struct {
	Role      string
	Transport string
	Config    config
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
		binary.BigEndian.PutUint32(out[p+6:p+10], 600)
		binary.BigEndian.PutUint16(out[p+10:p+12], 4)
		copy(out[p+12:p+16], ip.AsSlice())
	} else {
		out = out[:end]
	}
	return out
}

func serverFailure(req []byte, end int) []byte {
	out := answer(req, end, netip.Addr{})
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|2)
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
	binary.BigEndian.PutUint32(out[p+6:p+10], 600)
	binary.BigEndian.PutUint16(out[p+10:p+12], uint16(len(rdata)))
	copy(out[p+12:], rdata)
	return out
}
func main() {
	cmd, err := parseCommand(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if cmd.Role == "dns" {
		runDNS(context.Background(), cmd.Config, cmd.Transport)
		return
	}
	runEgress(context.Background(), cmd.Config, cmd.Transport)
}

func parseCommand(args []string) (command, error) {
	if len(args) == 0 || (args[0] != "dns" && args[0] != "egress") {
		return command{}, fmt.Errorf("usage: domain-gateway <dns|egress> [-mode tsnet|tailscaled] [-config path] [daemon flags]")
	}
	path, err := configPath(args[1:])
	if err != nil {
		return command{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return command{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return command{}, err
	}
	for _, name := range []string{"tsnet_dir", "tsnet_hostname", "tsnet_auth_key", "tsnet_tags"} {
		if _, found := fields[name]; found {
			return command{}, fmt.Errorf("%s is no longer supported; use tsnet.%s", name, strings.TrimPrefix(name, "tsnet_"))
		}
	}
	var c config
	if err := json.Unmarshal(data, &c); err != nil {
		return command{}, err
	}
	fs := flag.NewFlagSet("domain-gateway "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mode := fs.String("mode", "tsnet", "transport: tsnet or tailscaled")
	fs.String("config", path, "configuration file")
	fs.StringVar(&c.Listen, "dns-listen", c.Listen, "DNS UDP listen address")
	fs.StringVar(&c.GatewayListen, "gateway-listen", c.GatewayListen, "egress TCP listen address")
	fs.StringVar(&c.TailscaledSocket, "tailscaled-socket", c.TailscaledSocket, "tailscaled LocalAPI socket")
	fs.StringVar(&c.Database, "database", c.Database, "allocation database URL (sqlite:// or postgres://)")
	fs.StringVar(&c.AllocationLease, "allocation-lease", c.AllocationLease, "synthetic allocation lease duration")
	fs.StringVar(&c.TSNet.Dir, "tsnet-dir", c.TSNet.Dir, "tsnet state directory")
	fs.StringVar(&c.TSNet.Hostname, "tsnet-hostname", c.TSNet.Hostname, "tsnet hostname")
	fs.StringVar(&c.TSNet.AuthKey, "tsnet-auth-key", c.TSNet.AuthKey, "tsnet auth key")
	tags := fs.String("tsnet-tags", strings.Join(c.TSNet.Tags, ","), "comma-separated tsnet tags")
	if err := fs.Parse(args[1:]); err != nil {
		return command{}, err
	}
	if *mode != "tsnet" && *mode != "tailscaled" {
		return command{}, fmt.Errorf("invalid -mode %q (want tsnet or tailscaled)", *mode)
	}
	if c.AllocationLease != "" {
		lease, err := time.ParseDuration(c.AllocationLease)
		if err != nil || lease <= 0 {
			return command{}, fmt.Errorf("invalid allocation lease %q", c.AllocationLease)
		}
	}
	if args[0] == "dns" && c.Egress != nil {
		return command{}, fmt.Errorf("egress assignment is only valid for the egress role")
	}
	if args[0] == "egress" {
		if _, err := egressGateways(c, ""); err != nil {
			return command{}, err
		}
	}
	if *tags == "" {
		c.TSNet.Tags = nil
	} else {
		c.TSNet.Tags = strings.Split(*tags, ",")
	}
	return command{Role: args[0], Transport: *mode, Config: c}, nil
}

func egressGateways(c config, resolver string) (map[string]domain.Gateway, error) {
	if c.Egress == nil || c.Egress.Tag == "" || !strings.HasPrefix(c.Egress.Tag, "tag:") || len(c.Egress.Ranges) == 0 {
		return nil, fmt.Errorf("egress requires egress.tag and at least one egress.ranges entry")
	}
	prefixes := make([]netip.Prefix, 0, len(c.Egress.Ranges))
	for _, raw := range c.Egress.Ranges {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return nil, fmt.Errorf("invalid egress range %q", raw)
		}
		for _, prior := range prefixes {
			if prefix.Overlaps(prior) {
				return nil, fmt.Errorf("overlapping egress range %q", raw)
			}
		}
		prefixes = append(prefixes, prefix)
	}
	return map[string]domain.Gateway{c.Egress.Tag: {Prefixes: prefixes, Resolver: resolver}}, nil
}

func configPath(args []string) (string, error) {
	path := "config.json"
	for i := 0; i < len(args); i++ {
		if args[i] == "-config" || args[i] == "--config" {
			if i+1 == len(args) {
				return "", fmt.Errorf("%s requires a path", args[i])
			}
			path = args[i+1]
			i++
			continue
		}
		if value, ok := strings.CutPrefix(args[i], "-config="); ok {
			path = value
		}
		if value, ok := strings.CutPrefix(args[i], "--config="); ok {
			path = value
		}
	}
	return filepath.Clean(path), nil
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
	for tag, prefixes := range nodeConfig.Gateways {
		gs[tag] = domain.Gateway{Prefixes: prefixes, Resolver: upstream}
	}
	return gs, upstream, nil
}

// dnsGatewayTopology makes NodeAttr ranges an explicit administrative override
// while the normal path observes active PrimaryRoutes from stable status.
func dnsGatewayTopology(ctx context.Context, nodeConfig domain.NodeConfig, nodes domain.TaggedNodeSource) (map[string]domain.Gateway, string, error) {
	upstream := nodeConfig.UpstreamDNS
	if domain.IsSystemResolver(upstream) {
		var err error
		upstream, err = systemUpstream()
		if err != nil {
			return nil, "", err
		}
	}
	discovered, discoveryErr := func() (map[string][]netip.Prefix, error) {
		inventory, err := nodes.TaggedNodes(ctx)
		if err != nil {
			return nil, err
		}
		return domain.DiscoverGatewayRoutes(inventory)
	}()
	if nodeConfig.Gateways != nil {
		if discoveryErr != nil || !samePrefixes(nodeConfig.Gateways, discovered) {
			log.Printf("domain-gateway: NodeAttr gateway override differs from active route discovery (override=%v discovered=%v error=%v)", nodeConfig.Gateways, discovered, discoveryErr)
		}
		gs := make(map[string]domain.Gateway, len(nodeConfig.Gateways))
		for tag, prefixes := range nodeConfig.Gateways {
			gs[tag] = domain.Gateway{Prefixes: prefixes, Resolver: upstream}
		}
		return gs, upstream, nil
	}
	if discoveryErr != nil {
		return nil, upstream, discoveryErr
	}
	gs := make(map[string]domain.Gateway, len(discovered))
	for tag, prefixes := range discovered {
		gs[tag] = domain.Gateway{Prefixes: prefixes, Resolver: upstream}
	}
	return gs, upstream, nil
}

func samePrefixes(a, b map[string][]netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for tag, left := range a {
		right, ok := b[tag]
		if !ok || len(left) != len(right) {
			return false
		}
		for _, prefix := range left {
			found := false
			for _, candidate := range right {
				found = found || prefix == candidate
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func newTSNet(c config) (*tsnet.Server, error) {
	if c.TSNet.Dir == "" {
		return nil, fmt.Errorf("tsnet.dir is required for userspace mode")
	}
	authKey := c.TSNet.AuthKey
	if authKey == "" {
		authKey = os.Getenv("TS_AUTHKEY")
	}
	advertiseTags := c.TSNet.Tags
	if authKey != "" {
		// Headscale (correctly) takes tags from a tagged preauth key and
		// rejects a duplicate client-side request. This also prevents a local
		// process setting tags beyond those granted by its enrollment key.
		advertiseTags = nil
	}
	return &tsnet.Server{Dir: c.TSNet.Dir, Hostname: c.TSNet.Hostname, AuthKey: authKey, AdvertiseTags: advertiseTags}, nil
}

func runEgress(ctx context.Context, c config, transport string) {
	if transport == "tailscaled" {
		api := domain.NewLocalAPI(c.TailscaledSocket)
		resolver, err := systemUpstream()
		if err != nil {
			log.Fatal(err)
		}
		gs, err := egressGateways(c, resolver)
		if err != nil {
			log.Fatal(err)
		}
		s := &domain.Service{Identity: api, Gateways: gs}
		if err := s.ServeTCP(ctx, c.GatewayListen); err != nil {
			log.Fatal(err)
		}
		return
	}
	// The selected tsnet transport never falls back to the host daemon.
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
	dnsConfig, err := client.DNSConfig(ctx)
	if err != nil || len(dnsConfig.Resolvers) == 0 {
		log.Fatal("userspace gateway requires an advertised Tailscale DNS resolver")
	}
	dnsResolvers := make([]string, 0, len(dnsConfig.Resolvers))
	for _, resolver := range dnsConfig.Resolvers {
		if resolver.Addr == "" {
			continue
		}
		addr := resolver.Addr
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		dnsResolvers = append(dnsResolvers, addr)
	}
	if len(dnsResolvers) == 0 {
		log.Fatal("userspace gateway requires an advertised Tailscale DNS resolver")
	}
	gs, err := egressGateways(c, dnsResolvers[0])
	if err != nil {
		log.Fatal(err)
	}
	s := &domain.Service{Identity: identity, Gateways: gs, PTRLookup: func(ctx context.Context, ip netip.Addr) ([]string, error) {
		var last error
		for _, dnsAddr := range dnsResolvers {
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return server.Dial(ctx, network, dnsAddr)
			}}
			names, err := resolver.LookupAddr(ctx, ip.String())
			if err == nil && len(names) != 0 {
				return names, nil
			}
			last = err
		}
		return nil, last
	}}
	if err := s.ServeTSNetGateway(ctx, server); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
}

func runDNS(ctx context.Context, c config, transport string) {
	var identity domain.Identity
	var nodes domain.TaggedNodeSource
	var nodeConfig domain.NodeConfig
	var listen func() (net.PacketConn, error)
	if transport == "tailscaled" {
		api := domain.NewLocalAPI(c.TailscaledSocket)
		var err error
		nodeConfig, err = api.NodeConfig(ctx)
		if err != nil {
			log.Fatalf("-mode=tailscaled requires a usable tailscaled LocalAPI: %v", err)
		}
		ip, err := api.TailscaleIP(ctx)
		if err != nil {
			log.Fatal(err)
		}
		identity = api
		nodes = api
		listen = func() (net.PacketConn, error) { return net.ListenPacket("udp", dnsListenAddress(c.Listen, ip)) }
	} else {
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
		id := domain.TSNetIdentity{Client: client}
		identity = id
		nodes = id
		nodeConfig, err = id.NodeConfig(ctx)
		if err != nil {
			log.Fatal("missing or invalid domain-gateway NodeAttr: ", err)
		}
		ip4, _ := server.TailscaleIPs()
		listen = func() (net.PacketConn, error) { return server.ListenPacket("udp", dnsListenAddress(c.Listen, ip4)) }
	}
	gs, upstream, err := dnsGatewayTopology(ctx, nodeConfig, nodes)
	if err != nil {
		discoveryErr := err
		// Discovery is per-new-allocation operational state. DNS still starts so
		// an authorized protected request can receive SERVFAIL instead of an
		// upstream answer while status recovers.
		gs, upstream, err = gateways(nodeConfig)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("domain-gateway: active route discovery unavailable at startup: %v", discoveryErr)
	}
	alloc := domain.NewAllocator()
	store, closeStore, err := allocationStore(ctx, c)
	if err != nil {
		log.Fatal(err)
	}
	defer closeStore()
	// SQL rows are intentionally loaded lazily: the store checks their lease on
	// every cache miss, so startup cannot resurrect an expired mapping.
	lease := time.Hour
	if c.AllocationLease != "" {
		lease, _ = time.ParseDuration(c.AllocationLease)
	}
	s := &domain.Service{Identity: identity, Gateways: gs, Allocations: alloc, AllocationStore: store, Lease: lease, GatewayTopology: func(ctx context.Context) (map[string]domain.Gateway, error) {
		gs, _, err := dnsGatewayTopology(ctx, nodeConfig, nodes)
		return gs, err
	}}
	conn, err := listen()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	upstreamAddr := mustAddr(upstream)
	serveDNS(ctx, conn, s, nodes, upstreamAddr)
}

func dnsListenAddress(configured string, ip netip.Addr) string {
	if configured != "" {
		return configured
	}
	return net.JoinHostPort(ip.String(), "53")
}

func allocationStore(ctx context.Context, c config) (domain.AllocationStore, func(), error) {
	if c.Database != "" {
		store, err := domain.OpenAllocationStore(ctx, c.Database)
		if err != nil {
			return nil, func() {}, err
		}
		return store, func() { _ = store.Close() }, nil
	}
	return nil, func() {}, nil
}

func serveDNS(ctx context.Context, conn net.PacketConn, s *domain.Service, nodes domain.TaggedNodeSource, upstreamAddr *net.UDPAddr) {
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
					if mapping, found := s.PTRMapping(ctx, synthetic); found {
						conn.WriteTo(ptrAnswer(b, end, mapping.Domain), src)
					} else {
						conn.WriteTo(answer(b, end, netip.Addr{}), src)
					}
					return
				}
			}
			if ips, tagged := domain.ResolveTags(ctx, name, nodes); tagged {
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
			ip, outcome := s.DNSAnswer(ctx, srcAddr, name)
			if outcome == domain.DNSSynthesized {
				if typ == 1 {
					conn.WriteTo(answer(b, end, ip), src)
				} else if typ == 28 {
					conn.WriteTo(answer(b, end, netip.Addr{}), src)
				}
				return
			}
			if outcome == domain.DNSUnavailable {
				conn.WriteTo(serverFailure(b, end), src)
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
