// domain-gateway is a low-allocation UDP synthetic-DNS server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/matchlighter/headscale-domain-proxies/internal/dnsudp"
	"github.com/matchlighter/headscale-domain-proxies/internal/domain"
	"github.com/tailscale/hujson"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

type config struct {
	Listen                    string        `json:"dns_listen"`
	GatewayListen             string        `json:"gateway_listen"`
	TailscaledSocket          string        `json:"tailscaled_socket"`
	Database                  string        `json:"database"`
	AllocationLease           string        `json:"allocation_lease"`
	UpstreamResolver          string        `json:"upstream_resolver"`
	UpstreamResolverInterface string        `json:"upstream_resolver_interface"`
	Egress                    *egressConfig `json:"egress"`
	TSNet                     tsnetConfig   `json:"tsnet"`
}

// egressConfig is the local startup authority for one egress instance. Its
// ranges must be advertised by egress and exactly match the policy grant.
type egressConfig struct {
	Ranges               []string `json:"ranges"`
	PTRResolver          string   `json:"ptr_resolver"`
	PTRResolverInterface string   `json:"ptr_resolver_interface"`
}

// localEgressGatewayKey names the single local gateway entry used for egress
// flow enforcement and route advertisement.
const localEgressGatewayKey = "local-egress"

type tsnetConfig struct {
	Dir        string   `json:"dir"`
	Hostname   string   `json:"hostname"`
	AuthKey    string   `json:"auth_key"`
	ControlURL string   `json:"control_url"`
	Tags       []string `json:"tags"`
}

type command struct {
	Role      string
	Transport string
	Config    config
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
	data, err = hujson.Standardize(data)
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
	var legacy struct {
		Egress map[string]json.RawMessage `json:"egress"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return command{}, err
	}
	if _, found := legacy.Egress["tag"]; found {
		return command{}, fmt.Errorf("egress.tag is no longer supported")
	}
	for old, replacement := range map[string]string{"dns_resolver": "ptr_resolver", "upstream_dns_interface": "upstream_resolver_interface or ptr_resolver_interface"} {
		if _, found := legacy.Egress[old]; found {
			return command{}, fmt.Errorf("egress.%s is no longer supported; use %s", old, replacement)
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
	fs.StringVar(&c.UpstreamResolver, "upstream-resolver", c.UpstreamResolver, "egress fallback DNS resolver (host[:port] or system)")
	fs.StringVar(&c.TSNet.Dir, "tsnet-dir", c.TSNet.Dir, "tsnet state directory")
	fs.StringVar(&c.TSNet.Hostname, "tsnet-hostname", c.TSNet.Hostname, "tsnet hostname")
	fs.StringVar(&c.TSNet.AuthKey, "tsnet-auth-key", c.TSNet.AuthKey, "tsnet auth key")
	fs.StringVar(&c.TSNet.ControlURL, "tsnet-control-url", c.TSNet.ControlURL, "tsnet coordination server URL")
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
		if _, err := egressUpstreamResolverInterface(c); err != nil {
			return command{}, err
		}
		if _, err := egressPTRResolverInterface(c); err != nil {
			return command{}, err
		}
		if _, _, err := egressPTRResolver(c); err != nil {
			return command{}, err
		}
		if _, err := configuredResolver(c.UpstreamResolver); err != nil {
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

// configuredResolver validates the local egress fallback. Capability
// resolvers are validated separately because they must never select system.
func configuredResolver(resolver string) (string, error) {
	if resolver == "" || domain.IsSystemResolver(resolver) {
		return resolver, nil
	}
	host, port, err := net.SplitHostPort(resolver)
	if err != nil {
		if !strings.Contains(resolver, ":") || net.ParseIP(resolver) != nil {
			return net.JoinHostPort(resolver, "53"), nil
		}
		return "", fmt.Errorf("invalid upstream_resolver %q (want host[:port] or system)", resolver)
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("invalid upstream_resolver %q (want host[:port] or system)", resolver)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return "", fmt.Errorf("invalid upstream_resolver %q (want host[:port] or system)", resolver)
	}
	return net.JoinHostPort(host, port), nil
}

// egressBackendResolver applies the non-capability part of egress resolver
// precedence. An explicitly visible gateway NodeAttr wins over the local
// fallback; "system" always means the host's non-Tailscale resolver.
func egressBackendResolver(c config, nodeConfig domain.NodeConfig) (string, bool, error) {
	resolver := c.UpstreamResolver
	if nodeConfig.HasUpstreamDNS {
		resolver = nodeConfig.UpstreamDNS
	}
	if resolver == "" {
		resolver = "system"
	}
	resolver, err := configuredResolver(resolver)
	if err != nil {
		return "", false, err
	}
	if domain.IsSystemResolver(resolver) {
		resolver, err := systemUpstream()
		return resolver, true, err
	}
	return resolver, false, nil
}

func egressGateways(c config, resolver string, systemResolver ...bool) (map[string]domain.Gateway, error) {
	if c.Egress == nil || len(c.Egress.Ranges) == 0 {
		return nil, fmt.Errorf("egress requires at least one egress.ranges entry")
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
	return map[string]domain.Gateway{localEgressGatewayKey: {Prefixes: prefixes, Resolver: resolver, SystemResolver: len(systemResolver) != 0 && systemResolver[0]}}, nil
}

// egressUpstreamDNSInterface selects how tsnet reaches an appcap resolver.
// "auto" follows an active peer subnet route when it contains the resolver IP
// and otherwise uses the host network. The forced values are useful when both
// paths exist or an operator needs a deterministic path.
func egressResolverInterface(value string) (string, error) {
	if value == "" {
		value = "auto"
	}
	switch value {
	case "auto", "tailnet", "host":
		return value, nil
	default:
		return "", fmt.Errorf("invalid egress upstream_dns_interface %q (want auto, tailnet, or host)", value)
	}
}

func egressUpstreamResolverInterface(c config) (string, error) {
	return egressResolverInterface(c.UpstreamResolverInterface)
}

func egressPTRResolverInterface(c config) (string, error) {
	if c.Egress == nil {
		return egressResolverInterface("")
	}
	return egressResolverInterface(c.Egress.PTRResolverInterface)
}

func prefixesContainResolver(prefixes []netip.Prefix, resolver string) bool {
	host, _, err := net.SplitHostPort(resolver)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func peerRoutesContainResolver(status *ipnstate.Status, resolver string) bool {
	if status == nil {
		return false
	}
	for _, peer := range status.Peer {
		if peer != nil && peer.PrimaryRoutes != nil && prefixesContainResolver(peer.PrimaryRoutes.AsSlice(), resolver) {
			return true
		}
	}
	return false
}

// tailnetResolver identifies a resolver from the control-plane's current
// Tailnet membership instead of assuming Tailscale's default address ranges.
// This supports Headscale deployments with custom IP prefixes.
func tailnetResolver(status *ipnstate.Status, resolver string) bool {
	if status == nil {
		return false
	}
	host, _, err := net.SplitHostPort(resolver)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if status.Self != nil {
		for _, candidate := range status.Self.TailscaleIPs {
			if candidate == address {
				return true
			}
		}
	}
	for _, candidate := range status.TailscaleIPs {
		if candidate == address {
			return true
		}
	}
	for _, peer := range status.Peer {
		if peer == nil {
			continue
		}
		for _, candidate := range peer.TailscaleIPs {
			if candidate == address {
				return true
			}
		}
	}
	return false
}

// autoUsesTailnet recognizes control-plane Tailnet node addresses and
// peer-advertised subnets. Other resolvers deliberately remain host-routable.
func autoUsesTailnet(status *ipnstate.Status, resolver string) bool {
	return tailnetResolver(status, resolver) || peerRoutesContainResolver(status, resolver)
}

// egressPTRResolver returns the egress-local DNS authority used to recover a
// synthetic address's domain. Backend resolution is selected from the appcap.
func egressPTRResolver(c config) (string, bool, error) {
	if c.Egress == nil || c.Egress.PTRResolver == "" {
		return "", false, nil
	}
	resolver := c.Egress.PTRResolver
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}
	host, _, err := net.SplitHostPort(resolver)
	if err != nil || net.ParseIP(host) == nil {
		return "", false, fmt.Errorf("invalid egress PTR resolver IP %q", c.Egress.PTRResolver)
	}
	_, port, _ := net.SplitHostPort(resolver)
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return "", false, fmt.Errorf("invalid egress PTR resolver IP %q", c.Egress.PTRResolver)
	}
	return resolver, true, nil
}

// lookupPTR queries the synthetic-address authority using the configured
// egress DNS path. Auto routing recognizes control-plane Tailnet members and
// peer-advertised subnet routes.
func lookupPTR(ctx context.Context, ip netip.Addr, resolvers []string, dial domain.ResolverDial) ([]string, error) {
	var last error
	for _, dnsAddr := range resolvers {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, network, dnsAddr)
		}}
		names, err := resolver.LookupAddr(ctx, ip.String())
		if err == nil && len(names) != 0 {
			return names, nil
		}
		last = err
	}
	return nil, last
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

func dnsGateways(nodeConfig domain.NodeConfig) (map[string]domain.Gateway, string, error) {
	upstream := nodeConfig.UpstreamDNS
	var err error
	if domain.IsSystemResolver(upstream) {
		upstream, err = systemUpstream()
		if err != nil {
			return nil, "", err
		}
	}
	return map[string]domain.Gateway{}, upstream, nil
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
	return &tsnet.Server{Dir: c.TSNet.Dir, Hostname: c.TSNet.Hostname, AuthKey: authKey, ControlURL: c.TSNet.ControlURL, AdvertiseTags: advertiseTags}, nil
}

func runEgress(ctx context.Context, c config, transport string) {
	if transport == "tailscaled" {
		tailnet, err := openTailnetTransport(ctx, c, transport, false)
		if err != nil {
			log.Fatal(err)
		}
		if tailnet.NodeConfigErr != nil {
			log.Printf("domain-gateway: gateway NodeAttr unavailable: %v", tailnet.NodeConfigErr)
		}
		resolver, systemResolver, err := egressBackendResolver(c, tailnet.NodeConfig)
		if err != nil {
			log.Fatal(err)
		}
		gs, err := egressGateways(c, resolver, systemResolver)
		if err != nil {
			log.Fatal(err)
		}
		s := &domain.Service{Identity: tailnet.Identity, Gateways: gs, SystemResolver: func(context.Context) (string, error) { return systemUpstream() }}
		if ptrResolver, configured, err := egressPTRResolver(c); err != nil {
			log.Fatal(err)
		} else if configured {
			dialer := net.Dialer{}
			s.PTRLookup = func(ctx context.Context, ip netip.Addr) ([]string, error) {
				resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, ptrResolver)
				}}
				return resolver.LookupAddr(ctx, ip.String())
			}
		}
		if err := s.ServeTCP(ctx, c.GatewayListen); err != nil {
			log.Fatal(err)
		}
		return
	}
	// The selected tsnet transport never falls back to the host daemon.
	tailnet, err := openTailnetTransport(ctx, c, transport, false)
	if err != nil {
		log.Fatal(err)
	}
	server, client := tailnet.Server, tailnet.Client
	if _, err := client.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{RouteAll: true}, RouteAllSet: true}); err != nil {
		log.Fatalf("userspace gateway cannot accept tailnet subnet routes: %v", err)
	}
	upstreamResolverInterface, err := egressUpstreamResolverInterface(c)
	if err != nil {
		log.Fatal(err)
	}
	ptrResolverInterface, err := egressPTRResolverInterface(c)
	if err != nil {
		log.Fatal(err)
	}
	hostDialer := net.Dialer{}
	resolverDialFor := func(resolverInterface string) domain.ResolverDial {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			switch resolverInterface {
			case "tailnet":
				return server.Dial(ctx, network, address)
			case "host":
				return hostDialer.DialContext(ctx, network, address)
			}
			status, err := client.Status(ctx)
			if err == nil && autoUsesTailnet(status, address) {
				return server.Dial(ctx, network, address)
			}
			return hostDialer.DialContext(ctx, network, address)
		}
	}
	resolverDial := resolverDialFor(upstreamResolverInterface)
	ptrResolverDial := resolverDialFor(ptrResolverInterface)
	if tailnet.NodeConfigErr != nil {
		log.Printf("domain-gateway: gateway NodeAttr unavailable: %v", tailnet.NodeConfigErr)
	}
	backendResolver, systemResolver, err := egressBackendResolver(c, tailnet.NodeConfig)
	if err != nil {
		log.Fatal(err)
	}
	ptrResolver, configured, err := egressPTRResolver(c)
	if err != nil {
		log.Fatal(err)
	}
	var dnsResolvers []string
	if configured {
		dnsResolvers = []string{ptrResolver}
	} else {
		dnsConfig, err := client.DNSConfig(ctx)
		if err != nil || len(dnsConfig.Resolvers) == 0 {
			log.Fatal("userspace gateway requires egress.ptr_resolver or an advertised Tailscale DNS resolver")
		}
		dnsResolvers = make([]string, 0, len(dnsConfig.Resolvers))
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
			log.Fatal("userspace gateway requires egress.ptr_resolver or an advertised Tailscale DNS resolver")
		}
	}
	gs, err := egressGateways(c, backendResolver, systemResolver)
	if err != nil {
		log.Fatal(err)
	}
	s := &domain.Service{Identity: tailnet.Identity, Gateways: gs, ResolverDial: resolverDial, SystemResolver: func(context.Context) (string, error) { return systemUpstream() }, PTRLookup: func(ctx context.Context, ip netip.Addr) ([]string, error) {
		return lookupPTR(ctx, ip, dnsResolvers, ptrResolverDial)
	}}
	if err := s.ServeTSNetGateway(ctx, server); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
}

func runDNS(ctx context.Context, c config, transport string) {
	tailnet, err := openTailnetTransport(ctx, c, transport, true)
	if err != nil {
		log.Fatal(err)
	}
	if tailnet.NodeConfigErr != nil {
		log.Fatal("missing or invalid domain-gateway NodeAttr: ", tailnet.NodeConfigErr)
	}
	gs, upstream, err := dnsGateways(tailnet.NodeConfig)
	if err != nil {
		log.Fatal(err)
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
	s := &domain.Service{Identity: tailnet.Identity, Gateways: gs, Allocations: alloc, Lifecycle: &domain.AllocationLifecycle{Allocator: alloc, Store: store, Lease: lease}}
	conn, err := tailnet.listenUDP(dnsListenAddress(c.Listen, tailnet.IP))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	upstreamAddr := mustAddr(upstream)
	(dnsudp.Server{
		Upstream: upstreamAddr,
		Decide: func(ctx context.Context, source netip.Addr, question dnsudp.Question) dnsudp.Decision {
			if question.Type == dnsudp.TypePTR {
				if synthetic, reverse := dnsudp.ReverseIPv4(question.Name); reverse {
					if mapping, found := s.PTRMapping(ctx, synthetic); found {
						return dnsudp.Decision{Outcome: dnsudp.PTR, PTRName: mapping.Domain}
					}
					return dnsudp.Decision{Outcome: dnsudp.PTR}
				}
			}
			if ips, tagged := domain.ResolveTags(ctx, question.Name, tailnet.Nodes); tagged {
				if question.Type == dnsudp.TypeA && len(ips) > 0 {
					if ip, err := netip.ParseAddr(ips[0]); err == nil {
						return dnsudp.Decision{Outcome: dnsudp.Address, Address: ip}
					}
				}
				return dnsudp.Decision{Outcome: dnsudp.NoResponse}
			}
			if !source.IsValid() {
				return dnsudp.Decision{Outcome: dnsudp.NoResponse}
			}
			ip, outcome := s.DNSAnswer(ctx, source, question.Name)
			switch outcome {
			case domain.DNSSynthesized:
				return dnsudp.Decision{Outcome: dnsudp.Address, Address: ip}
			case domain.DNSUnavailable:
				return dnsudp.Decision{Outcome: dnsudp.Unavailable}
			default:
				return dnsudp.Decision{Outcome: dnsudp.Passthrough}
			}
		},
	}).Serve(ctx, conn)
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
func mustAddr(s string) *net.UDPAddr {
	a, e := net.ResolveUDPAddr("udp", s)
	if e != nil {
		log.Fatal(e)
	}
	return a
}
