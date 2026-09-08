package domain

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ServeTCP accepts Linux REDIRECT/DNAT traffic and reauthorizes every connection.
func (s *Service) ServeTCP(ctx context.Context, listen string) error {
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.proxy(ctx, c)
	}
}
func originalDestination(c *net.TCPConn) (netip.Addr, uint16, bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.Addr{}, 0, false
	}
	var ip netip.Addr
	var port uint16
	var result error
	raw.Control(func(fd uintptr) {
		b := make([]byte, 16)
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(syscall.SOL_IP), 80, uintptr(unsafePointer(&b[0])), uintptr(16), 0)
		if errno != 0 {
			result = errno
			return
		}
		ip = netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]})
		port = binary.BigEndian.Uint16(b[2:4])
	})
	return ip, port, result == nil
}

// unsafePointer is isolated here for the Linux socket ABI.
func unsafePointer(p *byte) unsafe.Pointer { return unsafe.Pointer(p) }
func (s *Service) proxy(ctx context.Context, client net.Conn) {
	defer client.Close()
	tcp, ok := client.(*net.TCPConn)
	if !ok {
		return
	}
	src, _ := netip.ParseAddrPort(client.RemoteAddr().String())
	dst, port, ok := originalDestination(tcp)
	if !ok {
		return
	}
	s.ProxyTCP(ctx, client, src, netip.AddrPortFrom(dst, port))
}

// ProxyTCP is shared by the kernel and tsnet dataplanes. dst is always the
// client-visible synthetic destination, never an internal listener address.
func (s *Service) ProxyTCP(ctx context.Context, client net.Conn, src, dst netip.AddrPort) {
	lookupPTR := s.PTRLookup
	if lookupPTR == nil {
		lookupPTR = func(ctx context.Context, ip netip.Addr) ([]string, error) {
			return net.DefaultResolver.LookupAddr(ctx, ip.String())
		}
	}
	names, err := lookupPTR(ctx, dst.Addr())
	if err != nil || len(names) != 1 {
		return
	}
	g, ok := s.FlowDomain(ctx, src.Addr(), dst.Addr(), names[0], "tcp", dst.Port())
	if !ok {
		return
	}
	dial := s.ResolverDial
	if g.SystemResolver || dial == nil {
		dialer := net.Dialer{}
		dial = dialer.DialContext
	}
	resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dial(ctx, "udp", g.Resolver)
	}}
	ips, err := resolver.LookupNetIP(ctx, "ip", strings.TrimSuffix(names[0], "."))
	if err != nil || len(ips) == 0 {
		return
	}
	backend, err := net.DialTimeout("tcp", net.JoinHostPort(ips[0].String(), fmt.Sprint(dst.Port())), 5*time.Second)
	if err != nil {
		return
	}
	defer backend.Close()
	go io.Copy(backend, client)
	io.Copy(client, backend)
}
