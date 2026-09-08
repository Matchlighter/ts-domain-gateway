// Package dnsudp owns UDP DNS wire handling around a domain decision.
package dnsudp

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	TypeA    = 1
	TypePTR  = 12
	TypeAAAA = 28
)

// Question is the DNS question passed to a domain decision.
type Question struct {
	Name string
	Type uint16
}

// Outcome describes how a domain decision should be represented on the wire.
type Outcome uint8

const (
	NoResponse Outcome = iota
	Address
	PTR
	Passthrough
	Unavailable
)

// Decision is the protocol-neutral result of evaluating one DNS question.
type Decision struct {
	Outcome Outcome
	Address netip.Addr
	PTRName string
}

// Decide evaluates the parsed DNS question. source is invalid when its UDP
// address cannot be represented as a netip.Addr.
type Decide func(context.Context, netip.Addr, Question) Decision

// Server serves DNS over a PacketConn. It owns wire parsing, responses, and
// upstream forwarding; Decide owns domain policy and allocation state.
type Server struct {
	Decide   Decide
	Upstream *net.UDPAddr
}

// Serve reads requests until conn returns an error. At most 256 request
// handlers are active, matching the previous DNS authority bound.
func (s Server) Serve(ctx context.Context, conn net.PacketConn) {
	pool := sync.Pool{New: func() any { return make([]byte, 65535) }}
	jobs := make(chan struct{}, 256)
	for {
		buf := pool.Get().([]byte)
		n, source, err := conn.ReadFrom(buf)
		if err != nil {
			pool.Put(buf)
			return
		}
		jobs <- struct{}{}
		go func(buffer, request []byte, source net.Addr) {
			defer func() { <-jobs; pool.Put(buffer) }()
			response, forward := s.Respond(ctx, request, source)
			if response != nil {
				_, _ = conn.WriteTo(response, source)
			} else if forward {
				s.forward(conn, request, source)
			}
		}(buf, buf[:n], source)
	}
}

// Respond parses one request and applies the domain decision. A nil response
// with forward=true tells a transport to preserve ordinary DNS via Upstream.
func (s Server) Respond(ctx context.Context, request []byte, source net.Addr) ([]byte, bool) {
	question, end, ok := parseQuestion(request)
	if !ok || s.Decide == nil {
		return nil, false
	}
	decision := s.Decide(ctx, sourceIP(source), question)
	switch decision.Outcome {
	case Address:
		if question.Type == TypeA {
			return addressAnswer(request, end, decision.Address), false
		}
		if question.Type == TypeAAAA {
			return addressAnswer(request, end, netip.Addr{}), false
		}
	case PTR:
		if decision.PTRName != "" {
			return ptrAnswer(request, end, decision.PTRName), false
		}
		return addressAnswer(request, end, netip.Addr{}), false
	case Passthrough:
		return nil, true
	case Unavailable:
		return serverFailure(request, end), false
	}
	return nil, false
}

func (s Server) forward(listener net.PacketConn, request []byte, client net.Addr) {
	if s.Upstream == nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, s.Upstream)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return
	}
	buf := make([]byte, 65535)
	if n, err := conn.Read(buf); err == nil {
		_, _ = listener.WriteTo(buf[:n], client)
	}
}

func parseQuestion(request []byte) (Question, int, bool) {
	if len(request) < 17 || binary.BigEndian.Uint16(request[4:6]) != 1 {
		return Question{}, 0, false
	}
	p := 12
	labels := make([]string, 0, 4)
	for {
		if p >= len(request) {
			return Question{}, 0, false
		}
		n := int(request[p])
		p++
		if n == 0 {
			break
		}
		if n > 63 || p+n > len(request) {
			return Question{}, 0, false
		}
		labels = append(labels, string(request[p:p+n]))
		p += n
	}
	if p+4 > len(request) {
		return Question{}, 0, false
	}
	return Question{Name: strings.Join(labels, "."), Type: binary.BigEndian.Uint16(request[p : p+2])}, p + 4, true
}

func sourceIP(source net.Addr) netip.Addr {
	if udp, ok := source.(*net.UDPAddr); ok {
		addr, _ := netip.AddrFromSlice(udp.IP)
		return addr
	}
	addrPort, err := netip.ParseAddrPort(source.String())
	if err != nil {
		return netip.Addr{}
	}
	return addrPort.Addr()
}

func addressAnswer(request []byte, end int, ip netip.Addr) []byte {
	response := make([]byte, end+16)
	copy(response[:end], request[:end])
	binary.BigEndian.PutUint16(response[2:4], 0x8000|(binary.BigEndian.Uint16(request[2:4])&0x0100))
	if ip.IsValid() {
		binary.BigEndian.PutUint16(response[6:8], 1)
		p := end
		response[p], response[p+1] = 0xc0, 0x0c
		binary.BigEndian.PutUint16(response[p+2:p+4], TypeA)
		binary.BigEndian.PutUint16(response[p+4:p+6], 1)
		binary.BigEndian.PutUint32(response[p+6:p+10], 600)
		binary.BigEndian.PutUint16(response[p+10:p+12], 4)
		copy(response[p+12:p+16], ip.AsSlice())
	} else {
		response = response[:end]
	}
	return response
}

func serverFailure(request []byte, end int) []byte {
	response := addressAnswer(request, end, netip.Addr{})
	binary.BigEndian.PutUint16(response[2:4], binary.BigEndian.Uint16(response[2:4])|2)
	return response
}

func ptrAnswer(request []byte, end int, name string) []byte {
	rdata := encodeName(name)
	response := make([]byte, end+12+len(rdata))
	copy(response[:end], request[:end])
	binary.BigEndian.PutUint16(response[2:4], 0x8000|(binary.BigEndian.Uint16(request[2:4])&0x0100))
	binary.BigEndian.PutUint16(response[6:8], 1)
	p := end
	response[p], response[p+1] = 0xc0, 0x0c
	binary.BigEndian.PutUint16(response[p+2:p+4], TypePTR)
	binary.BigEndian.PutUint16(response[p+4:p+6], 1)
	binary.BigEndian.PutUint32(response[p+6:p+10], 600)
	binary.BigEndian.PutUint16(response[p+10:p+12], uint16(len(rdata)))
	copy(response[p+12:], rdata)
	return response
}

func encodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	response := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		response = append(response, byte(len(label)))
		response = append(response, label...)
	}
	return append(response, 0)
}

// ReverseIPv4 returns the address named by an in-addr.arpa question.
func ReverseIPv4(name string) (netip.Addr, bool) {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	if len(parts) != 6 || parts[4] != "in-addr" || parts[5] != "arpa" {
		return netip.Addr{}, false
	}
	var octets [4]byte
	for i := range octets {
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
