package dnsudp

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func TestRespondOutcomes(t *testing.T) {
	server := Server{Decide: func(_ context.Context, _ netip.Addr, question Question) Decision {
		switch question.Name {
		case "synth.example":
			return Decision{Outcome: Address, Address: netip.MustParseAddr("10.254.0.1")}
		case "ptr.example":
			return Decision{Outcome: PTR, PTRName: "app.example.com"}
		case "tag.example":
			return Decision{Outcome: Address, Address: netip.MustParseAddr("100.64.0.1")}
		case "ordinary.example":
			return Decision{Outcome: Passthrough}
		default:
			return Decision{Outcome: Unavailable}
		}
	}}
	source := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53}
	for _, test := range []struct {
		name       string
		question   string
		typeCode   uint16
		answers    uint16
		serverFail bool
		forward    bool
		contains   string
	}{
		{name: "synthesized A", question: "synth.example", typeCode: TypeA, answers: 1},
		{name: "synthesized AAAA is NODATA", question: "synth.example", typeCode: TypeAAAA, answers: 0},
		{name: "PTR", question: "ptr.example", typeCode: TypePTR, answers: 1, contains: "app"},
		{name: "tag", question: "tag.example", typeCode: TypeA, answers: 1},
		{name: "passthrough", question: "ordinary.example", typeCode: TypeA, forward: true},
		{name: "unavailable", question: "down.example", typeCode: TypeA, serverFail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, forward := server.Respond(context.Background(), query(test.question, test.typeCode), source)
			if forward != test.forward {
				t.Fatalf("forward = %v, want %v", forward, test.forward)
			}
			if test.forward {
				if response != nil {
					t.Fatalf("passthrough response = %x, want nil", response)
				}
				return
			}
			if got := binary.BigEndian.Uint16(response[6:8]); got != test.answers {
				t.Fatalf("answers = %d, want %d", got, test.answers)
			}
			if got := binary.BigEndian.Uint16(response[2:4])&0xf == 2; got != test.serverFail {
				t.Fatalf("SERVFAIL = %v, want %v", got, test.serverFail)
			}
			if test.contains != "" && !contains(response, []byte(test.contains)) {
				t.Fatalf("response %x does not contain %q", response, test.contains)
			}
		})
	}
}

func TestReverseIPv4(t *testing.T) {
	got, ok := ReverseIPv4("1.0.254.10.in-addr.arpa")
	if !ok || got != netip.MustParseAddr("10.254.0.1") {
		t.Fatalf("ReverseIPv4 = %v, %v", got, ok)
	}
}

func query(name string, typeCode uint16) []byte {
	request := make([]byte, 12)
	binary.BigEndian.PutUint16(request[:2], 123)
	binary.BigEndian.PutUint16(request[4:6], 1)
	for _, label := range split(name) {
		request = append(request, byte(len(label)))
		request = append(request, label...)
	}
	request = append(request, 0, 0, byte(typeCode), 0, 1)
	return request
}

func split(name string) [][]byte {
	var labels [][]byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, []byte(name[start:i]))
			start = i + 1
		}
	}
	return labels
}

func contains(haystack, needle []byte) bool {
	for i := range haystack {
		if len(haystack)-i >= len(needle) && string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
