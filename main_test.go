package main

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

type mockForwarder struct {
	calls []forwardCall
}

type forwardCall struct {
	ifaceName string
	data      []byte
}

func (m *mockForwarder) forward(ifaceName string, data []byte) {
	m.calls = append(m.calls, forwardCall{ifaceName: ifaceName, data: data})
}

func TestHandlePacket(t *testing.T) {
	cfg := &Config{
		Interfaces: []InterfaceConfig{
			{Name: "vlan.10", Group: "users"},
			{Name: "vlan.19", Group: "gl_iot"},
			{Name: "vlan.20", Group: "gl_tv"},
		},
		Rules: []Rule{
			{
				From:  "users",
				To:    []string{"gl_iot", "gl_tv"},
				Types: []string{"query"},
				Filter: Filter{
					AllowedServices: []string{"_airplay._tcp"},
				},
			},
			{
				From:  "gl_iot",
				To:    []string{"users"},
				Types: []string{"response"},
				Filter: Filter{
					AllowedIPs: []string{"192.168.19.10"},
				},
			},
			{
				From:  "gl_tv",
				To:    []string{"users"},
				Types: []string{"response"},
			},
		},
	}

	r := NewReflector(cfg)
	mock := &mockForwarder{}
	r.forwarder = mock.forward

	t.Run("Query from user to IoT allowed service", func(t *testing.T) {
		mock.calls = nil
		msg := &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: false},
			Question: []dns.Question{
				{Name: "_airplay._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET | 0x8000}, // With QU bit
			},
		}
		data, _ := msg.Pack()
		srcIP := net.ParseIP("192.168.10.50")

		r.handlePacket("vlan.10", data, msg, srcIP)

		// Should reflect to vlan.19 and vlan.20
		if len(mock.calls) != 2 {
			t.Errorf("Expected 2 forwarding calls, got %d", len(mock.calls))
		}

		// Check if QU bit was stripped in the forwarded data
		forwardedMsg := new(dns.Msg)
		forwardedMsg.Unpack(mock.calls[0].data)
		if forwardedMsg.Question[0].Qclass&0x8000 != 0 {
			t.Error("QU bit was not stripped from forwarded query")
		}
	})

	t.Run("Query from user blocked service", func(t *testing.T) {
		mock.calls = nil
		msg := &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: false},
			Question: []dns.Question{{Name: "_ssh._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}},
		}
		data, _ := msg.Pack()
		srcIP := net.ParseIP("192.168.10.50")

		r.handlePacket("vlan.10", data, msg, srcIP)

		if len(mock.calls) != 0 {
			t.Errorf("Expected 0 forwarding calls for blocked service, got %d", len(mock.calls))
		}
	})

	t.Run("Hostname resolution allowed", func(t *testing.T) {
		mock.calls = nil
		msg := &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: false},
			Question: []dns.Question{{Name: "myhost.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		}
		data, _ := msg.Pack()
		srcIP := net.ParseIP("192.168.10.50")

		r.handlePacket("vlan.10", data, msg, srcIP)

		if len(mock.calls) != 2 {
			t.Errorf("Expected 2 forwarding calls for hostname resolution, got %d", len(mock.calls))
		}
	})

	t.Run("Response from IoT allowed IP", func(t *testing.T) {
		// First, send a query from vlan.10 to open the window
		qMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: false}}
		r.handlePacket("vlan.10", nil, qMsg, net.ParseIP("192.168.10.50"))

		mock.calls = nil
		respMsg := &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true},
			Answer: []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: "_airplay._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET}}},
		}
		data, _ := respMsg.Pack()
		srcIP := net.ParseIP("192.168.19.10")

		r.handlePacket("vlan.19", data, respMsg, srcIP)

		if len(mock.calls) != 1 {
			t.Errorf("Expected 1 forwarding call, got %d", len(mock.calls))
		}
		if mock.calls[0].ifaceName != "vlan.10" {
			t.Errorf("Expected reflection to vlan.10, got %s", mock.calls[0].ifaceName)
		}
	})

	t.Run("Response from IoT blocked IP", func(t *testing.T) {
		mock.calls = nil
		respMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
		data, _ := respMsg.Pack()
		srcIP := net.ParseIP("192.168.19.99")

		r.handlePacket("vlan.19", data, respMsg, srcIP)

		if len(mock.calls) != 0 {
			t.Errorf("Expected 0 forwarding calls for blocked IP, got %d", len(mock.calls))
		}
	})

	t.Run("Response blocked by stateful window", func(t *testing.T) {
		mock.calls = nil
		// Ensure vlan.20 has no recent queries
		r.mu.Lock()
		delete(r.recentQueries, "vlan.10")
		r.mu.Unlock()

		respMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
		data, _ := respMsg.Pack()
		srcIP := net.ParseIP("192.168.20.10")

		r.handlePacket("vlan.20", data, respMsg, srcIP)

		if len(mock.calls) != 0 {
			t.Errorf("Expected 0 forwarding calls due to closed window, got %d", len(mock.calls))
		}
	})

	t.Run("Rule type mismatch (Response from User)", func(t *testing.T) {
		mock.calls = nil
		respMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
		data, _ := respMsg.Pack()
		srcIP := net.ParseIP("192.168.10.50")

		r.handlePacket("vlan.10", data, respMsg, srcIP)

		if len(mock.calls) != 0 {
			t.Errorf("Expected 0 forwarding calls for user response, got %d", len(mock.calls))
		}
	})
	
	t.Run("Rule From mismatch", func(t *testing.T) {
		mock.calls = nil
		msg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: false}}
		data, _ := msg.Pack()
		// Interface not in any rule's 'From'
		r.handlePacket("unknown_iface", data, msg, net.ParseIP("1.1.1.1"))
		
		if len(mock.calls) != 0 {
			t.Errorf("Expected 0 calls for unknown interface")
		}
	})
}

func TestMsgSummary(t *testing.T) {
	t.Run("Summary for query", func(t *testing.T) {
		msg := &dns.Msg{
			Question: []dns.Question{
				{Name: "q1.", Qtype: dns.TypeA},
				{Name: "q2.", Qtype: dns.TypePTR},
			},
		}
		s := getMsgSummary(msg)
		expected := "Questions: [q1. (A), q2. (PTR)]"
		if s != expected {
			t.Errorf("Expected %s, got %s", expected, s)
		}
	})

	t.Run("Summary for long query", func(t *testing.T) {
		msg := &dns.Msg{
			Question: []dns.Question{
				{Name: "q1.", Qtype: dns.TypeA},
				{Name: "q2.", Qtype: dns.TypeA},
				{Name: "q3.", Qtype: dns.TypeA},
				{Name: "q4.", Qtype: dns.TypeA},
			},
		}
		s := getMsgSummary(msg)
		if !strings.Contains(s, "+1 more") {
			t.Errorf("Expected truncation, got %s", s)
		}
	})

	t.Run("Summary for response", func(t *testing.T) {
		msg := &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true},
			Answer: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: "a1.", Rrtype: dns.TypeA}},
			},
		}
		s := getMsgSummary(msg)
		if !strings.Contains(s, "Records: [a1. (A)]") {
			t.Errorf("Expected Records summary, got %s", s)
		}
	})
	
	t.Run("Summary for empty response", func(t *testing.T) {
		msg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
		s := getMsgSummary(msg)
		if s != "No records" {
			t.Errorf("Expected 'No records', got %s", s)
		}
	})
}
