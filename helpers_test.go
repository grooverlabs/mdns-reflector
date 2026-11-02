package main

import (
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
)

type forwardCall struct {
	iface string
	data  []byte
}

// newTestReflector builds a reflector whose interfaces are synthetic: nets maps
// interface name to the reflector's address and prefix on it, e.g.
// "192.168.10.1/24". The reflector's addresses count as its own.
func newTestReflector(t testing.TB, cfg *Config, nets map[string]string) (*Reflector, *[]forwardCall) {
	t.Helper()
	r, err := NewReflector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	calls := &[]forwardCall{}
	r.forwarder = func(ifc *ifaceInfo, data []byte) {
		*calls = append(*calls, forwardCall{ifc.name, append([]byte(nil), data...)})
	}
	set := newIfaceSet()
	for i, ic := range cfg.Interfaces {
		cidr, ok := nets[ic.Name]
		if !ok {
			continue
		}
		p := netip.MustParsePrefix(cidr)
		set.own[p.Addr()] = struct{}{}
		set.add(&ifaceInfo{name: ic.Name, group: ic.Group, index: i + 1, prefixes: []netip.Prefix{p.Masked()}})
	}
	r.ifaces.Store(set)
	return r, calls
}

// receive feeds a copy of data to the packet path as if it arrived on iface
// from src.
func (r *Reflector) receive(iface string, data []byte, src string) {
	set := r.ifaces.Load()
	ifc := set.byName[iface]
	if ifc == nil {
		return
	}
	r.handle(set, ifc, append([]byte(nil), data...), netip.MustParseAddr(src))
}

func ifacesOf(calls []forwardCall) []string {
	var out []string
	for _, c := range calls {
		out = append(out, c.iface)
	}
	return out
}

func boolp(b bool) *bool { return &b }

// wireQuery builds a query with one PTR question per name. With compress set,
// every name after the first ends in a pointer to the first name's "local."
// (dns v2 Pack writes only one question, so multi-question packets are built
// by hand).
func wireQuery(names []string, qu, compress bool) []byte {
	b := make([]byte, 12)
	b[4] = byte(len(names) >> 8)
	b[5] = byte(len(names))
	localOff := -1
	for _, n := range names {
		labels := strings.Split(strings.TrimSuffix(n, "."), ".")
		pointed := false
		for i, label := range labels {
			if compress && localOff >= 0 && i == len(labels)-1 && label == "local" {
				b = append(b, 0xC0|byte(localOff>>8), byte(localOff))
				pointed = true
				break
			}
			if label == "local" && localOff < 0 {
				localOff = len(b)
			}
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
		if !pointed {
			b = append(b, 0)
		}
		b = append(b, 0, 12) // PTR
		cls := uint16(1)
		if qu {
			cls |= 0x8000
		}
		b = append(b, byte(cls>>8), byte(cls))
	}
	return b
}

func ptrRR(name, target string) *dns.PTR {
	rr := &dns.PTR{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 120}}
	rr.Ptr = target
	return rr
}

func aRR(name, addr string) *dns.A {
	rr := &dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET | 0x8000, TTL: 120}}
	rr.Addr = netip.MustParseAddr(addr)
	return rr
}

func aaaaRR(name, addr string) *dns.AAAA {
	rr := &dns.AAAA{Hdr: dns.Header{Name: name, Class: dns.ClassINET | 0x8000, TTL: 120}}
	rr.Addr = netip.MustParseAddr(addr)
	return rr
}

// packResponse packs an mDNS response (no questions) with dns v2.
func packResponse(t testing.TB, answer, extra []dns.RR) []byte {
	t.Helper()
	m := &dns.Msg{MsgHeader: dns.MsgHeader{Response: true, Authoritative: true}, Answer: answer, Extra: extra}
	if err := m.Pack(); err != nil {
		t.Fatal(err)
	}
	return m.Data
}

func packQuery(t testing.TB, name string, qtype uint16) []byte {
	t.Helper()
	newRR := dns.TypeToRR[qtype]
	q := newRR()
	*q.Header() = dns.Header{Name: name, Class: dns.ClassINET}
	m := &dns.Msg{Question: []dns.RR{q}}
	if err := m.Pack(); err != nil {
		t.Fatal(err)
	}
	return m.Data
}

func unpack(t testing.TB, data []byte) *dns.Msg {
	t.Helper()
	m := &dns.Msg{Data: data}
	if err := m.Unpack(); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return m
}

func rrStrings(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		out = append(out, rr.String())
	}
	return out
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
