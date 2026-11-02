package main

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
)

// Review finding 1: a multi-question QU query must come out byte-identical
// except for the QU bits, and still parse with all its questions.
func TestStripQUMultiQuestion(t *testing.T) {
	for _, compress := range []bool{false, true} {
		names := []string{"_companion-link._tcp.local.", "_airplay._tcp.local.", "_raop._tcp.local."}
		in := wireQuery(names, true, compress)
		data := append([]byte(nil), in...)
		m, err := scanMsg(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.questions) != 3 {
			t.Fatalf("questions: got %d, want 3", len(m.questions))
		}
		if !m.stripQU(data) {
			t.Fatal("stripQU reported no change")
		}
		want := wireQuery(names, false, compress)
		if !bytes.Equal(data, want) {
			t.Errorf("compress=%v: stripped packet\n got %x\nwant %x", compress, data, want)
		}
		out := unpack(t, data)
		if len(out.Question) != 3 {
			t.Fatalf("forwarded packet parses with %d questions, want 3", len(out.Question))
		}
		for i, q := range out.Question {
			if q.Header().Class != dns.ClassINET {
				t.Errorf("question %d class %#x", i, q.Header().Class)
			}
			if got := presentName(m.questions[i].name); got != names[i] {
				t.Errorf("question %d name %q, want %q", i, got, names[i])
			}
		}
	}
}

func TestScanCanonicalName(t *testing.T) {
	data := wireQuery([]string{"My-TV._AirPlay._TCP.Local."}, false, false)
	m, err := scanMsg(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := presentName(m.questions[0].name); got != "my-tv._airplay._tcp.local." {
		t.Errorf("canonical name %q", got)
	}
}

func TestScanRejectsMalformed(t *testing.T) {
	good := wireQuery([]string{"_ipp._tcp.local."}, false, false)
	hdr := func(qd, an byte) []byte { return []byte{0, 0, 0x84, 0, 0, qd, 0, an, 0, 0, 0, 0} }
	cases := map[string][]byte{
		"short header":       good[:11],
		"qdcount too large":  append(append([]byte(nil), good[:5]...), append([]byte{9}, good[6:]...)...),
		"truncated question": good[:len(good)-1],
		"trailing bytes":     append(append([]byte(nil), good...), 0),
		"label overrun":      append(hdr(1, 0), 10, 'a', 'b', 0, 0, 12, 0, 1),
		"self pointer":       append(hdr(1, 0), 0xC0, 12, 0, 12, 0, 1),
		"forward pointer":    append(hdr(1, 0), 0xC0, 20, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0),
		"header pointer":     append(hdr(1, 0), 0xC0, 2, 0, 12, 0, 1),
		"extended label":     append(hdr(1, 0), 0x40, 0, 0, 12, 0, 1),
		"rdlength overrun":   append(hdr(0, 1), 0, 0, 1, 0, 1, 0, 0, 0, 120, 0, 9, 1, 2, 3, 4),
		"short A record":     append(hdr(0, 1), 0, 0, 1, 0, 1, 0, 0, 0, 120, 0, 3, 1, 2, 3),
		"PTR rdata too long": append(hdr(0, 1), 0, 0, 12, 0, 1, 0, 0, 0, 120, 0, 2, 0, 0),
	}
	long := hdr(1, 0)
	for range 5 {
		long = append(long, 60)
		long = append(long, bytes.Repeat([]byte{'a'}, 60)...)
	}
	cases["name over 255"] = append(long, 0, 0, 12, 0, 1)
	for name, data := range cases {
		if _, err := scanMsg(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := scanMsg(good); err != nil {
		t.Errorf("good packet rejected: %v", err)
	}
}

// A realistic AirPlay-style response: answers PTR/SRV/TXT, extras A, AAAA,
// NSEC, plus an OPT record (Apple's Owner option rides in one).
func airplayResponse(t testing.TB, aAddrs ...string) []byte {
	t.Helper()
	srv := &dns.SRV{Hdr: dns.Header{Name: "TV._airplay._tcp.local.", Class: dns.ClassINET | 0x8000, TTL: 120}}
	srv.Priority, srv.Weight, srv.Port, srv.Target = 0, 0, 7000, "tv.local."
	txt := &dns.TXT{Hdr: dns.Header{Name: "TV._airplay._tcp.local.", Class: dns.ClassINET | 0x8000, TTL: 4500}}
	txt.Txt = []string{"model=AppleTV", "features=0x5A7FFFF7"}
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "tv.local.", Class: dns.ClassINET | 0x8000, TTL: 120}}
	nsec.NextDomain = "tv.local."
	nsec.TypeBitMap = []uint16{dns.TypeA, dns.TypeAAAA}
	extra := []dns.RR{}
	for _, a := range aAddrs {
		extra = append(extra, aRR("tv.local.", a))
	}
	extra = append(extra, aaaaRR("tv.local.", "fe80::1"), nsec)
	m := &dns.Msg{
		MsgHeader: dns.MsgHeader{Response: true, Authoritative: true, UDPSize: 1440},
		Answer:    []dns.RR{ptrRR("_airplay._tcp.local.", "TV._airplay._tcp.local."), srv, txt},
		Extra:     extra,
	}
	if err := m.Pack(); err != nil {
		t.Fatal(err)
	}
	return m.Data
}

// Removing records on the wire leaves every other record intact, as dns v2
// reads it, with pointers fixed up.
func TestRemoveRRsVerifiesAgainstDNSLibrary(t *testing.T) {
	txt := &dns.TXT{Hdr: dns.Header{Name: "printer2.local.", Class: dns.ClassINET, TTL: 120}}
	txt.Txt = []string{"x=1"}
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "printer2.local.", Class: dns.ClassINET, TTL: 120}}
	nsec.NextDomain = "printer2.local."
	nsec.TypeBitMap = []uint16{dns.TypeTXT}
	packets := map[string][]byte{
		"airplay": airplayResponse(t, "192.168.19.10", "10.9.9.9"),
		// Pointers after the removed A record target names after it, so
		// they must shift.
		"shifted pointers": packResponse(t,
			[]dns.RR{ptrRR("_ipp._tcp.local.", "P._ipp._tcp.local.")},
			[]dns.RR{aRR("other.local.", "10.9.9.9"), aaaaRR("other6.local.", "fe80::2"), txt, nsec}),
	}
	for name, data := range packets {
		orig := unpack(t, data)
		m, err := scanMsg(data)
		if err != nil {
			t.Fatal(err)
		}
		if !m.compressed {
			t.Fatalf("%s: no compression; dns v2 Pack changed", name)
		}
		drop := make([]bool, len(m.rrs))
		ndrop := 0
		for i, rr := range m.rrs {
			a, isA := rr.aAddr(data)
			drop[i] = (isA && a != mustAddr("192.168.19.10")) || rr.rrtype == typeAAAA
			if drop[i] {
				ndrop++
			}
		}
		if ndrop != 2 {
			t.Fatalf("%s: dropping %d records, want 2", name, ndrop)
		}
		out, err := m.removeRRs(data, drop)
		if err != nil {
			t.Fatal(err)
		}
		got := unpack(t, out)
		keep := func(rrs []dns.RR) []string {
			var s []string
			for _, rr := range rrs {
				if a, ok := rr.(*dns.A); ok && a.Addr.String() != "192.168.19.10" {
					continue
				}
				if _, ok := rr.(*dns.AAAA); ok {
					continue
				}
				s = append(s, rr.String())
			}
			return s
		}
		for sec, pair := range map[string][2][]dns.RR{"answer": {got.Answer, orig.Answer}, "authority": {got.Ns, orig.Ns}, "extra": {got.Extra, orig.Extra}} {
			if g, w := rrStrings(pair[0]), keep(pair[1]); !slices.Equal(g, w) {
				t.Errorf("%s %s:\n got %v\nwant %v", name, sec, g, w)
			}
		}
		if !slices.Equal(rrStrings(got.Pseudo), rrStrings(orig.Pseudo)) || got.UDPSize != orig.UDPSize {
			t.Errorf("%s: EDNS changed", name)
		}
	}
}

func TestRemoveRRsRefusesCompressionTarget(t *testing.T) {
	// The A record's owner name is the first "tv.local."; the NSEC after it
	// compresses its owner into it.
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "tv.local.", Class: dns.ClassINET, TTL: 120}}
	nsec.NextDomain = "tv.local."
	nsec.TypeBitMap = []uint16{dns.TypeA}
	data := packResponse(t, []dns.RR{aRR("tv.local.", "10.9.9.9")}, []dns.RR{nsec})
	m, err := scanMsg(data)
	if err != nil {
		t.Fatal(err)
	}
	if !m.compressed {
		t.Fatal("test packet has no compression; dns v2 Pack changed")
	}
	_, err = m.removeRRs(data, []bool{true, false})
	if !errors.Is(err, errUnsafeRemove) {
		t.Errorf("err = %v, want errUnsafeRemove", err)
	}
}

// Fuzz the raw walker: it must not panic; whatever it accepts, the QU strip
// changes only the class bytes and address removal yields a packet the walker
// and (when it parsed the original) dns v2 accept with the expected records.
func FuzzScanMsg(f *testing.F) {
	f.Add(wireQuery([]string{"_ipp._tcp.local.", "_airplay._tcp.local."}, true, true))
	f.Add(airplayResponse(f, "192.168.19.10", "10.9.9.9"))
	f.Add(packQuery(f, "host.local.", dns.TypeA))
	f.Fuzz(func(t *testing.T, data []byte) {
		orig := append([]byte(nil), data...)
		m, err := scanMsg(data)
		if err != nil {
			return
		}
		m.stripQU(data)
		for i := range data {
			isClass := false
			for _, q := range m.questions {
				isClass = isClass || i == q.classOff
			}
			if data[i] != orig[i] && !isClass {
				t.Fatalf("byte %d changed outside a qclass", i)
			}
		}
		drop := make([]bool, len(m.rrs))
		kept := 0
		for i, rr := range m.rrs {
			drop[i] = rr.rrtype == typeA || rr.rrtype == typeAAAA
			if !drop[i] {
				kept++
			}
		}
		out, err := m.removeRRs(data, drop)
		if err != nil {
			return
		}
		nm, err := scanMsg(out)
		if err != nil || len(nm.rrs) != kept {
			t.Fatalf("removal produced a bad packet: %v", err)
		}
		om := &dns.Msg{Data: data}
		if om.Unpack() != nil || len(om.Question) > 1 {
			return
		}
		got := &dns.Msg{Data: out}
		if err := got.Unpack(); err != nil {
			t.Fatalf("dns v2 rejects the rewritten packet: %v", err)
		}
		if len(got.Answer)+len(got.Ns) > len(om.Answer)+len(om.Ns) {
			t.Fatal("records appeared")
		}
	})
}
