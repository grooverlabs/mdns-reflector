package main

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/net/ipv4"
)

var testNets = map[string]string{
	"vlan.10": "192.168.10.1/24",
	"vlan.11": "192.168.11.1/24",
	"vlan.12": "192.168.12.1/24",
	"vlan.19": "192.168.19.1/24",
	"vlan.20": "192.168.20.1/24",
}

func testConfig() *Config {
	return &Config{
		Interfaces: []InterfaceConfig{
			{Name: "vlan.10", Group: "users"},
			{Name: "vlan.11", Group: "users"},
			{Name: "vlan.12", Group: "users"},
			{Name: "vlan.19", Group: "gl_iot"},
			{Name: "vlan.20", Group: "gl_tv"},
		},
		Rules: []Rule{
			{From: "users", To: []string{"gl_iot", "gl_tv"}, Types: []string{"query"},
				Filter: Filter{AllowedServices: []string{"_ipp._tcp", "_airplay._tcp"}}},
			{From: "gl_iot", To: []string{"users"}, Types: []string{"response"},
				Filter: Filter{AllowedIPs: []string{"192.168.19.10"}}},
			{From: "gl_tv", To: []string{"users"}, Types: []string{"response"}, StatefulWindow: 60},
		},
	}
}

func ippResponse(t testing.TB) []byte {
	return packResponse(t, []dns.RR{ptrRR("_ipp._tcp.local.", "Printer._ipp._tcp.local.")}, nil)
}

func TestQueryReflectedWithQUStripped(t *testing.T) {
	r, calls := newTestReflector(t, testConfig(), testNets)
	r.receive("vlan.10", wireQuery([]string{"_airplay._tcp.local."}, true, false), "192.168.10.50")
	if got := ifacesOf(*calls); !slices.Equal(got, []string{"vlan.19", "vlan.20"}) {
		t.Fatalf("forwarded to %v", got)
	}
	out := unpack(t, (*calls)[0].data)
	if out.Question[0].Header().Class&0x8000 != 0 {
		t.Error("QU bit was not stripped")
	}
}

// Review finding 1 through the whole packet path.
func TestMultiQuestionQUQueryForwardedIntact(t *testing.T) {
	r, calls := newTestReflector(t, testConfig(), testNets)
	names := []string{"_ipp._tcp.local.", "_airplay._tcp.local.", "Printer._ipp._tcp.local."}
	r.receive("vlan.10", wireQuery(names, true, true), "192.168.10.5")
	if len(*calls) != 2 {
		t.Fatalf("want 2 forwards, got %d", len(*calls))
	}
	want := wireQuery(names, false, true)
	if got := (*calls)[0].data; string(got) != string(want) {
		t.Errorf("forwarded\n %x\nwant %x", got, want)
	}
	if n := len(unpack(t, (*calls)[0].data).Question); n != 3 {
		t.Errorf("forwarded query parses with %d questions", n)
	}
}

func TestServiceFilter(t *testing.T) {
	cases := []struct {
		names []string
		want  bool
	}{
		{[]string{"_ipp._tcp.local."}, true},
		{[]string{"Office Printer._ipp._tcp.local."}, true},
		{[]string{"_universal._sub._ipp._tcp.local."}, true},
		{[]string{"_IPP._TCP.LOCAL."}, true},
		{[]string{"myhost.local."}, true},
		{[]string{"10.10.168.192.in-addr.arpa."}, true},
		{[]string{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa."}, true},
		{[]string{"_ssh._tcp.local."}, false},
		{[]string{"x_ipp._tcp.local."}, false},     // substring, not a label suffix
		{[]string{"_ipp._tcpx.local."}, false},     // substring
		{[]string{"_ipp._tcp.evil.local."}, false}, // contains, but not a suffix
		{[]string{"a.b.local."}, false},            // not a bare hostname
		{[]string{"_hidden.local."}, false},
		// Review finding 11: every question must be allowed.
		{[]string{"_ssh._tcp.local.", "_ipp._tcp.local."}, false},
		{[]string{"_ipp._tcp.local.", "myhost.local."}, true},
	}
	for _, c := range cases {
		r, calls := newTestReflector(t, testConfig(), testNets)
		r.receive("vlan.10", wireQuery(c.names, false, false), "192.168.10.5")
		if got := len(*calls) > 0; got != c.want {
			t.Errorf("%v: forwarded=%v, want %v", c.names, got, c.want)
		}
	}
}

func TestResponseFiltering(t *testing.T) {
	t.Run("allowed IP with open window", func(t *testing.T) {
		r, calls := newTestReflector(t, testConfig(), testNets)
		r.receive("vlan.10", packQuery(t, "_ipp._tcp.local.", dns.TypePTR), "192.168.10.50")
		*calls = nil
		r.receive("vlan.19", ippResponse(t), "192.168.19.10")
		if got := ifacesOf(*calls); !slices.Equal(got, []string{"vlan.10"}) {
			t.Errorf("forwarded to %v, want [vlan.10]", got)
		}
	})
	t.Run("IP not allowed", func(t *testing.T) {
		r, calls := newTestReflector(t, testConfig(), testNets)
		r.receive("vlan.10", packQuery(t, "_ipp._tcp.local.", dns.TypePTR), "192.168.10.50")
		*calls = nil
		r.receive("vlan.19", ippResponse(t), "192.168.19.99")
		if len(*calls) != 0 {
			t.Errorf("forwarded to %v", ifacesOf(*calls))
		}
	})
	t.Run("no window", func(t *testing.T) {
		r, calls := newTestReflector(t, testConfig(), testNets)
		r.receive("vlan.20", ippResponse(t), "192.168.20.10")
		if len(*calls) != 0 {
			t.Errorf("forwarded to %v", ifacesOf(*calls))
		}
	})
	t.Run("response from users group has no rule", func(t *testing.T) {
		r, calls := newTestReflector(t, testConfig(), testNets)
		r.receive("vlan.11", packQuery(t, "_ipp._tcp.local.", dns.TypePTR), "192.168.11.5")
		*calls = nil
		r.receive("vlan.10", ippResponse(t), "192.168.10.50")
		if len(*calls) != 0 {
			t.Errorf("forwarded to %v", ifacesOf(*calls))
		}
	})
	t.Run("unknown interface", func(t *testing.T) {
		r, calls := newTestReflector(t, testConfig(), testNets)
		r.receive("eth0", packQuery(t, "_ipp._tcp.local.", dns.TypePTR), "1.1.1.1")
		if len(*calls) != 0 {
			t.Errorf("forwarded to %v", ifacesOf(*calls))
		}
	})
}

// Review finding 3: a blocked query must not open the window.
func TestWindowNotOpenedByBlockedQuery(t *testing.T) {
	r, calls := newTestReflector(t, testConfig(), testNets)
	r.receive("vlan.11", packQuery(t, "_ssh._tcp.local.", dns.TypePTR), "192.168.11.5")
	if len(*calls) != 0 {
		t.Fatalf("_ssh query forwarded to %v", ifacesOf(*calls))
	}
	// Blocked as a whole (one question is not allowed), but it asks for the
	// name the response answers.
	r.receive("vlan.12", wireQuery([]string{"_ipp._tcp.local.", "_ssh._tcp.local."}, false, false), "192.168.12.5")
	if len(*calls) != 0 {
		t.Fatalf("mixed query forwarded to %v", ifacesOf(*calls))
	}
	r.receive("vlan.19", ippResponse(t), "192.168.19.10")
	if len(*calls) != 0 {
		t.Errorf("response reflected to %v through a window a blocked query opened", ifacesOf(*calls))
	}
}

// The window is per (interface, name): only interfaces that asked for what the
// response answers receive it, and only within the window.
func TestWindowPerName(t *testing.T) {
	r, calls := newTestReflector(t, testConfig(), testNets)
	now := time.Unix(1_000_000, 0)
	r.now = func() time.Time { return now }
	r.receive("vlan.10", packQuery(t, "_ipp._tcp.local.", dns.TypePTR), "192.168.10.5")
	r.receive("vlan.11", packQuery(t, "_airplay._tcp.local.", dns.TypePTR), "192.168.11.5")
	*calls = nil

	r.receive("vlan.19", ippResponse(t), "192.168.19.10")
	if got := ifacesOf(*calls); !slices.Equal(got, []string{"vlan.10"}) {
		t.Errorf("_ipp response went to %v, want [vlan.10]", got)
	}

	*calls = nil
	now = now.Add(61 * time.Second)
	r.receive("vlan.19", ippResponse(t), "192.168.19.10")
	if len(*calls) != 0 {
		t.Errorf("expired window still reflected to %v", ifacesOf(*calls))
	}
}

func TestStatefulOptOut(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[2].Stateful = boolp(false)
	r, calls := newTestReflector(t, cfg, testNets)
	r.receive("vlan.20", ippResponse(t), "192.168.20.10")
	if got := ifacesOf(*calls); !slices.Equal(got, []string{"vlan.10", "vlan.11", "vlan.12"}) {
		t.Errorf("forwarded to %v", got)
	}
}

func TestWindowTableBounded(t *testing.T) {
	r, _ := newTestReflector(t, testConfig(), testNets)
	now := time.Unix(1_000_000, 0)
	for i := range maxWindows + 100 {
		r.openWindow("vlan.10", []byte(strings.Repeat("x", i%50)+string(rune(i))), now)
	}
	if r.windowCount > maxWindows {
		t.Errorf("windowCount %d > %d", r.windowCount, maxWindows)
	}
	n := 0
	for _, m := range r.windows {
		n += len(m)
	}
	if n != r.windowCount {
		t.Errorf("windowCount %d, entries %d", r.windowCount, n)
	}
}

// Review finding 2: the reviewer's storm simulation. Every forward comes back
// in on the destination interface (what multicast loopback did) with the
// reflector's own address as source. It must not snowball.
func TestLoopbackStorm(t *testing.T) {
	cfg := &Config{
		Interfaces: []InterfaceConfig{{Name: "u0", Group: "users"}, {Name: "u1", Group: "users"}, {Name: "u2", Group: "users"}},
		Rules:      []Rule{{From: "users", To: []string{"users"}, Types: []string{"query"}}},
	}
	nets := map[string]string{"u0": "10.0.0.1/24", "u1": "10.0.1.1/24", "u2": "10.0.2.1/24"}
	r, calls := newTestReflector(t, cfg, nets)
	r.receive("u0", packQuery(t, "foo.local.", dns.TypePTR), "10.0.0.2")
	for i := 0; i < len(*calls) && i < 10000; i++ {
		c := (*calls)[i]
		r.receive(c.iface, c.data, strings.TrimSuffix(nets[c.iface], "/24"))
	}
	if n := len(*calls); n > 2 {
		t.Errorf("one query produced %d forwards", n)
	}
}

// Review finding 4: sources outside the arriving interface's subnet are dropped.
func TestSourceMustBeInInterfaceSubnet(t *testing.T) {
	r, calls := newTestReflector(t, testConfig(), testNets)
	r.receive("vlan.10", packQuery(t, "_ipp._tcp.local.", dns.TypePTR), "192.168.10.50")
	*calls = nil
	// The printer's allowed address, spoofed from the TV VLAN.
	r.receive("vlan.20", ippResponse(t), "192.168.19.10")
	if len(*calls) != 0 {
		t.Errorf("spoofed source reflected to %v", ifacesOf(*calls))
	}
}

// Review findings 4 and 16: A records for other hosts and AAAA records are
// removed from reflected responses.
func TestResponseAddressRecordsFiltered(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[1].Filter.AllowedIPs = nil
	r, calls := newTestReflector(t, cfg, testNets)
	r.receive("vlan.10", packQuery(t, "_airplay._tcp.local.", dns.TypePTR), "192.168.10.50")
	*calls = nil
	r.receive("vlan.19", airplayResponse(t, "192.168.19.10", "10.9.9.9"), "192.168.19.10")
	if len(*calls) != 1 {
		t.Fatalf("want 1 forward, got %v", ifacesOf(*calls))
	}
	out := unpack(t, (*calls)[0].data)
	var addrs []string
	for _, rr := range out.Extra {
		switch rr := rr.(type) {
		case *dns.A:
			addrs = append(addrs, rr.Addr.String())
		case *dns.AAAA:
			addrs = append(addrs, rr.Addr.String())
		}
	}
	if !slices.Equal(addrs, []string{"192.168.19.10"}) {
		t.Errorf("address records %v, want only the sender's A", addrs)
	}
	if len(out.Answer) != 3 {
		t.Errorf("answers %d, want 3", len(out.Answer))
	}
}

// A foreign A record that cannot be cut out safely drops the whole response.
func TestForeignARecordUnremovableDropsResponse(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[1].Filter.AllowedIPs = nil
	cfg.Rules[1].Stateful = boolp(false)
	r, calls := newTestReflector(t, cfg, testNets)
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "tv.local.", Class: dns.ClassINET, TTL: 120}}
	nsec.NextDomain = "tv.local."
	nsec.TypeBitMap = []uint16{dns.TypeA}
	data := packResponse(t, []dns.RR{aRR("tv.local.", "10.9.9.9")}, []dns.RR{nsec})
	r.receive("vlan.19", data, "192.168.19.10")
	if len(*calls) != 0 {
		t.Errorf("response with an unremovable foreign A record reflected to %v", ifacesOf(*calls))
	}
}

// An AAAA record that cannot be cut out safely stays in.
func TestUnremovableAAAAKept(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[1].Filter.AllowedIPs = nil
	cfg.Rules[1].Stateful = boolp(false)
	r, calls := newTestReflector(t, cfg, testNets)
	data := packResponse(t, []dns.RR{aaaaRR("tv.local.", "fe80::1"), aRR("tv.local.", "192.168.19.10")}, nil)
	r.receive("vlan.19", data, "192.168.19.10")
	if len(*calls) != 3 {
		t.Fatalf("want 3 forwards, got %v", ifacesOf(*calls))
	}
	if string((*calls)[0].data) != string(data) {
		t.Error("response changed")
	}
}

func TestMalformedDropped(t *testing.T) {
	r, calls := newTestReflector(t, testConfig(), testNets)
	q := wireQuery([]string{"_ipp._tcp.local."}, true, false)
	r.receive("vlan.10", q[:len(q)-1], "192.168.10.5")
	if len(*calls) != 0 {
		t.Errorf("malformed query forwarded")
	}
}

func FuzzHandlePacket(f *testing.F) {
	f.Add(wireQuery([]string{"_ipp._tcp.local.", "_airplay._tcp.local."}, true, true))
	f.Add(packQuery(f, "_airplay._tcp.local.", dns.TypePTR))
	f.Add(airplayResponse(f, "192.168.19.10", "10.9.9.9"))
	f.Add(ippResponse(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := testConfig()
		cfg.Rules[1].Filter.AllowedIPs = nil
		r, _ := newTestReflector(t, cfg, testNets)
		r.receive("vlan.10", data, "192.168.10.5")
		r.receive("vlan.19", data, "192.168.19.10")
		r.receive("vlan.20", data, "192.168.20.10")
	})
}

func BenchmarkHandleQuery(b *testing.B) {
	r, _ := newTestReflector(b, testConfig(), testNets)
	r.forwarder = func(*ifaceInfo, []byte) {}
	q := wireQuery([]string{"_ipp._tcp.local.", "_airplay._tcp.local."}, true, true)
	set := r.ifaces.Load()
	src := set.byName["vlan.10"]
	ip := mustAddr("192.168.10.5")
	buf := make([]byte, len(q))
	b.ReportAllocs()
	for b.Loop() {
		copy(buf, q)
		r.handle(set, src, buf, ip)
	}
}

// BenchmarkForward measures one forward on a real socket (loopback, unicast
// sink). Before review finding 5 each forward also did InterfaceByName and
// ResolveUDPAddr: about 0.5 ms and 30 KB.
func BenchmarkForward(b *testing.B) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	go func() {
		buf := make([]byte, 9000)
		for {
			if _, err := sink.Read(buf); err != nil {
				return
			}
		}
	}()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		b.Skip("no lo interface")
	}
	r, _ := newTestReflector(b, testConfig(), testNets)
	r.conn = c
	r.dst = sink.LocalAddr().(*net.UDPAddr)
	ifc := &ifaceInfo{name: "lo", index: lo.Index, oob: (&ipv4.ControlMessage{IfIndex: lo.Index}).Marshal()}
	pkt := make([]byte, 300)
	b.ReportAllocs()
	for b.Loop() {
		r.forward(ifc, pkt)
	}
}
