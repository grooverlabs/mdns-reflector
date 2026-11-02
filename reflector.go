package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	mdnsPort        = 5353
	refreshInterval = 30 * time.Second
	// maxWindows caps the stateful-window table. Queries for hostnames are
	// allowed through any service filter, so its keys are attacker-chosen.
	maxWindows = 4096
)

var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort}

// compiledRule is a Rule with its filters parsed for the packet path.
type compiledRule struct {
	from       string
	to         []string
	query      bool
	response   bool
	stateful   bool
	window     time.Duration
	allowedIPs map[netip.Addr]struct{} // empty: any source
	services   [][]byte                // canonical name suffixes; empty: any question
}

func compileRule(rule *Rule) (compiledRule, error) {
	cr := compiledRule{
		from:     rule.From,
		to:       rule.To,
		query:    rule.hasType("query"),
		response: rule.hasType("response"),
		stateful: rule.isStateful(),
		window:   time.Duration(rule.window()) * time.Second,
	}
	if len(rule.Filter.AllowedIPs) > 0 {
		cr.allowedIPs = make(map[netip.Addr]struct{})
		for _, s := range rule.Filter.AllowedIPs {
			ip, err := netip.ParseAddr(s)
			if err != nil || !ip.Is4() {
				return cr, fmt.Errorf("allowed_ips: %q is not an IPv4 address", s)
			}
			cr.allowedIPs[ip] = struct{}{}
		}
	}
	for _, s := range rule.Filter.AllowedServices {
		name, err := serviceName(s)
		if err != nil {
			return cr, err
		}
		cr.services = append(cr.services, name)
	}
	return cr, nil
}

// serviceName turns an allowed_services entry such as "_ipp._tcp" into the
// canonical wire name "_ipp._tcp.local.".
func serviceName(s string) ([]byte, error) {
	s = strings.ToLower(strings.Trim(s, "."))
	if s != "local" && !strings.HasSuffix(s, ".local") {
		s += ".local"
	}
	var out []byte
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("allowed_services: %q is not a valid name", s)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

func (cr *compiledRule) ipAllowed(ip netip.Addr) bool {
	if len(cr.allowedIPs) == 0 {
		return true
	}
	_, ok := cr.allowedIPs[ip]
	return ok
}

var (
	localSuffix   = []byte("\x05local\x00")
	inAddrSuffix  = []byte("\x07in-addr\x04arpa\x00")
	ip6ArpaSuffix = []byte("\x03ip6\x04arpa\x00")
)

// questionAllowed reports whether a question name passes the service filter:
// it is an allowed service name or a name below one (an instance or subtype),
// a bare hostname ("host.local."), or a reverse-lookup name.
func (cr *compiledRule) questionAllowed(name []byte) bool {
	if len(cr.services) == 0 {
		return true
	}
	for _, s := range cr.services {
		if hasLabelSuffix(name, s) {
			return true
		}
	}
	return isHostname(name) || hasLabelSuffix(name, inAddrSuffix) || hasLabelSuffix(name, ip6ArpaSuffix)
}

// hasLabelSuffix reports whether canonical name ends with the canonical name
// suffix on a label boundary.
func hasLabelSuffix(name, suffix []byte) bool {
	want := len(name) - len(suffix)
	if want < 0 {
		return false
	}
	for p := 0; p < len(name); p += 1 + int(name[p]) {
		if p == want {
			return bytes.Equal(name[p:], suffix)
		}
		if p > want || name[p] == 0 {
			return false
		}
	}
	return false
}

// isHostname reports whether name is a single label (not starting with "_")
// under .local.
func isHostname(name []byte) bool {
	if len(name) < 2 || name[0] == 0 || name[1] == '_' {
		return false
	}
	return bytes.Equal(name[1+int(name[0]):], localSuffix)
}

// ifaceInfo is one configured interface as it exists on the host now.
type ifaceInfo struct {
	name     string
	group    string
	index    int
	oob      []byte // IP_PKTINFO control message selecting this interface
	prefixes []netip.Prefix
}

func (i *ifaceInfo) inSubnet(ip netip.Addr) bool {
	for _, p := range i.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ifaceSet is an immutable snapshot of the configured interfaces that exist,
// replaced as a whole on every refresh.
type ifaceSet struct {
	byIndex map[int]*ifaceInfo
	byName  map[string]*ifaceInfo
	byGroup map[string][]*ifaceInfo // in config order
	own     map[netip.Addr]struct{} // every IPv4 address of this host
}

func newIfaceSet() *ifaceSet {
	return &ifaceSet{
		byIndex: make(map[int]*ifaceInfo),
		byName:  make(map[string]*ifaceInfo),
		byGroup: make(map[string][]*ifaceInfo),
		own:     make(map[netip.Addr]struct{}),
	}
}

func (s *ifaceSet) add(i *ifaceInfo) {
	s.byIndex[i.index] = i
	s.byName[i.name] = i
	s.byGroup[i.group] = append(s.byGroup[i.group], i)
}

type Reflector struct {
	config *Config
	rules  []compiledRule
	ifaces atomic.Pointer[ifaceSet]

	conn *net.UDPConn
	pc   *ipv4.PacketConn
	dst  *net.UDPAddr

	// Stateful windows: interface name -> canonical question name -> time a
	// query for it was forwarded from that interface. Owned by the listener
	// goroutine.
	windows     map[string]map[string]time.Time
	windowCount int
	maxWindow   time.Duration
	now         func() time.Time

	// forwarder sends one packet out of one interface; tests replace it.
	forwarder func(ifc *ifaceInfo, data []byte)

	// Refresh state, owned by the refresh goroutine (and Start).
	joined       map[string]int // interface name -> ifindex joined
	joinFailed   map[string]bool
	refreshEvery time.Duration

	sent []*ifaceInfo // scratch: destinations of the current packet
}

func NewReflector(cfg *Config) (*Reflector, error) {
	r := &Reflector{
		config:       cfg,
		dst:          mdnsGroup,
		windows:      make(map[string]map[string]time.Time),
		now:          time.Now,
		joined:       make(map[string]int),
		joinFailed:   make(map[string]bool),
		refreshEvery: refreshInterval,
	}
	r.forwarder = r.forward
	r.ifaces.Store(newIfaceSet())
	for i := range cfg.Rules {
		cr, err := compileRule(&cfg.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		r.maxWindow = max(r.maxWindow, cr.window)
		r.rules = append(r.rules, cr)
	}
	return r, nil
}

// Start opens the socket and joins the configured interfaces that exist.
func (r *Reflector) Start() error {
	lc := net.ListenConfig{Control: reuseAddrPort}
	c, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", mdnsPort))
	if err != nil {
		return err
	}
	r.conn = c.(*net.UDPConn)
	p := ipv4.NewPacketConn(r.conn)
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return fmt.Errorf("IP_PKTINFO: %w", err)
	}
	// Never hear our own transmissions: a reflected packet looping back in
	// would be reflected again.
	if err := p.SetMulticastLoopback(false); err != nil {
		return fmt.Errorf("IP_MULTICAST_LOOP: %w", err)
	}
	// RFC 6762 §11: mDNS is sent with IP TTL 255.
	if err := p.SetMulticastTTL(255); err != nil {
		return fmt.Errorf("IP_MULTICAST_TTL: %w", err)
	}
	r.pc = p
	r.refresh()
	set := r.ifaces.Load()
	for _, ic := range r.config.Interfaces {
		if set.byName[ic.Name] == nil {
			slog.Warn("Interface not found or down; it is joined when it comes up", "interface", ic.Name, "check_every", r.refreshEvery)
		}
	}
	return nil
}

// reuseAddrPort lets the reflector share :5353 with avahi-daemon or another
// mDNS stack on the same host; every socket gets its own copy of each
// multicast packet.
func reuseAddrPort(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if serr == nil {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// Run reads and reflects packets until ctx is done (returns nil) or the
// socket fails (returns the error; the process should exit and be restarted).
func (r *Reflector) Run(ctx context.Context) error {
	go r.refreshLoop(ctx)
	stop := context.AfterFunc(ctx, func() { _ = r.conn.Close() })
	defer stop()

	buf := make([]byte, 9000)
	oob := ipv4.NewControlMessage(ipv4.FlagInterface)
	var cm ipv4.ControlMessage
	for {
		n, oobn, flags, src, err := r.conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}
		if flags&syscall.MSG_TRUNC != 0 {
			slog.Debug("Dropped truncated packet", "src_ip", src.Addr())
			continue
		}
		cm = ipv4.ControlMessage{}
		if err := cm.Parse(oob[:oobn]); err != nil || cm.IfIndex == 0 {
			continue
		}
		set := r.ifaces.Load()
		ifc := set.byIndex[cm.IfIndex]
		if ifc == nil {
			slog.Debug("Dropped packet from unconfigured interface", "ifindex", cm.IfIndex, "src_ip", src.Addr())
			continue
		}
		r.handle(set, ifc, buf[:n], src.Addr().Unmap())
	}
}

func (r *Reflector) forward(ifc *ifaceInfo, data []byte) {
	if _, _, err := r.conn.WriteMsgUDP(data, ifc.oob, r.dst); err != nil {
		slog.Warn("Failed to forward packet", "interface", ifc.name, "error", err)
	}
}

// handle filters and reflects one received packet. data is modified in place.
func (r *Reflector) handle(set *ifaceSet, src *ifaceInfo, data []byte, srcIP netip.Addr) {
	if _, ok := set.own[srcIP]; ok {
		return // sent by this host (us, avahi, another reflector)
	}
	if !src.inSubnet(srcIP) {
		slog.Debug("Dropped packet: source not in the interface's subnet", "src_ip", srcIP, "from", src.name)
		return
	}
	m, err := scanMsg(data)
	if err != nil {
		slog.Debug("Dropped malformed packet", "src_ip", srcIP, "from", src.name, "error", err)
		return
	}
	r.sent = r.sent[:0]
	if m.response {
		r.handleResponse(set, src, data, m, srcIP)
	} else {
		r.handleQuery(set, src, data, m, srcIP)
	}
}

// reflect sends data to every interface in the rule's target groups except
// the source and interfaces already sent this packet; pass, if set, filters
// further.
func (r *Reflector) reflect(set *ifaceSet, src *ifaceInfo, cr *compiledRule, data []byte, pass func(*ifaceInfo) bool) {
	for _, g := range cr.to {
		for _, d := range set.byGroup[g] {
			if d == src || slices.Contains(r.sent, d) || (pass != nil && !pass(d)) {
				continue
			}
			r.sent = append(r.sent, d)
			r.forwarder(d, data)
		}
	}
}

func (r *Reflector) handleQuery(set *ifaceSet, src *ifaceInfo, data []byte, m *wireMsg, srcIP netip.Addr) {
	if len(m.questions) == 0 {
		return
	}
	// Clear the QU bit so that services answer by multicast, which the
	// reflector hears; a unicast answer would go straight to a client on
	// another VLAN and be lost.
	m.stripQU(data)

	for i := range r.rules {
		cr := &r.rules[i]
		if cr.from != src.group || !cr.query || !cr.ipAllowed(srcIP) {
			continue
		}
		// A query is forwarded only if every question passes the filter;
		// one allowed question does not carry the others through.
		allowed := true
		for _, q := range m.questions {
			if !cr.questionAllowed(q.name) {
				allowed = false
				break
			}
		}
		if allowed {
			r.reflect(set, src, cr, data, nil)
		}
	}
	if len(r.sent) == 0 {
		return
	}
	now := r.now()
	for _, q := range m.questions {
		r.openWindow(src.name, q.name, now)
	}
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug("Query reflected", "src_ip", srcIP, "from", src.name, "from_group", src.group,
			"to", ifaceNames(r.sent), "questions", questionSummary(m))
	}
}

func (r *Reflector) handleResponse(set *ifaceSet, src *ifaceInfo, data []byte, m *wireMsg, srcIP netip.Addr) {
	applies := func(cr *compiledRule) bool {
		return cr.from == src.group && cr.response && cr.ipAllowed(srcIP)
	}
	if !slices.ContainsFunc(r.rules, func(cr compiledRule) bool { return applies(&cr) }) {
		return
	}
	out, m, ok := filterAddresses(data, m, srcIP)
	if !ok || len(m.rrs) == 0 {
		return
	}
	now := r.now()
	for i := range r.rules {
		cr := &r.rules[i]
		if !applies(cr) {
			continue
		}
		var pass func(*ifaceInfo) bool
		if cr.stateful {
			pass = func(d *ifaceInfo) bool { return r.windowOpen(d.name, m, now, cr.window) }
		}
		r.reflect(set, src, cr, out, pass)
	}
	if len(r.sent) > 0 && slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug("Response reflected", "src_ip", srcIP, "from", src.name, "from_group", src.group,
			"to", ifaceNames(r.sent), "records", recordSummary(m))
	}
}

// filterAddresses removes address records that do not belong to the sender:
// A records for any address other than srcIP, and AAAA records (the reflector
// is IPv4-only and cannot check them). Removal is done on the wire bytes. If a
// foreign A record cannot be removed safely the response is dropped (ok is
// false); AAAA records that cannot be removed safely are left in.
func filterAddresses(data []byte, m *wireMsg, srcIP netip.Addr) ([]byte, *wireMsg, bool) {
	drop := make([]bool, len(m.rrs))
	foreignA, aaaa := false, false
	for i, rr := range m.rrs {
		if a, isA := rr.aAddr(data); isA && a != srcIP {
			drop[i], foreignA = true, true
		} else if rr.rrtype == typeAAAA {
			drop[i], aaaa = true, true
		}
	}
	if !foreignA && !aaaa {
		return data, m, true
	}
	out, err := m.removeRRs(data, drop)
	if errors.Is(err, errUnsafeRemove) && aaaa {
		for i, rr := range m.rrs {
			if rr.rrtype == typeAAAA {
				drop[i] = false
			}
		}
		out, err = m.removeRRs(data, drop)
	}
	if err != nil {
		slog.Debug("Dropped response: a foreign A record cannot be removed safely", "src_ip", srcIP)
		return nil, nil, false
	}
	kept := 0
	for _, d := range drop {
		if !d {
			kept++
		}
	}
	nm, err := scanMsg(out)
	if err != nil || len(nm.rrs) != kept {
		slog.Debug("Dropped response: rewrite did not verify", "src_ip", srcIP, "error", err)
		return nil, nil, false
	}
	return out, nm, true
}

func (r *Reflector) openWindow(iface string, name []byte, now time.Time) {
	names := r.windows[iface]
	if names == nil {
		names = make(map[string]time.Time)
		r.windows[iface] = names
	}
	if _, ok := names[string(name)]; !ok {
		if r.windowCount >= maxWindows {
			r.pruneWindows(now)
		}
		if r.windowCount >= maxWindows {
			r.evictOneWindow()
		}
		r.windowCount++
	}
	names[string(name)] = now
}

// evictOneWindow drops an arbitrary entry; only reached when maxWindows
// distinct names were queried within the longest window.
func (r *Reflector) evictOneWindow() {
	for _, ns := range r.windows {
		for k := range ns {
			delete(ns, k)
			r.windowCount--
			return
		}
	}
}

func (r *Reflector) pruneWindows(now time.Time) {
	for iface, names := range r.windows {
		for k, t := range names {
			if now.Sub(t) > r.maxWindow {
				delete(names, k)
				r.windowCount--
			}
		}
		if len(names) == 0 {
			delete(r.windows, iface)
		}
	}
}

// windowOpen reports whether iface forwarded a query, within window, for a
// name that one of the response's answers is for.
func (r *Reflector) windowOpen(iface string, m *wireMsg, now time.Time, window time.Duration) bool {
	names := r.windows[iface]
	if names == nil {
		return false
	}
	for _, rr := range m.rrs {
		if rr.section != sectionAnswer {
			continue
		}
		if t, ok := names[string(rr.name)]; ok && now.Sub(t) <= window {
			return true
		}
	}
	return false
}

func ifaceNames(ifs []*ifaceInfo) string {
	names := make([]string, len(ifs))
	for i, f := range ifs {
		names[i] = f.name
	}
	return strings.Join(names, ",")
}

// presentName renders a canonical wire name for logs.
func presentName(name []byte) string {
	var sb strings.Builder
	for p := 0; p < len(name) && name[p] != 0; p += 1 + int(name[p]) {
		for _, c := range name[p+1 : p+1+int(name[p])] {
			switch {
			case c == '.' || c == '\\':
				sb.WriteByte('\\')
				sb.WriteByte(c)
			case c < 0x21 || c > 0x7e:
				fmt.Fprintf(&sb, "\\%03d", c)
			default:
				sb.WriteByte(c)
			}
		}
		sb.WriteByte('.')
	}
	if sb.Len() == 0 {
		return "."
	}
	return sb.String()
}

func typeName(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func summarize(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	if len(items) > 3 {
		return fmt.Sprintf("[%s ... +%d more]", strings.Join(items[:3], ", "), len(items)-3)
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func questionSummary(m *wireMsg) string {
	items := make([]string, len(m.questions))
	for i, q := range m.questions {
		items[i] = fmt.Sprintf("%s (%s)", presentName(q.name), typeName(q.qtype))
	}
	return summarize(items)
}

// recordSummary lists the answer records (owner and type).
func recordSummary(m *wireMsg) string {
	var items []string
	for _, rr := range m.rrs {
		if rr.section == sectionAnswer {
			items = append(items, fmt.Sprintf("%s (%s)", presentName(rr.name), typeName(rr.rrtype)))
		}
	}
	return summarize(items)
}
