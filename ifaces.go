package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

func (r *Reflector) refreshLoop(ctx context.Context) {
	t := time.NewTicker(r.refreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refresh()
		}
	}
}

// refresh re-reads the host's interfaces: name -> index, each configured
// interface's IPv4 prefixes, and the host's own addresses. It joins the mDNS
// group on interfaces that appeared or were recreated, and publishes a new
// snapshot for the listener.
func (r *Reflector) refresh() {
	sys, err := net.Interfaces()
	if err != nil {
		slog.Warn("Listing interfaces failed", "error", err)
		return
	}
	set := newIfaceSet()
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if p, ok := ipv4Prefix(a); ok {
				set.own[p.Addr()] = struct{}{}
			}
		}
	} else {
		slog.Warn("Listing addresses failed", "error", err)
	}

	byName := make(map[string]*net.Interface, len(sys))
	for i := range sys {
		byName[sys[i].Name] = &sys[i]
	}
	old := r.ifaces.Load()

	for _, ic := range r.config.Interfaces {
		prev := old.byName[ic.Name]
		si := byName[ic.Name]
		if si == nil || si.Flags&net.FlagUp == 0 {
			if prev != nil {
				slog.Info("Interface gone", "interface", ic.Name)
			}
			r.leave(ic.Name)
			continue
		}
		info := &ifaceInfo{
			name:  ic.Name,
			group: ic.Group,
			index: si.Index,
			oob:   (&ipv4.ControlMessage{IfIndex: si.Index}).Marshal(),
		}
		if addrs, err := si.Addrs(); err == nil {
			for _, a := range addrs {
				if p, ok := ipv4Prefix(a); ok {
					info.prefixes = append(info.prefixes, p.Masked())
				}
			}
		}
		r.join(si)

		switch {
		case prev == nil:
			slog.Info("Interface up", "interface", ic.Name, "group", ic.Group, "index", si.Index, "prefixes", info.prefixes)
		case prev.index != si.Index:
			slog.Info("Interface recreated", "interface", ic.Name, "index", si.Index, "prefixes", info.prefixes)
		case !slices.Equal(prev.prefixes, info.prefixes):
			slog.Info("Interface addresses changed", "interface", ic.Name, "prefixes", info.prefixes)
		}
		if len(info.prefixes) == 0 && (prev == nil || len(prev.prefixes) > 0) {
			slog.Warn("Interface has no IPv4 address; packets from it are dropped", "interface", ic.Name)
		}
		set.add(info)
	}
	r.ifaces.Store(set)
}

// join adds the mDNS group membership on si unless it is already joined at
// this index.
func (r *Reflector) join(si *net.Interface) {
	if r.joined[si.Name] == si.Index {
		return
	}
	r.leave(si.Name) // recreated at a new index: drop the stale membership first
	err := r.pc.JoinGroup(si, mdnsGroup)
	if err != nil && !errors.Is(err, syscall.EADDRINUSE) {
		attrs := []any{"interface", si.Name, "error", err}
		if errors.Is(err, syscall.ENOBUFS) {
			attrs = append(attrs, "hint", "raise net.ipv4.igmp_max_memberships")
		}
		if r.joinFailed[si.Name] {
			slog.Debug("Failed to join multicast group", attrs...)
		} else {
			slog.Warn("Failed to join multicast group", attrs...)
			r.joinFailed[si.Name] = true
		}
		return
	}
	delete(r.joinFailed, si.Name)
	r.joined[si.Name] = si.Index
}

// leave drops the membership held for name at its old index, if any. A stale
// membership (the interface was deleted or recreated) still counts against
// net.ipv4.igmp_max_memberships, so without this enough recreations make
// every later join fail with ENOBUFS.
func (r *Reflector) leave(name string) {
	idx, ok := r.joined[name]
	if !ok {
		return
	}
	if err := r.pc.LeaveGroup(&net.Interface{Index: idx}, mdnsGroup); err != nil {
		slog.Debug("Leaving stale multicast membership failed", "interface", name, "index", idx, "error", err)
	}
	delete(r.joined, name)
}

func ipv4Prefix(a net.Addr) (netip.Prefix, bool) {
	ipn, ok := a.(*net.IPNet)
	if !ok {
		return netip.Prefix{}, false
	}
	ip4 := ipn.IP.To4()
	if ip4 == nil {
		return netip.Prefix{}, false
	}
	ones, bits := ipn.Mask.Size()
	if bits != 32 {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(netip.AddrFrom4([4]byte(ip4)), ones), true
}
