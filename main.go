package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/net/ipv4"
)

const (
	mDNSAddr = "224.0.0.251:5353"
)

func setupLogger(level string) {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove timestamp — journald provides it
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(handler))
}

func getMsgSummary(msg *dns.Msg) string {
	if !msg.Response {
		var qStrs []string
		for _, q := range msg.Question {
			qStrs = append(qStrs, fmt.Sprintf("%s (%s)", q.Header().Name, dns.TypeToString[dns.RRToType(q)]))
		}
		if len(qStrs) > 3 {
			return fmt.Sprintf("Questions: [%s ... +%d more]", strings.Join(qStrs[:3], ", "), len(qStrs)-3)
		}
		return "Questions: [" + strings.Join(qStrs, ", ") + "]"
	}

	var aStrs []string
	// Combine Answer and Extra records for a better overview
	records := make([]dns.RR, 0, len(msg.Answer)+len(msg.Extra))
	records = append(records, msg.Answer...)
	records = append(records, msg.Extra...)
	for _, a := range records {
		aStrs = append(aStrs, fmt.Sprintf("%s (%s)", a.Header().Name, dns.TypeToString[dns.RRToType(a)]))
	}

	if len(aStrs) > 3 {
		return fmt.Sprintf("Records: [%s ... +%d more]", strings.Join(aStrs[:3], ", "), len(aStrs)-3)
	}
	if len(aStrs) == 0 {
		return "No records"
	}
	return "Records: [" + strings.Join(aStrs, ", ") + "]"
}

const maxListenerRestarts = 5

type Reflector struct {
	config     *Config
	conn       *ipv4.PacketConn
	ifaceMap   map[string]string   // interface name -> group name
	ifaceIndex map[int]string      // index -> name
	groupMap   map[string][]string // group name -> list of interface names

	// Stateful tracking: map[ifaceName] -> Last time a query was seen
	recentQueries map[string]time.Time
	mu            sync.Mutex

	// forwarder is the function called to actually send a packet.
	// We use a field here so it can be mocked in unit tests.
	forwarder func(ifaceName string, data []byte)

	done chan struct{}
}

func NewReflector(cfg *Config) *Reflector {
	r := &Reflector{
		config:        cfg,
		ifaceMap:      make(map[string]string),
		ifaceIndex:    make(map[int]string),
		groupMap:      make(map[string][]string),
		recentQueries: make(map[string]time.Time),
		done:          make(chan struct{}),
	}

	r.forwarder = r.forward // Set the default implementation

	for _, iface := range cfg.Interfaces {
		r.ifaceMap[iface.Name] = iface.Group
		r.groupMap[iface.Group] = append(r.groupMap[iface.Group], iface.Name)
	}

	return r
}

func (r *Reflector) Start() error {
	if len(r.ifaceMap) == 0 {
		return fmt.Errorf("no interfaces configured")
	}

	c, err := net.ListenPacket("udp4", ":5353")
	if err != nil {
		return err
	}

	p := ipv4.NewPacketConn(c)
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return err
	}

	addr, err := net.ResolveUDPAddr("udp4", mDNSAddr)
	if err != nil {
		return err
	}

	for ifaceName := range r.ifaceMap {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			slog.Warn("Interface not found", "interface", ifaceName, "error", err)
			continue
		}
		r.ifaceIndex[iface.Index] = ifaceName

		if err := p.JoinGroup(iface, addr); err != nil {
			slog.Warn("Failed to join multicast group", "interface", ifaceName, "error", err)
			continue
		}
	}

	r.conn = p
	go r.listen()
	return nil
}

func (r *Reflector) listen() {
	restarts := 0
	for {
		r.listenLoop()

		// Check if we were told to stop
		select {
		case <-r.done:
			return
		default:
		}

		restarts++
		if restarts > maxListenerRestarts {
			slog.Error("Listener has restarted too many times, giving up", "max_restarts", maxListenerRestarts)
			return
		}
		backoff := time.Duration(restarts) * time.Second
		slog.Warn("Listener restarting", "attempt", restarts, "max", maxListenerRestarts, "backoff", backoff)
		time.Sleep(backoff)
	}
}

func (r *Reflector) listenLoop() {
	defer func() {
		if err := recover(); err != nil {
			slog.Error("Recovered from panic in listener", "error", err)
		}
	}()

	buf := make([]byte, 9000)
	for {
		n, cm, src, err := r.conn.ReadFrom(buf)
		if err != nil {
			slog.Error("Read error", "error", err)
			return
		}

		if cm == nil {
			continue
		}

		srcIface := r.ifaceIndex[cm.IfIndex]
		if srcIface == "" {
			continue // Packet from an interface we don't care about
		}

		srcUDP, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		msg := new(dns.Msg)
		msg.Data = buf[:n]
		if err := msg.Unpack(); err != nil {
			continue
		}

		r.handlePacket(srcIface, buf[:n], msg, srcUDP.IP)
	}
}

func (r *Reflector) handlePacket(srcIface string, data []byte, msg *dns.Msg, srcIP net.IP) {
	srcGroup := r.ifaceMap[srcIface]

	// Keep track of which interfaces we have already reflected to for THIS packet
	// to prevent duplicates if multiple rules match.
	reflectedTo := make(map[string]bool)

	// Track queries
	if !msg.Response {
		r.mu.Lock()
		r.recentQueries[srcIface] = time.Now()
		r.mu.Unlock()

		// FORCE MULTICAST RESPONSES:
		// Many mDNS clients (like Apple devices and Avahi) set the "QU" (Unicast Response) bit
		// in their queries (RFC 6762). When this bit is set, the service (e.g., a TV or printer)
		// will attempt to respond directly to the client's IP address via Unicast.
		//
		// In a multi-VLAN environment, this is problematic: the Unicast response would be
		// sent to the client's IP in a different subnet, bypassing this reflector and
		// likely being blocked by the network firewall.
		//
		// By clearing the QU bit (the top bit of the Qclass field), we force the device
		// to respond via Multicast. This ensures the response is sent to the 224.0.0.251
		// address on its local segment, allowing this reflector to "hear" the response
		// and forward it back to the original VLAN.
		modified := false
		for i := range msg.Question {
			if msg.Question[i].Header().Class&0x8000 != 0 {
				msg.Question[i].Header().Class &= 0x7FFF
				modified = true
			}
		}
		if modified {
			if err := msg.Pack(); err == nil {
				data = msg.Data
			}
		}
	}

	for _, rule := range r.config.Rules {
		if rule.From != srcGroup {
			continue
		}

		// 1. Type Filtering (Strictly use the msg.Response flag)
		typeName := "query"
		if msg.Response {
			typeName = "response"
		}

		if len(rule.Types) > 0 {
			match := false
			for _, t := range rule.Types {
				if t == typeName {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		// 2. IP Filtering
		if len(rule.Filter.AllowedIPs) > 0 {
			allowed := false
			for _, ip := range rule.Filter.AllowedIPs {
				if srcIP.String() == ip {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}

		// 3. Service Type Filtering (for Queries)
		if !msg.Response && len(rule.Filter.AllowedServices) > 0 {
			allowed := false
			for _, q := range msg.Question {
				for _, service := range rule.Filter.AllowedServices {
					if strings.Contains(q.Header().Name, service) {
						allowed = true
						break
					}
				}
				if !allowed {
					isHostname := strings.HasSuffix(q.Header().Name, ".local.") && !strings.Contains(q.Header().Name, "_")
					isReverse := strings.HasSuffix(q.Header().Name, ".in-addr.arpa.") || strings.HasSuffix(q.Header().Name, ".ip6.arpa.")
					if isHostname || isReverse {
						allowed = true
					}
				}
				if allowed {
					break
				}
			}
			if !allowed {
				continue
			}
		}

		// 4. Reflect to target groups
		for _, destGroup := range rule.To {
			for _, destIfaceName := range r.groupMap[destGroup] {
				if destIfaceName == srcIface || reflectedTo[destIfaceName] {
					continue
				}

				// STATEFUL OPTIMIZATION:
				// If the rule is marked as stateful,
				// ONLY send responses to interfaces that have sent a recent query.
				if msg.Response && rule.Stateful {
					window := time.Duration(rule.StatefulWindow) * time.Second
					r.mu.Lock()
					lastQuery, ok := r.recentQueries[destIfaceName]
					r.mu.Unlock()

					if !ok || time.Since(lastQuery) > window {
						continue
					}
				}

				reflectedTo[destIfaceName] = true
				if msg.Response {
					slog.Info("Service response reflected",
						"src_ip", srcIP,
						"from", srcIface,
						"from_group", srcGroup,
						"to", destIfaceName,
						"to_group", destGroup,
						"records", getMsgSummary(msg),
					)
				} else {
					slog.Debug("Query reflected",
						"src_ip", srcIP,
						"from", srcIface,
						"from_group", srcGroup,
						"to", destIfaceName,
						"to_group", destGroup,
						"questions", getMsgSummary(msg),
					)
				}
				r.forwarder(destIfaceName, data)
			}
		}
	}
}

func (r *Reflector) Stop() {
	close(r.done)
	if r.conn != nil {
		r.conn.Close()
	}
}

func (r *Reflector) forward(ifaceName string, data []byte) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return
	}

	cm := &ipv4.ControlMessage{IfIndex: iface.Index}
	dst, err := net.ResolveUDPAddr("udp4", mDNSAddr)
	if err != nil {
		slog.Error("Failed to resolve mDNS address", "error", err)
		return
	}

	if _, err := r.conn.WriteTo(data, cm, dst); err != nil {
		slog.Error("Failed to forward packet", "interface", ifaceName, "error", err)
	}
}

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	setupLogger(cfg.LogLevel)

	slog.Info("mDNS Reflector starting", "interfaces", len(cfg.Interfaces))
	for i, rule := range cfg.Rules {
		slog.Info("Rule loaded",
			"rule", i,
			"from", rule.From,
			"to", rule.To,
			"types", rule.Types,
			"allowed_ips", len(rule.Filter.AllowedIPs),
			"stateful", rule.Stateful,
		)
	}

	reflector := NewReflector(cfg)
	if err := reflector.Start(); err != nil {
		log.Fatalf("Error starting reflector: %v", err)
	}

	slog.Info("mDNS Reflector started", "interfaces", len(cfg.Interfaces))

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	slog.Info("Shutting down", "signal", sig)
	reflector.Stop()
}
