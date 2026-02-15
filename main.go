package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

const (
	mDNSAddr = "224.0.0.251:5353"
)

func getMsgSummary(msg *dns.Msg) string {
	if !msg.Response {
		var qStrs []string
		for _, q := range msg.Question {
			qStrs = append(qStrs, fmt.Sprintf("%s (%s)", q.Name, dns.TypeToString[q.Qtype]))
		}
		if len(qStrs) > 3 {
			return fmt.Sprintf("Questions: [%s ... +%d more]", strings.Join(qStrs[:3], ", "), len(qStrs)-3)
		}
		return "Questions: [" + strings.Join(qStrs, ", ") + "]"
	}

	var aStrs []string
	// Combine Answer and Extra records for a better overview
	records := append(msg.Answer, msg.Extra...)
	for _, a := range records {
		aStrs = append(aStrs, fmt.Sprintf("%s (%s)", a.Header().Name, dns.TypeToString[a.Header().Rrtype]))
	}

	if len(aStrs) > 3 {
		return fmt.Sprintf("Records: [%s ... +%d more]", strings.Join(aStrs[:3], ", "), len(aStrs)-3)
	}
	if len(aStrs) == 0 {
		return "No records"
	}
	return "Records: [" + strings.Join(aStrs, ", ") + "]"
}

type Reflector struct {
	config     *Config
	conn       *ipv4.PacketConn
	ifaceMap   map[string]string   // interface name -> group name
	ifaceIndex map[int]string      // index -> name
	groupMap   map[string][]string // group name -> list of interface names

	// Stateful tracking: map[ifaceName] -> Last time a query was seen
	recentQueries map[string]time.Time
	mu            sync.Mutex
}

func NewReflector(cfg *Config) *Reflector {
	r := &Reflector{
		config:        cfg,
		ifaceMap:      make(map[string]string),
		ifaceIndex:    make(map[int]string),
		groupMap:      make(map[string][]string),
		recentQueries: make(map[string]time.Time),
	}

	for _, iface := range cfg.Interfaces {
		r.ifaceMap[iface.Name] = iface.Group
		r.groupMap[iface.Group] = append(r.groupMap[iface.Group], iface.Name)
	}

	return r
}

func (r *Reflector) Start() error {
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
			log.Printf("Error finding interface %s: %v", ifaceName, err)
			continue
		}
		r.ifaceIndex[iface.Index] = ifaceName

		if err := p.JoinGroup(iface, addr); err != nil {
			log.Printf("Error joining multicast group on %s: %v", ifaceName, err)
			continue
		}
	}

	r.conn = p
	go r.listen()
	return nil
}

func (r *Reflector) listen() {
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := r.conn.ReadFrom(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		if cm == nil {
			continue
		}

		srcIface := r.ifaceIndex[cm.IfIndex]
		if srcIface == "" {
			continue // Packet from an interface we don't care about
		}

		srcUDP := src.(*net.UDPAddr)
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}

		r.handlePacket(srcIface, buf[:n], msg, srcUDP.IP)
	}
}

func (r *Reflector) handlePacket(srcIface string, data []byte, msg *dns.Msg, srcIP net.IP) {
	srcGroup := r.ifaceMap[srcIface]

	// Track queries
	if !msg.Response {
		r.mu.Lock()
		r.recentQueries[srcIface] = time.Now()
		r.mu.Unlock()

		// FORCE MULTICAST RESPONSES:
		// Clear the QU (Unicast Response) bit in all questions.
		// This ensures that TVs and other devices "shout" their answer on the
		// multicast address so that the reflector can hear and forward it.
		modified := false
		for i := range msg.Question {
			if msg.Question[i].Qclass&0x8000 != 0 {
				msg.Question[i].Qclass &= 0x7FFF
				modified = true
			}
		}
		if modified {
			if newData, err := msg.Pack(); err == nil {
				data = newData
			}
		}
	}

	for _, rule := range r.config.Rules {
		if rule.From != srcGroup {
			continue
		}

		// 1. Type Filtering
		isResponse := msg.Response || len(msg.Answer) > 0

		if len(rule.Types) > 0 {
			match := false
			typeName := "query"
			if isResponse {
				typeName = "response"
			}
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
			// Check if ANY question in the query matches our allowed services
			for _, q := range msg.Question {
				// A: Match against the allowed service list (e.g. "_airplay._tcp")
				for _, service := range rule.Filter.AllowedServices {
					if strings.Contains(q.Name, service) {
						allowed = true
						break
					}
				}

				// B: Allow hostname resolution and reverse lookups.
				// Hostnames end in .local. and don't have underscores.
				// Reverse lookups end in .arpa.
				if !allowed {
					isHostname := strings.HasSuffix(q.Name, ".local.") && !strings.Contains(q.Name, "_")
					isReverse := strings.HasSuffix(q.Name, ".in-addr.arpa.") || strings.HasSuffix(q.Name, ".ip6.arpa.")
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
				if destIfaceName == srcIface {
					continue
				}

				// STATEFUL OPTIMIZATION:
				if isResponse && destGroup == "users" {
					r.mu.Lock()
					lastQuery, ok := r.recentQueries[destIfaceName]
					r.mu.Unlock()

					if !ok || time.Since(lastQuery) > 60*time.Second {
						continue
					}
				}

				log.Printf("Reflecting %s from %s (%s) to %s (%s) - %s",
					func() string {
						if isResponse {
							return "Response"
						}
						return "Query"
					}(),
					srcIP, srcIface, destIfaceName, destGroup,
					getMsgSummary(msg))
				r.forward(destIfaceName, data)
			}
		}
	}
}
func (r *Reflector) forward(ifaceName string, data []byte) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return
	}

	cm := &ipv4.ControlMessage{IfIndex: iface.Index}
	dst, _ := net.ResolveUDPAddr("udp4", mDNSAddr)

	if _, err := r.conn.WriteTo(data, cm, dst); err != nil {
		log.Printf("Error forwarding to %s: %v", ifaceName, err)
	}
}

func main() {
	cfg, err := LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	log.Printf("mDNS Reflector starting with %d interfaces", len(cfg.Interfaces))
	for i, rule := range cfg.Rules {
		log.Printf("Rule %d: From:%s To:%v Types:%v Filters:%d IPs",
			i, rule.From, rule.To, rule.Types, len(rule.Filter.AllowedIPs))
	}

	reflector := NewReflector(cfg)
	if err := reflector.Start(); err != nil {
		log.Fatalf("Error starting reflector: %v", err)
	}

	log.Printf("mDNS Reflector started with %d interfaces", len(cfg.Interfaces))

	// Keep main goroutine alive
	select {}
}
