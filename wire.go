package main

// Raw-bytes handling of mDNS packets.
//
// The reflector forwards the bytes it received, changed as little as possible.
// Re-packing through a DNS library is not safe here (dns v2 Pack writes one
// question while keeping Qdcount=N, and re-packing reorders or drops EDNS
// data), so the few rewrites the reflector makes — clearing the QU bit and
// dropping address records — are done on the wire bytes. scanMsg validates the
// whole message first; a packet it rejects is dropped, never forwarded
// partially modified.

import (
	"errors"
	"net/netip"
)

const (
	headerLen = 12

	typeA    = 1
	typeAAAA = 28

	sectionAnswer     = 0
	sectionAuthority  = 1
	sectionAdditional = 2

	maxNameLen  = 255
	maxPtrHops  = 64
	minQuestion = 5  // root name + type + class
	minRR       = 11 // root name + type + class + ttl + rdlength
)

var (
	errMalformed = errors.New("malformed packet")
	// errUnsafeRemove means a compression pointer elsewhere in the message
	// points into a record that would be removed.
	errUnsafeRemove = errors.New("record is a compression target")
)

type wireQuestion struct {
	name     []byte // canonical name: lower-case wire format, uncompressed
	qtype    uint16
	classOff int // offset of the 2-byte qclass
}

type wireRR struct {
	start, end int // the whole record, owner name to end of rdata
	section    int
	rrtype     uint16
	rdata      int // offset of rdata
	rdlen      int
	name       []byte // canonical owner name; only set for the answer section
}

type wireMsg struct {
	response   bool
	questions  []wireQuestion
	rrs        []wireRR // answer, authority, additional, in wire order
	names      []int    // offset of every name: questions, owners, rdata names
	compressed bool     // some name uses a compression pointer
}

// scanMsg validates data as a DNS message and indexes it: every question,
// every record, and every name, in owner names and in the rdata of the record
// types that may carry compressed names (RFC 3597 §4: no other type may). It rejects truncated names, pointer loops, forward or header
// pointers, rdata overruns and trailing bytes.
func scanMsg(data []byte) (*wireMsg, error) {
	if len(data) < headerLen {
		return nil, errMalformed
	}
	m := &wireMsg{response: data[2]&0x80 != 0}
	qd := int(data[4])<<8 | int(data[5])
	counts := [3]int{
		int(data[6])<<8 | int(data[7]),
		int(data[8])<<8 | int(data[9]),
		int(data[10])<<8 | int(data[11]),
	}
	// Counts are attacker-controlled: never allocate more than the bytes allow.
	rest := len(data) - headerLen
	if qd*minQuestion > rest || (counts[0]+counts[1]+counts[2])*minRR > rest {
		return nil, errMalformed
	}
	m.questions = make([]wireQuestion, 0, qd)
	m.rrs = make([]wireRR, 0, counts[0]+counts[1]+counts[2])

	off := headerLen
	for range qd {
		name, end, err := m.name(data, off, true)
		if err != nil {
			return nil, err
		}
		if end+4 > len(data) {
			return nil, errMalformed
		}
		m.questions = append(m.questions, wireQuestion{
			name:     name,
			qtype:    uint16(data[end])<<8 | uint16(data[end+1]),
			classOff: end + 2,
		})
		off = end + 4
	}
	for section, n := range counts {
		for range n {
			rr := wireRR{start: off, section: section}
			name, end, err := m.name(data, off, section == sectionAnswer)
			if err != nil {
				return nil, err
			}
			rr.name = name
			if end+10 > len(data) {
				return nil, errMalformed
			}
			rr.rrtype = uint16(data[end])<<8 | uint16(data[end+1])
			rr.rdlen = int(data[end+8])<<8 | int(data[end+9])
			rr.rdata = end + 10
			rr.end = rr.rdata + rr.rdlen
			if rr.end > len(data) {
				return nil, errMalformed
			}
			if (rr.rrtype == typeA && rr.rdlen != 4) || (rr.rrtype == typeAAAA && rr.rdlen != 16) {
				return nil, errMalformed
			}
			if err := m.rdataNames(data, rr); err != nil {
				return nil, err
			}
			m.rrs = append(m.rrs, rr)
			off = rr.end
		}
	}
	if off != len(data) {
		return nil, errMalformed
	}
	return m, nil
}

// rdataNames walks the compressible names inside rr's rdata so that they are
// recorded and checked, and checks that they fit the rdata.
func (m *wireMsg) rdataNames(data []byte, rr wireRR) error {
	// Layout: fixed bytes before the first name, number of names, and whether
	// the names must end exactly at the end of the rdata.
	var skip, names int
	exact := true
	switch rr.rrtype {
	case 2, 3, 4, 5, 7, 8, 9, 12, 39: // NS MD MF CNAME MB MG MR PTR DNAME
		names = 1
	case 15, 18, 21, 36: // MX AFSDB RT KX
		skip, names = 2, 1
	case 33: // SRV
		skip, names = 6, 1
	case 14, 17: // MINFO RP
		names = 2
	case 26: // PX
		skip, names = 2, 2
	case 6: // SOA: two names then 20 bytes
		names, exact = 2, false
	case 47: // NSEC: next name then type bitmap
		names, exact = 1, false
	default:
		return nil // opaque rdata
	}
	end := rr.rdata + rr.rdlen
	off := rr.rdata + skip
	if off > end {
		return errMalformed
	}
	for range names {
		_, next, err := m.name(data[:end], off, false)
		if err != nil {
			return err
		}
		off = next
	}
	if exact && off != end {
		return errMalformed
	}
	if rr.rrtype == 6 && off+20 != end {
		return errMalformed
	}
	return nil
}

// name reads the name at off, records it, and returns the offset just past
// it in the message. It follows pointers to
// validate the full name; with want set it also returns the canonical form.
// Pointer targets are resolved in data, which may be cut short at the end of
// the enclosing rdata; targets always lie earlier in the message.
func (m *wireMsg) name(data []byte, off int, want bool) ([]byte, int, error) {
	var out []byte
	if want {
		out = make([]byte, 0, 32)
	}
	m.names = append(m.names, off)
	end := -1
	total := 0
	hops := 0
	pos := off
	for {
		if pos >= len(data) {
			return nil, 0, errMalformed
		}
		b := data[pos]
		switch {
		case b == 0:
			if end < 0 {
				end = pos + 1
			}
			total++
			if total > maxNameLen {
				return nil, 0, errMalformed
			}
			if want {
				out = append(out, 0)
			}
			return out, end, nil
		case b&0xC0 == 0xC0:
			if pos+1 >= len(data) {
				return nil, 0, errMalformed
			}
			target := int(b&0x3F)<<8 | int(data[pos+1])
			// Only backward pointers past the header: this rules out loops
			// together with the hop limit, and keeps pointer fix-ups simple.
			if target < headerLen || target >= pos {
				return nil, 0, errMalformed
			}
			if end < 0 {
				end = pos + 2
			}
			m.compressed = true
			hops++
			if hops > maxPtrHops {
				return nil, 0, errMalformed
			}
			pos = target
		case b&0xC0 != 0:
			return nil, 0, errMalformed // extended label types are not used
		default:
			l := int(b)
			if pos+1+l > len(data) {
				return nil, 0, errMalformed
			}
			total += 1 + l
			if total > maxNameLen {
				return nil, 0, errMalformed
			}
			if want {
				out = append(out, b)
				for _, c := range data[pos+1 : pos+1+l] {
					if 'A' <= c && c <= 'Z' {
						c += 'a' - 'A'
					}
					out = append(out, c)
				}
			}
			pos += 1 + l
		}
	}
}

// stripQU clears the QU (unicast-response) bit of every question in place.
// It reports whether anything changed. data must be the buffer m was scanned
// from.
func (m *wireMsg) stripQU(data []byte) bool {
	changed := false
	for _, q := range m.questions {
		if data[q.classOff]&0x80 != 0 {
			data[q.classOff] &^= 0x80
			changed = true
		}
	}
	return changed
}

// aAddr returns the IPv4 address of an A record, or false if rr is not one.
func (rr wireRR) aAddr(data []byte) (netip.Addr, bool) {
	if rr.rrtype != typeA || rr.rdlen != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(data[rr.rdata : rr.rdata+4])), true
}

// removeRRs returns a copy of data without the records whose indexes in m.rrs
// are set in drop, with the section counts and every surviving compression
// pointer adjusted. It returns errUnsafeRemove if a surviving name reaches
// into a removed record, directly or through a pointer chain.
func (m *wireMsg) removeRRs(data []byte, drop []bool) ([]byte, error) {
	type region struct{ start, end int }
	var cut []region
	var removed [3]int
	for i, rr := range m.rrs {
		if drop[i] {
			cut = append(cut, region{rr.start, rr.end})
			removed[rr.section]++
		}
	}
	if len(cut) == 0 {
		return data, nil
	}
	overlaps := func(start, end int) bool {
		for _, c := range cut {
			if start < c.end && c.start < end {
				return true
			}
		}
		return false
	}
	// shift(o) is the number of removed bytes before offset o, which must not
	// lie inside a removed record. Regions are in wire order.
	shift := func(o int) int {
		s := 0
		for _, c := range cut {
			if o < c.start {
				break
			}
			s += c.end - c.start
		}
		return s
	}

	// Walk every name that survives (scanMsg has validated them all) and
	// collect the pointers it uses, at every hop.
	ptrs := make(map[int]struct{})
	for _, o := range m.names {
		if overlaps(o, o+1) {
			continue // the name is removed with its record
		}
		pos := o
		for {
			b := data[pos]
			if b == 0 {
				if overlaps(pos, pos+1) {
					return nil, errUnsafeRemove
				}
				break
			}
			if b&0xC0 == 0xC0 {
				if overlaps(pos, pos+2) {
					return nil, errUnsafeRemove
				}
				ptrs[pos] = struct{}{}
				pos = int(b&0x3F)<<8 | int(data[pos+1])
				continue
			}
			if overlaps(pos, pos+1+int(b)) {
				return nil, errUnsafeRemove
			}
			pos += 1 + int(b)
		}
	}

	out := make([]byte, 0, len(data))
	prev := 0
	for _, c := range cut {
		out = append(out, data[prev:c.start]...)
		prev = c.end
	}
	out = append(out, data[prev:]...)

	for p := range ptrs {
		target := int(data[p]&0x3F)<<8 | int(data[p+1])
		nt := target - shift(target)
		np := p - shift(p)
		out[np] = 0xC0 | byte(nt>>8)
		out[np+1] = byte(nt)
	}
	for s, n := range removed {
		i := 6 + 2*s
		c := int(out[i])<<8 | int(out[i+1]) - n
		out[i], out[i+1] = byte(c>>8), byte(c)
	}
	return out, nil
}
