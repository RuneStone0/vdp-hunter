// Package dnsq is a minimal DNS client: A queries over UDP, no dependencies.
//
// net.Resolver would do, but it hides the query shape and adds a goroutine per
// lookup plus cgo on some builds. At a few thousand queries a second the cost of
// that is measurable, and this scanner only ever needs to know "does this name
// have an address".
package dnsq

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"time"
)

var ErrNoAnswer = errors.New("no address")

// Client queries a fixed list of resolvers, rotating, so one slow server cannot
// stall the whole pass.
type Client struct {
	Resolvers []string
	Timeout   time.Duration
}

func New(resolvers []string, timeout time.Duration) *Client {
	if len(resolvers) == 0 {
		resolvers = []string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53"}
	}
	return &Client{Resolvers: resolvers, Timeout: timeout}
}

// Resolve returns the first A record the resolver hands back.
//
// The address matters as much as the verdict: the port check dials this IP
// directly instead of asking the system resolver a second time per name, which
// both halves the lookups and keeps the two stages from disagreeing.
func (c *Client) Resolve(name string) (string, bool, error) {
	q, id, err := buildQuery(name)
	if err != nil {
		return "", false, err
	}
	server := c.Resolvers[rand.Intn(len(c.Resolvers))]
	conn, err := net.DialTimeout("udp", server, c.Timeout)
	if err != nil {
		return "", false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err := conn.Write(q); err != nil {
		return "", false, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return "", false, err
		}
		ip, match, err := parseResponse(buf[:n], id)
		if err != nil {
			return "", false, err
		}
		if match {
			return ip, ip != "", nil
		}
	}
}

func buildQuery(name string) ([]byte, uint16, error) {
	if len(name) == 0 || len(name) > 253 {
		return nil, 0, errors.New("bad name")
	}
	id := uint16(rand.Intn(65536))
	buf := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(buf[0:], id)
	binary.BigEndian.PutUint16(buf[2:], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(buf[4:], 1)      // one question
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i == start {
				return nil, 0, errors.New("empty label")
			}
			label := name[start:i]
			if len(label) > 63 {
				return nil, 0, errors.New("long label")
			}
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
			start = i + 1
		}
	}
	buf = append(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, 1) // A
	buf = binary.BigEndian.AppendUint16(buf, 1) // IN
	return buf, id, nil
}

// parseResponse walks the answer section and reports whether any A record exists.
func parseResponse(msg []byte, id uint16) (ip string, match bool, err error) {
	if len(msg) < 12 {
		return "", false, errors.New("short")
	}
	if binary.BigEndian.Uint16(msg[0:]) != id {
		return "", false, nil
	}
	rcode := msg[3] & 0x0f
	if rcode != 0 { // NXDOMAIN is a normal answer for us
		return "", true, nil
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	ns := int(binary.BigEndian.Uint16(msg[8:]))
	ar := int(binary.BigEndian.Uint16(msg[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		off, err = skipName(msg, off)
		if err != nil {
			return "", true, err
		}
		off += 4
	}
	// A CNAME answer often carries the target's address only in the additional
	// section, so every section is walked for A records, not just the answer.
	for i := 0; i < an+ns+ar; i++ {
		off, err = skipName(msg, off)
		if err != nil {
			return "", true, err
		}
		if off+10 > len(msg) {
			return "", true, errors.New("short rr")
		}
		rtype := binary.BigEndian.Uint16(msg[off:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		if rtype == 1 && rdlen == 4 && off+10+4 <= len(msg) {
			return net.IP(msg[off+10 : off+14]).String(), true, nil
		}
		off += 10 + rdlen
	}
	return "", true, nil
}

func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("short name")
		}
		l := int(msg[off])
		if l == 0 {
			return off + 1, nil
		}
		if l&0xc0 == 0xc0 {
			return off + 2, nil
		}
		off += 1 + l
	}
}
