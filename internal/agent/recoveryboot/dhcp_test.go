// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

var (
	testMAC    = []byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	testServer = [4]byte{10, 0, 2, 2}
	testLeased = [4]byte{10, 0, 2, 15}
)

const testXID = 0x1badb002

type dhcpOption struct {
	code  byte
	value []byte
}

// testDHCPReply builds a BOOTREPLY with the given options followed by END.
func testDHCPReply(xid uint32, mac []byte, yiaddr [4]byte, options ...dhcpOption) []byte {
	packet := make([]byte, dhcpFixedBytes)
	packet[0], packet[1], packet[2] = 2, 1, 6
	binary.BigEndian.PutUint32(packet[4:], xid)
	copy(packet[16:], yiaddr[:])
	copy(packet[28:], mac)
	packet = append(packet, dhcpMagicCookie...)
	for _, option := range options {
		packet = append(packet, option.code, byte(len(option.value)))
		packet = append(packet, option.value...)
	}
	return append(packet, dhcpOptionEnd)
}

func standardReply(kind byte, extra ...dhcpOption) []byte {
	options := append([]dhcpOption{
		{dhcpOptionMessageType, []byte{kind}},
		{dhcpOptionServerID, testServer[:]},
		{dhcpOptionSubnetMask, []byte{255, 255, 255, 0}},
		{dhcpOptionRouter, []byte{10, 0, 2, 2, 10, 0, 2, 3}},
		{dhcpOptionDNS, []byte{10, 0, 2, 3, 1, 1, 1, 1}},
	}, extra...)
	return testDHCPReply(testXID, testMAC, testLeased, options...)
}

func TestParseDHCPReplyStrictness(t *testing.T) {
	reply, err := parseDHCPReply(standardReply(dhcpAck), testXID, testMAC)
	if err != nil || reply.Type != dhcpAck || reply.YourIP != testLeased || reply.ServerID != testServer || !reply.HasMask || len(reply.Routers) != 2 || len(reply.DNS) != 2 {
		t.Fatalf("valid ACK rejected: %+v %v", reply, err)
	}
	if _, err := parseDHCPReply(testDHCPReply(testXID, testMAC, [4]byte{}, dhcpOption{dhcpOptionMessageType, []byte{dhcpNak}}), testXID, testMAC); err != nil {
		t.Fatalf("NAK without address or server rejected: %v", err)
	}
	mutate := func(change func([]byte) []byte) []byte { return change(standardReply(dhcpOffer)) }
	for name, packet := range map[string][]byte{
		"truncated header":  standardReply(dhcpOffer)[:dhcpFixedBytes+2],
		"oversized":         append(standardReply(dhcpOffer), make([]byte, dhcpMaximumReply)...),
		"request op":        mutate(func(p []byte) []byte { p[0] = 1; return p }),
		"non-ethernet":      mutate(func(p []byte) []byte { p[1] = 6; return p }),
		"wrong xid":         testDHCPReply(testXID+1, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpOffer}}, dhcpOption{dhcpOptionServerID, testServer[:]}),
		"wrong chaddr":      testDHCPReply(testXID, []byte{1, 2, 3, 4, 5, 6}, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpOffer}}, dhcpOption{dhcpOptionServerID, testServer[:]}),
		"bad cookie":        mutate(func(p []byte) []byte { p[dhcpFixedBytes] = 0; return p }),
		"missing end":       mutate(func(p []byte) []byte { return p[:len(p)-1] }),
		"option overflow":   mutate(func(p []byte) []byte { return append(p[:len(p)-1], dhcpOptionDNS, 200, 1, 2, 3, 4) }),
		"truncated length":  mutate(func(p []byte) []byte { return append(p[:len(p)-1], dhcpOptionDNS) }),
		"duplicate option":  standardReply(dhcpOffer, dhcpOption{dhcpOptionDNS, []byte{8, 8, 8, 8}}),
		"option overload":   standardReply(dhcpOffer, dhcpOption{dhcpOptionOverload, []byte{3}}),
		"long message type": testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpOffer, 0}}, dhcpOption{dhcpOptionServerID, testServer[:]}),
		"missing type":      testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionServerID, testServer[:]}),
		"decline type":      standardReply(4),
		"offer without id":  testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpOffer}}),
		"zero address":      testDHCPReply(testXID, testMAC, [4]byte{}, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]}),
		"broadcast address": testDHCPReply(testXID, testMAC, [4]byte{255, 255, 255, 255}, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]}),
		"loopback address":  testDHCPReply(testXID, testMAC, [4]byte{127, 0, 0, 1}, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]}),
		"multicast server":  testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, []byte{224, 0, 0, 1}}),
		"short server id":   testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, []byte{10, 0, 2}}),
		"holey netmask":     testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]}, dhcpOption{dhcpOptionSubnetMask, []byte{255, 0, 255, 0}}),
		"zero netmask":      testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]}, dhcpOption{dhcpOptionSubnetMask, []byte{0, 0, 0, 0}}),
		"partial router":    testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]}, dhcpOption{dhcpOptionRouter, []byte{10, 0, 2, 2, 1}}),
		"empty dns":         testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]}, dhcpOption{dhcpOptionDNS, nil}),
		"broadcast dns":     testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]}, dhcpOption{dhcpOptionDNS, []byte{255, 255, 255, 255}}),
	} {
		if reply, err := parseDHCPReply(packet, testXID, testMAC); err == nil {
			t.Fatalf("%s accepted: %+v", name, reply)
		}
	}
	for _, mask := range [][4]byte{{255, 255, 255, 255}, {255, 255, 255, 252}, {128, 0, 0, 0}, {255, 255, 240, 0}} {
		if !contiguousNetmask(mask) {
			t.Fatalf("contiguous mask %v rejected", mask)
		}
	}
}

type dhcpEvent struct {
	packet  []byte
	length  int // reported length; larger than len(packet) means truncated
	timeout bool
}

// scriptedDHCP replies to each Send with the next scripted batch of events.
type scriptedDHCP struct {
	now       time.Time
	responses [][]dhcpEvent
	pending   []dhcpEvent
	sent      [][]byte
	deadlines []time.Duration
}

func (s *scriptedDHCP) Send(packet []byte) error {
	s.sent = append(s.sent, bytes.Clone(packet))
	s.pending = nil
	if len(s.responses) != 0 {
		s.pending, s.responses = s.responses[0], s.responses[1:]
	}
	return nil
}

func (s *scriptedDHCP) Receive(buffer []byte, deadline time.Time) (int, error) {
	s.deadlines = append(s.deadlines, deadline.Sub(s.now))
	if len(s.pending) == 0 {
		return 0, errDHCPTimeout
	}
	event := s.pending[0]
	s.pending = s.pending[1:]
	if event.timeout {
		return 0, errDHCPTimeout
	}
	n := copy(buffer, event.packet)
	if event.length > n {
		return event.length, nil
	}
	return n, nil
}

func (s *scriptedDHCP) clock() time.Time { return s.now }

func requestOption(t *testing.T, packet []byte, code byte) []byte {
	t.Helper()
	for i := dhcpMinimumReply; i < len(packet) && packet[i] != dhcpOptionEnd; {
		if packet[i] == dhcpOptionPad {
			i++
			continue
		}
		if packet[i] == code {
			return packet[i+2 : i+2+int(packet[i+1])]
		}
		i += 2 + int(packet[i+1])
	}
	return nil
}

func TestAcquireDHCPLeaseExchange(t *testing.T) {
	conn := &scriptedDHCP{now: time.Unix(1700000000, 0), responses: [][]dhcpEvent{
		{
			{packet: testDHCPReply(testXID+1, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpOffer}}, dhcpOption{dhcpOptionServerID, testServer[:]})},
			{packet: standardReply(dhcpOffer), length: dhcpMaximumReply + 1},
			{packet: []byte("garbage")},
			{packet: standardReply(dhcpAck)},
			{packet: standardReply(dhcpOffer)},
		},
		{
			{packet: standardReply(dhcpOffer)},
			{packet: testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, []byte{10, 0, 2, 9}})},
			{packet: testDHCPReply(testXID, testMAC, [4]byte{10, 0, 2, 99}, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]})},
			{packet: testDHCPReply(testXID, testMAC, [4]byte{}, dhcpOption{dhcpOptionMessageType, []byte{dhcpNak}}, dhcpOption{dhcpOptionServerID, []byte{10, 0, 2, 9}})},
			{packet: standardReply(dhcpAck)},
		},
	}}
	lease, err := acquireDHCPLease(conn, testMAC, testXID, conn.clock)
	if err != nil {
		t.Fatal(err)
	}
	want := dhcpLease{Address: testLeased, Netmask: [4]byte{255, 255, 255, 0}, Router: testServer, HasRouter: true, DNS: [][4]byte{{10, 0, 2, 3}, {1, 1, 1, 1}}}
	if lease.Address != want.Address || lease.Netmask != want.Netmask || lease.Router != want.Router || !lease.HasRouter || len(lease.DNS) != 2 || lease.DNS[1] != want.DNS[1] {
		t.Fatalf("lease = %+v", lease)
	}
	if len(conn.sent) != 2 {
		t.Fatalf("sent %d packets", len(conn.sent))
	}
	for i, kind := range []byte{dhcpDiscover, dhcpRequest} {
		packet := conn.sent[i]
		if len(packet) < dhcpMinimumRequest || packet[0] != 1 || binary.BigEndian.Uint32(packet[4:]) != testXID || binary.BigEndian.Uint16(packet[10:]) != dhcpBroadcastFlag || !bytes.Equal(packet[28:34], testMAC) {
			t.Fatalf("packet %d header invalid", i)
		}
		if got := requestOption(t, packet, dhcpOptionMessageType); !bytes.Equal(got, []byte{kind}) {
			t.Fatalf("packet %d type %v", i, got)
		}
		if got := requestOption(t, packet, dhcpOptionClientID); !bytes.Equal(got, append([]byte{1}, testMAC...)) {
			t.Fatalf("packet %d client id %v", i, got)
		}
	}
	if !bytes.Equal(requestOption(t, conn.sent[1], dhcpOptionRequestedIP), testLeased[:]) || !bytes.Equal(requestOption(t, conn.sent[1], dhcpOptionServerID), testServer[:]) {
		t.Fatal("REQUEST does not select the offered lease")
	}
	for _, deadline := range conn.deadlines {
		if deadline != dhcpReplyTimeout {
			t.Fatalf("reply wait %v, want %v", deadline, dhcpReplyTimeout)
		}
	}
}

func TestAcquireDHCPLeaseBounds(t *testing.T) {
	t.Run("no offer", func(t *testing.T) {
		conn := &scriptedDHCP{}
		if _, err := acquireDHCPLease(conn, testMAC, testXID, conn.clock); !errors.Is(err, errDHCPNoLease) {
			t.Fatalf("err = %v", err)
		}
		if len(conn.sent) != dhcpDiscoverAttempts || len(conn.deadlines) != dhcpDiscoverAttempts {
			t.Fatalf("sent %d DISCOVERs, waited %d times", len(conn.sent), len(conn.deadlines))
		}
	})
	t.Run("no ack", func(t *testing.T) {
		conn := &scriptedDHCP{responses: [][]dhcpEvent{{{timeout: true}}, {{packet: standardReply(dhcpOffer)}}}}
		if _, err := acquireDHCPLease(conn, testMAC, testXID, conn.clock); !errors.Is(err, errDHCPNoLease) {
			t.Fatalf("err = %v", err)
		}
		if len(conn.sent) != 2+dhcpRequestAttempts {
			t.Fatalf("sent %d packets", len(conn.sent))
		}
	})
	t.Run("nak", func(t *testing.T) {
		conn := &scriptedDHCP{responses: [][]dhcpEvent{{{packet: standardReply(dhcpOffer)}}, {{packet: testDHCPReply(testXID, testMAC, [4]byte{}, dhcpOption{dhcpOptionMessageType, []byte{dhcpNak}}, dhcpOption{dhcpOptionServerID, testServer[:]})}}}}
		if _, err := acquireDHCPLease(conn, testMAC, testXID, conn.clock); !errors.Is(err, errDHCPNak) {
			t.Fatalf("err = %v", err)
		}
		if len(conn.sent) != 2 {
			t.Fatalf("NAK did not end the exchange: sent %d", len(conn.sent))
		}
	})
	t.Run("defaults", func(t *testing.T) {
		ack := testDHCPReply(testXID, testMAC, testLeased, dhcpOption{dhcpOptionMessageType, []byte{dhcpAck}}, dhcpOption{dhcpOptionServerID, testServer[:]})
		conn := &scriptedDHCP{responses: [][]dhcpEvent{{{packet: standardReply(dhcpOffer)}}, {{packet: ack}}}}
		lease, err := acquireDHCPLease(conn, testMAC, testXID, conn.clock)
		if err != nil || lease.Netmask != [4]byte{255, 255, 255, 0} || lease.HasRouter || len(lease.DNS) != 0 {
			t.Fatalf("lease = %+v, %v", lease, err)
		}
	})
	t.Run("non-ethernet", func(t *testing.T) {
		conn := &scriptedDHCP{}
		if _, err := acquireDHCPLease(conn, testMAC[:4], testXID, conn.clock); err == nil || len(conn.sent) != 0 {
			t.Fatalf("non-ethernet address accepted: %v", err)
		}
	})
}
