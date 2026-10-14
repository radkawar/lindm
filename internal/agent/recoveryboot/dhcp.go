// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

// The recovery DHCPv4 client is deliberately smaller than a general client. It
// keeps the previous `udhcpc -n -q -t 5 -T 3` bounds: at most five DISCOVERs and
// three REQUESTs, each waiting three seconds, and exits after one ACK without
// renewal. A NAK ends the attempt on that interface instead of restarting the
// exchange, so a hostile server cannot extend the per-interface bound. Replies
// are requested by broadcast (RFC 2131 4.1) because the interface has no
// address yet. Option overload, duplicated options and non-unicast addresses
// are rejected rather than interpreted.
const (
	dhcpServerPort       = 67
	dhcpClientPort       = 68
	dhcpDiscoverAttempts = 5
	dhcpRequestAttempts  = 3
	dhcpReplyTimeout     = 3 * time.Second
	dhcpFixedBytes       = 236
	dhcpMinimumReply     = dhcpFixedBytes + 4
	// Replies larger than an Ethernet MTU are not needed for address, mask,
	// router and DNS; larger or truncated datagrams are ignored.
	dhcpMaximumReply = 1500
	// RFC 1542 relay agents may discard BOOTP messages shorter than 300 bytes.
	dhcpMinimumRequest = 300

	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpNak      = 6

	dhcpOptionPad          = 0
	dhcpOptionSubnetMask   = 1
	dhcpOptionRouter       = 3
	dhcpOptionDNS          = 6
	dhcpOptionRequestedIP  = 50
	dhcpOptionOverload     = 52
	dhcpOptionMessageType  = 53
	dhcpOptionServerID     = 54
	dhcpOptionParameters   = 55
	dhcpOptionClientID     = 61
	dhcpOptionEnd          = 255
	dhcpBroadcastFlag      = 0x8000
	dhcpHardwareEthernet   = 1
	dhcpHardwareAddressLen = 6
)

var dhcpMagicCookie = []byte{99, 130, 83, 99}

var (
	errDHCPTimeout = errors.New("recoveryboot: dhcp_timeout")
	errDHCPNoLease = errors.New("recoveryboot: dhcp_no_lease")
	errDHCPNak     = errors.New("recoveryboot: dhcp_nak")
	errDHCPReply   = errors.New("recoveryboot: invalid_dhcp_reply")
)

// dhcpConn is one interface-bound DHCP exchange. Receive returns the actual
// datagram length, which may exceed len(buffer) for a truncated datagram, or
// errDHCPTimeout when the deadline passes.
type dhcpConn interface {
	Send(packet []byte) error
	Receive(buffer []byte, deadline time.Time) (int, error)
}

type dhcpReply struct {
	Type      byte
	YourIP    [4]byte
	ServerID  [4]byte
	HasServer bool
	Netmask   [4]byte
	HasMask   bool
	Routers   [][4]byte
	DNS       [][4]byte
}

// dhcpLease is the configuration applied after ACK. Netmask defaults to
// 255.255.255.0 when the server sends none, as the previous handler did.
type dhcpLease struct {
	Address [4]byte
	Netmask [4]byte
	Router  [4]byte
	// HasRouter is false when the ACK carries no router; no default route is set.
	HasRouter bool
	DNS       [][4]byte
}

func dhcpMessage(kind byte, xid uint32, mac []byte, requested, server [4]byte) []byte {
	packet := make([]byte, dhcpFixedBytes, dhcpMinimumRequest)
	packet[0], packet[1], packet[2] = 1, dhcpHardwareEthernet, dhcpHardwareAddressLen
	binary.BigEndian.PutUint32(packet[4:], xid)
	binary.BigEndian.PutUint16(packet[10:], dhcpBroadcastFlag)
	copy(packet[28:], mac)
	packet = append(packet, dhcpMagicCookie...)
	packet = append(packet, dhcpOptionMessageType, 1, kind)
	packet = append(packet, dhcpOptionClientID, 1+dhcpHardwareAddressLen, dhcpHardwareEthernet)
	packet = append(packet, mac...)
	if kind == dhcpRequest {
		packet = append(packet, dhcpOptionRequestedIP, 4)
		packet = append(packet, requested[:]...)
		packet = append(packet, dhcpOptionServerID, 4)
		packet = append(packet, server[:]...)
	}
	packet = append(packet, dhcpOptionParameters, 3, dhcpOptionSubnetMask, dhcpOptionRouter, dhcpOptionDNS, dhcpOptionEnd)
	for len(packet) < dhcpMinimumRequest {
		packet = append(packet, dhcpOptionPad)
	}
	return packet
}

func unicastIPv4(address [4]byte) bool {
	return address[0] != 0 && address[0] != 127 && address[0] < 224
}

func dhcpAddresses(value []byte) ([][4]byte, bool) {
	if len(value) == 0 || len(value)%4 != 0 {
		return nil, false
	}
	addresses := make([][4]byte, 0, len(value)/4)
	for i := 0; i < len(value); i += 4 {
		address := [4]byte(value[i : i+4])
		if !unicastIPv4(address) {
			return nil, false
		}
		addresses = append(addresses, address)
	}
	return addresses, true
}

func contiguousNetmask(mask [4]byte) bool {
	value := binary.BigEndian.Uint32(mask[:])
	host := ^value
	return value != 0 && host&(host+1) == 0
}

// parseDHCPReply validates one BOOTREPLY for this exchange. Any malformed,
// unrelated or ambiguous datagram is an error and is ignored by the caller.
func parseDHCPReply(packet []byte, xid uint32, mac []byte) (dhcpReply, error) {
	var reply dhcpReply
	if len(packet) < dhcpMinimumReply || len(packet) > dhcpMaximumReply || packet[0] != 2 || packet[1] != dhcpHardwareEthernet || packet[2] != dhcpHardwareAddressLen {
		return reply, errDHCPReply
	}
	if binary.BigEndian.Uint32(packet[4:]) != xid || !bytes.Equal(packet[28:28+dhcpHardwareAddressLen], mac) || !bytes.Equal(packet[dhcpFixedBytes:dhcpMinimumReply], dhcpMagicCookie) {
		return reply, errDHCPReply
	}
	reply.YourIP = [4]byte(packet[16:20])
	seen := make(map[byte]bool)
	ended := false
	for i := dhcpMinimumReply; i < len(packet) && !ended; {
		code := packet[i]
		switch code {
		case dhcpOptionPad:
			i++
			continue
		case dhcpOptionEnd:
			ended = true
			continue
		}
		if i+1 >= len(packet) || i+2+int(packet[i+1]) > len(packet) {
			return reply, errDHCPReply
		}
		value := packet[i+2 : i+2+int(packet[i+1])]
		i += 2 + len(value)
		if seen[code] || code == dhcpOptionOverload {
			return reply, errDHCPReply
		}
		seen[code] = true
		var ok bool
		switch code {
		case dhcpOptionMessageType:
			if len(value) != 1 {
				return reply, errDHCPReply
			}
			reply.Type = value[0]
		case dhcpOptionServerID:
			if len(value) != 4 || !unicastIPv4([4]byte(value)) {
				return reply, errDHCPReply
			}
			reply.ServerID, reply.HasServer = [4]byte(value), true
		case dhcpOptionSubnetMask:
			if len(value) != 4 || !contiguousNetmask([4]byte(value)) {
				return reply, errDHCPReply
			}
			reply.Netmask, reply.HasMask = [4]byte(value), true
		case dhcpOptionRouter:
			if reply.Routers, ok = dhcpAddresses(value); !ok {
				return reply, errDHCPReply
			}
		case dhcpOptionDNS:
			if reply.DNS, ok = dhcpAddresses(value); !ok {
				return reply, errDHCPReply
			}
		}
	}
	if !ended {
		return reply, errDHCPReply
	}
	switch reply.Type {
	case dhcpOffer, dhcpAck:
		if !reply.HasServer || !unicastIPv4(reply.YourIP) {
			return reply, errDHCPReply
		}
	case dhcpNak:
	default:
		return reply, errDHCPReply
	}
	return reply, nil
}

// receiveDHCP waits until deadline for the first valid reply accepted by
// match. Invalid, truncated and unrelated datagrams are discarded.
func receiveDHCP(conn dhcpConn, xid uint32, mac []byte, deadline time.Time, match func(dhcpReply) bool) (dhcpReply, error) {
	buffer := make([]byte, dhcpMaximumReply)
	for {
		n, err := conn.Receive(buffer, deadline)
		if err != nil {
			return dhcpReply{}, err
		}
		if n > len(buffer) {
			continue
		}
		reply, err := parseDHCPReply(buffer[:n], xid, mac)
		if err == nil && match(reply) {
			return reply, nil
		}
	}
}

// acquireDHCPLease performs one bounded DISCOVER/OFFER/REQUEST/ACK exchange.
func acquireDHCPLease(conn dhcpConn, mac []byte, xid uint32, now func() time.Time) (dhcpLease, error) {
	if len(mac) != dhcpHardwareAddressLen {
		return dhcpLease{}, errors.New("recoveryboot: dhcp_requires_ethernet")
	}
	var offer dhcpReply
	offered := false
	for range dhcpDiscoverAttempts {
		if offered {
			break
		}
		if err := conn.Send(dhcpMessage(dhcpDiscover, xid, mac, [4]byte{}, [4]byte{})); err != nil {
			return dhcpLease{}, err
		}
		reply, err := receiveDHCP(conn, xid, mac, now().Add(dhcpReplyTimeout), func(r dhcpReply) bool { return r.Type == dhcpOffer })
		switch {
		case err == nil:
			offer, offered = reply, true
		case !errors.Is(err, errDHCPTimeout):
			return dhcpLease{}, err
		}
	}
	if !offered {
		return dhcpLease{}, errDHCPNoLease
	}
	for range dhcpRequestAttempts {
		if err := conn.Send(dhcpMessage(dhcpRequest, xid, mac, offer.YourIP, offer.ServerID)); err != nil {
			return dhcpLease{}, err
		}
		reply, err := receiveDHCP(conn, xid, mac, now().Add(dhcpReplyTimeout), func(r dhcpReply) bool {
			if r.Type == dhcpNak {
				return !r.HasServer || r.ServerID == offer.ServerID
			}
			return r.Type == dhcpAck && r.ServerID == offer.ServerID && r.YourIP == offer.YourIP
		})
		if errors.Is(err, errDHCPTimeout) {
			continue
		}
		if err != nil {
			return dhcpLease{}, err
		}
		if reply.Type == dhcpNak {
			return dhcpLease{}, errDHCPNak
		}
		lease := dhcpLease{Address: reply.YourIP, Netmask: [4]byte{255, 255, 255, 0}, DNS: reply.DNS}
		if reply.HasMask {
			lease.Netmask = reply.Netmask
		}
		if len(reply.Routers) != 0 {
			lease.Router, lease.HasRouter = reply.Routers[0], true
		}
		return lease, nil
	}
	return dhcpLease{}, errDHCPNoLease
}
