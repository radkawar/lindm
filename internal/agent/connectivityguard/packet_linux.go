// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connectivityguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func packetAddresses(t *agentv1.ConnectivityProbeTarget) (netip.Addr, netip.Addr, error) {
	source, err := netip.ParseAddr(t.GetSourceAddress())
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	destination, err := netip.ParseAddr(t.GetAddress())
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if source.Is4() != destination.Is4() || source.Is4In6() || destination.Is4In6() || source.IsUnspecified() || destination.IsUnspecified() || source.IsMulticast() || destination.IsMulticast() || source.IsLoopback() || destination.IsLoopback() {
		return netip.Addr{}, netip.Addr{}, ErrConflict
	}
	return source, destination, nil
}
func localAddress(address netip.Addr) error {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, entry := range addresses {
		prefix, err := netip.ParsePrefix(entry.String())
		if err == nil && prefix.Addr() == address {
			return nil
		}
	}
	return errors.New("probe_address_not_local")
}
func packetProtocol(t *agentv1.ConnectivityProbeTarget) int {
	if t.GetProtocol() == agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_TCP {
		return unix.IPPROTO_TCP
	}
	return unix.IPPROTO_UDP
}
func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func transportPacket(t *agentv1.ConnectivityProbeTarget, nonce []byte) ([]byte, error) {
	source, destination, err := packetAddresses(t)
	if err != nil {
		return nil, err
	}
	if len(nonce) != 32 {
		return nil, ErrConflict
	}
	protocol := packetProtocol(t)
	header := 8
	if protocol == unix.IPPROTO_TCP {
		header = 20
	}
	packet := make([]byte, header+32)
	binary.BigEndian.PutUint16(packet, uint16(t.GetSourcePort()))
	binary.BigEndian.PutUint16(packet[2:], uint16(t.GetPort()))
	copy(packet[header:], nonce)
	checksumOffset := 6
	if protocol == unix.IPPROTO_TCP {
		binary.BigEndian.PutUint32(packet[4:], binary.BigEndian.Uint32(nonce))
		packet[12] = 5 << 4
		packet[13] = 2
		binary.BigEndian.PutUint16(packet[14:], 4096)
		checksumOffset = 16
	} else {
		binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)))
	}
	pseudo := make([]byte, 0, 40+len(packet))
	pseudo = append(pseudo, source.AsSlice()...)
	pseudo = append(pseudo, destination.AsSlice()...)
	if source.Is4() {
		pseudo = append(pseudo, 0, byte(protocol), byte(len(packet)>>8), byte(len(packet)))
	} else {
		pseudo = append(pseudo, 0, 0, byte(len(packet)>>8), byte(len(packet)), 0, 0, 0, byte(protocol))
	}
	pseudo = append(pseudo, packet...)
	sum := checksum(pseudo)
	if sum == 0 && protocol == unix.IPPROTO_UDP {
		sum = 65535
	}
	binary.BigEndian.PutUint16(packet[checksumOffset:], sum)
	return packet, nil
}
func transmitPacket(ctx context.Context, t *agentv1.ConnectivityProbeTarget, nonce []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source, destination, err := packetAddresses(t)
	if err != nil {
		return nil, err
	}
	if err := localAddress(source); err != nil {
		return nil, err
	}
	transport, err := transportPacket(t, nonce)
	if err != nil {
		return nil, err
	}
	family := unix.AF_INET6
	if source.Is4() {
		family = unix.AF_INET
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	var packet []byte
	var address unix.Sockaddr
	if source.Is4() {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
			return nil, err
		}
		packet = make([]byte, 20+len(transport))
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		packet[6] = 0x40
		packet[8] = 64
		packet[9] = byte(packetProtocol(t))
		copy(packet[12:], source.AsSlice())
		copy(packet[16:], destination.AsSlice())
		copy(packet[20:], transport)
		binary.BigEndian.PutUint16(packet[10:], checksum(packet[:20]))
		address = &unix.SockaddrInet4{Addr: destination.As4()}
	} else {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
			return nil, err
		}
		packet = make([]byte, 40+len(transport))
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:], uint16(len(transport)))
		packet[6] = byte(packetProtocol(t))
		packet[7] = 64
		copy(packet[8:], source.AsSlice())
		copy(packet[24:], destination.AsSlice())
		copy(packet[40:], transport)
		address = &unix.SockaddrInet6{Addr: destination.As16()}
	}
	if err := unix.Sendto(fd, packet, 0, address); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(transport)
	return sum[:], nil
}

type packetReceiver struct {
	fd       int
	source   netip.Addr
	expected []byte
	deadline time.Time
	packets  int
	buffer   [128]byte
}

func receivePackets(t *agentv1.ConnectivityProbeTarget, nonce []byte) (*packetReceiver, error) {
	source, destination, err := packetAddresses(t)
	if err != nil {
		return nil, err
	}
	if err := localAddress(destination); err != nil {
		return nil, err
	}
	expected, err := transportPacket(t, nonce)
	if err != nil {
		return nil, err
	}
	family := unix.AF_INET6
	var address unix.Sockaddr = &unix.SockaddrInet6{Addr: destination.As16()}
	if source.Is4() {
		family = unix.AF_INET
		address = &unix.SockaddrInet4{Addr: destination.As4()}
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, packetProtocol(t))
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, address); err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	return &packetReceiver{fd: fd, source: source, expected: expected, deadline: time.Now().Add(10 * time.Second)}, nil
}
func (r *packetReceiver) close() error { return unix.Close(r.fd) }
func (r *packetReceiver) observe() ([]byte, error) {
	if !time.Now().Before(r.deadline) {
		return nil, ErrExpired
	}
	source := r.source
	buffer := r.buffer[:]
	for range 128 {
		n, from, err := unix.Recvfrom(r.fd, buffer, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		r.packets++
		if r.packets > 4096 {
			return nil, ErrUnconfirmed
		}
		packet := buffer[:n]
		if source.Is4() {
			address, ok := from.(*unix.SockaddrInet4)
			if !ok || address.Addr != source.As4() || n < 20 || packet[0]>>4 != 4 {
				continue
			}
			header := int(packet[0]&15) * 4
			if header < 20 || header > n {
				continue
			}
			packet = packet[header:]
		} else {
			address, ok := from.(*unix.SockaddrInet6)
			if !ok || address.Addr != source.As16() {
				continue
			}
		}
		if bytes.Equal(packet, r.expected) {
			sum := sha256.Sum256(packet)
			return sum[:], nil
		}
	}
	return nil, nil
}
