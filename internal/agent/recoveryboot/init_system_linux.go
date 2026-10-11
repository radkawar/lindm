//go:build linux

package recoveryboot

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// linuxInitSystem is the production PID 1 boundary. It uses only direct
// syscalls, ioctls and rtnetlink; no helper binary is executed except the
// recovery-run child, which is this same signed executable.
type linuxInitSystem struct{}

var _ initSystem = linuxInitSystem{}

const netlinkTimeout = 5 * time.Second

func (linuxInitSystem) Mount(source, target, fstype string, flags uintptr, data string) error {
	return unix.Mount(source, target, fstype, flags, data)
}

func (linuxInitSystem) Unmount(target string) error {
	return unix.Unmount(target, 0)
}

func (linuxInitSystem) RebindConsole(console string) error {
	fd, err := unix.Open(console, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	for target := range 3 {
		if err := unix.Dup3(fd, target, 0); err != nil {
			return errors.Join(err, unix.Close(fd))
		}
	}
	if fd > 2 {
		return unix.Close(fd)
	}
	return nil
}

func (linuxInitSystem) LoadModule(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = unix.FinitModule(fd, "", 0)
	if errors.Is(err, unix.EEXIST) {
		err = nil
	}
	return errors.Join(err, unix.Close(fd))
}

func (linuxInitSystem) KernelRelease() (string, error) {
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(name.Release[:]), nil
}

func (linuxInitSystem) ReadBlockHead(path string, device uint64) (_ []byte, err error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFBLK || stat.Rdev != device {
		return nil, errors.New("recoveryboot: block_device_mismatch")
	}
	head := make([]byte, blockProbeBytes)
	n, err := unix.Pread(fd, head, 0)
	if err != nil {
		return nil, err
	}
	if n != len(head) {
		return nil, errors.New("recoveryboot: short_block_device")
	}
	return head, nil
}

func (linuxInitSystem) SetMemlockUnlimited() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
}

func interfaceIoctl(iface string, apply func(fd int, request *unix.Ifreq) error) error {
	request, err := unix.NewIfreq(iface)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	return errors.Join(apply(fd, request), unix.Close(fd))
}

func (linuxInitSystem) LinkUp(iface string) error {
	return interfaceIoctl(iface, func(fd int, request *unix.Ifreq) error {
		if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
			return err
		}
		request.SetUint16(request.Uint16() | unix.IFF_UP)
		return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, request)
	})
}

// ConfigureIPv4 uses the same SIOCSIFADDR/SIOCSIFNETMASK sequence as the
// previous ifconfig handler; the kernel derives broadcast and subnet route.
func (linuxInitSystem) ConfigureIPv4(iface string, address, netmask [4]byte) error {
	return interfaceIoctl(iface, func(fd int, request *unix.Ifreq) error {
		if err := request.SetInet4Addr(address[:]); err != nil {
			return err
		}
		if err := unix.IoctlIfreq(fd, unix.SIOCSIFADDR, request); err != nil {
			return err
		}
		if err := request.SetInet4Addr(netmask[:]); err != nil {
			return err
		}
		return unix.IoctlIfreq(fd, unix.SIOCSIFNETMASK, request)
	})
}

func interfaceIndex(iface string) (int, error) {
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, err
	}
	return link.Index, nil
}

// FlushAddresses deletes every address of every family on the interface, as
// `ip addr flush dev` did, by returning each dumped address as RTM_DELADDR.
func (linuxInitSystem) FlushAddresses(iface string) error {
	index, err := interfaceIndex(iface)
	if err != nil {
		return err
	}
	dump, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return err
	}
	messages, err := syscall.ParseNetlinkMessage(dump)
	if err != nil {
		return err
	}
	for _, message := range messages {
		if message.Header.Type != syscall.RTM_NEWADDR || len(message.Data) < unix.SizeofIfAddrmsg {
			continue
		}
		if binary.NativeEndian.Uint32(message.Data[4:8]) != uint32(index) {
			continue
		}
		if err := netlinkRequest(unix.RTM_DELADDR, 0, message.Data); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			return err
		}
	}
	return nil
}

func netlinkAttribute(kind uint16, value []byte) []byte {
	attribute := make([]byte, 4, 4+len(value)+3)
	binary.NativeEndian.PutUint16(attribute, uint16(4+len(value)))
	binary.NativeEndian.PutUint16(attribute[2:], kind)
	attribute = append(attribute, value...)
	for len(attribute)%4 != 0 {
		attribute = append(attribute, 0)
	}
	return attribute
}

// ReplaceDefaultRoute is `ip route replace default via GATEWAY dev IFACE`.
func (linuxInitSystem) ReplaceDefaultRoute(iface string, gateway [4]byte) error {
	index, err := interfaceIndex(iface)
	if err != nil {
		return err
	}
	route := []byte{unix.AF_INET, 0, 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0, 0, 0, 0}
	route = append(route, netlinkAttribute(unix.RTA_GATEWAY, gateway[:])...)
	oif := make([]byte, 4)
	binary.NativeEndian.PutUint32(oif, uint32(index))
	route = append(route, netlinkAttribute(unix.RTA_OIF, oif)...)
	return netlinkRequest(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, route)
}

// netlinkRequest sends one acknowledged rtnetlink request with a bounded wait.
func netlinkRequest(kind, flags uint16, payload []byte) (err error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	timeout := unix.NsecToTimeval(netlinkTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	const sequence = 1
	message := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(payload))
	binary.NativeEndian.PutUint32(message, uint32(unix.NLMSG_HDRLEN+len(payload)))
	binary.NativeEndian.PutUint16(message[4:], kind)
	binary.NativeEndian.PutUint16(message[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|flags)
	binary.NativeEndian.PutUint32(message[8:], sequence)
	message = append(message, payload...)
	if err := unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buffer := make([]byte, 8192)
	for range 16 {
		n, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return err
		}
		replies, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return err
		}
		for _, reply := range replies {
			if reply.Header.Seq != sequence || reply.Header.Type != unix.NLMSG_ERROR {
				continue
			}
			if len(reply.Data) < 4 {
				return errors.New("recoveryboot: short_netlink_ack")
			}
			if code := int32(binary.NativeEndian.Uint32(reply.Data)); code != 0 {
				return unix.Errno(-code)
			}
			return nil
		}
	}
	return errors.New("recoveryboot: netlink_ack_missing")
}

type udpDHCPSocket struct {
	fd int
}

func (linuxInitSystem) OpenDHCP(iface string) (dhcpSocket, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	err = errors.Join(
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1),
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1),
		unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface),
	)
	if err == nil {
		err = unix.Bind(fd, &unix.SockaddrInet4{Port: dhcpClientPort})
	}
	if err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	return &udpDHCPSocket{fd: fd}, nil
}

func (s *udpDHCPSocket) Send(packet []byte) error {
	return unix.Sendto(s.fd, packet, 0, &unix.SockaddrInet4{Port: dhcpServerPort, Addr: [4]byte{255, 255, 255, 255}})
}

// Receive returns datagrams only from UDP port 67. With MSG_TRUNC the
// returned length exposes truncation instead of silently parsing a prefix.
func (s *udpDHCPSocket) Receive(buffer []byte, deadline time.Time) (int, error) {
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, errDHCPTimeout
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}, int(min(remaining.Milliseconds()+1, 1<<30)))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if ready == 0 {
			continue
		}
		n, from, err := unix.Recvfrom(s.fd, buffer, unix.MSG_TRUNC|unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if source, ok := from.(*unix.SockaddrInet4); !ok || source.Port != dhcpServerPort {
			continue
		}
		return n, nil
	}
}

func (s *udpDHCPSocket) Close() error {
	return unix.Close(s.fd)
}

func (linuxInitSystem) TransactionID() (uint32, error) {
	var value [4]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value[:]), nil
}

// RunRecovery starts this same signed executable as `recovery-run` and reaps
// every child until it exits. Its result never changes the poweroff outcome.
func (linuxInitSystem) RunRecovery() error {
	environment := []string{recoverySearchPath}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "PATH=") {
			environment = append(environment, value)
		}
	}
	process, err := os.StartProcess(recoveryExecutable, []string{"lindm-agent", "recovery-run", "-config", recoveryConfigPath}, &os.ProcAttr{
		Dir:   "/",
		Env:   environment,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return fmt.Errorf("start recovery-run: %w", err)
	}
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for recovery-run: %w", err)
		}
		if pid != process.Pid {
			continue
		}
		if status.Exited() && status.ExitStatus() == 0 {
			return nil
		}
		return fmt.Errorf("recovery-run ended: %s", describeWait(status))
	}
}

func describeWait(status unix.WaitStatus) string {
	if status.Signaled() {
		return "signal " + status.Signal().String()
	}
	return fmt.Sprintf("exit status %d", status.ExitStatus())
}

func (linuxInitSystem) PowerOff() error {
	unix.Sync()
	return unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}

func (linuxInitSystem) Sleep(duration time.Duration) {
	time.Sleep(duration)
}

func (linuxInitSystem) Now() time.Time {
	return time.Now()
}
