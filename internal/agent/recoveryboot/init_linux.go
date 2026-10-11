//go:build linux

package recoveryboot

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Fixed recovery-image paths. They are the same for every distribution; the
// runtime configuration's state directory must name stateMount.
const (
	stateMount            = "/run/lindm-recovery"
	espMount              = "/run/recovery-esp"
	loaderEntrySelected   = "/sys/firmware/efi/efivars/LoaderEntrySelected-" + loaderGUID
	filesystemAttempts    = 30
	filesystemRetryDelay  = time.Second
	maxBlockDevices       = 4096
	maxNetworkInterfaces  = 1024
	blockProbeBytes       = 2048
	maxCapsuleBytes       = 1 << 20
	recoveryConfigPath    = "/etc/lindm/recovery.json"
	recoveryExecutable    = "/init"
	recoverySearchPath    = "PATH=/bin:/sbin:/usr/bin:/usr/sbin"
	resolverConfiguration = "/etc/resolv.conf"
)

// initSystem is PID 1's privileged kernel boundary. Paths are absolute
// recovery-image paths; file contents are read and written by initRun under
// its root so tests exercise the real file handling without privileges.
type initSystem interface {
	Mount(source, target, fstype string, flags uintptr, data string) error
	Unmount(target string) error
	// RebindConsole makes the named console PID 1's stdin, stdout and stderr.
	RebindConsole(console string) error
	// LoadModule loads one unchanged module file; an already loaded module is
	// success, matching modprobe.
	LoadModule(path string) error
	KernelRelease() (string, error)
	// ReadBlockHead returns the first blockProbeBytes of a block device after
	// confirming the opened node is the sysfs-reported device number.
	ReadBlockHead(path string, device uint64) ([]byte, error)
	SetMemlockUnlimited() error
	LinkUp(iface string) error
	FlushAddresses(iface string) error
	ConfigureIPv4(iface string, address, netmask [4]byte) error
	ReplaceDefaultRoute(iface string, gateway [4]byte) error
	OpenDHCP(iface string) (dhcpSocket, error)
	TransactionID() (uint32, error)
	// RunRecovery runs `recovery-run` as a child of PID 1 and waits for it.
	RunRecovery() error
	// PowerOff syncs and powers off. It returns only if the kernel refused.
	PowerOff() error
	Sleep(time.Duration)
	Now() time.Time
}

type dhcpSocket interface {
	dhcpConn
	Close() error
}

type initRun struct {
	root string
	sys  initSystem
	log  io.Writer
}

// RunInit is the signed recovery image's PID 1. It never returns: success,
// error, panic or a termination signal all end in a forced poweroff. There is
// no shell, alternate init or credential fallback.
func RunInit() {
	system := linuxInitSystem{}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	// This goroutine lives until poweroff ends the machine; PID 1 never exits
	// normally. It mirrors the previous init's INT/TERM poweroff trap.
	go func() {
		<-signals
		_ = system.PowerOff()
	}()
	(&initRun{root: "/", sys: system, log: os.Stderr}).main()
	os.Exit(1)
}

func (r *initRun) main() {
	if err := r.guarded(); err != nil {
		r.report("%v", err)
	} else {
		r.report("recovery returned; powering off")
	}
	if err := r.sys.PowerOff(); err != nil {
		r.report("poweroff: %v", err)
	}
}

// report writes a console diagnostic. A failed console write cannot change
// the outcome: every path still ends in poweroff.
func (r *initRun) report(format string, args ...any) {
	_, _ = fmt.Fprintf(r.log, "lindm-recovery-init: "+format+"\n", args...)
}

func (r *initRun) guarded() (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("recovery init panic: %v", recovered)
		}
	}()
	return r.run()
}

func (r *initRun) path(name string) string {
	return filepath.Join(r.root, name)
}

func (r *initRun) mount(source, target, fstype string, flags uintptr, data string) error {
	if err := r.sys.Mount(source, target, fstype, flags, data); err != nil {
		return fmt.Errorf("mount %s on %s: %w", fstype, target, err)
	}
	return nil
}

func (r *initRun) run() error {
	if err := r.mount("devtmpfs", "/dev", "devtmpfs", 0, ""); err != nil {
		return err
	}
	// The archive's static console only exists until devtmpfs hides it.
	if err := r.sys.RebindConsole("/dev/console"); err != nil {
		return fmt.Errorf("rebind console: %w", err)
	}
	if err := r.mount("proc", "/proc", "proc", 0, ""); err != nil {
		return err
	}
	if err := r.mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		return err
	}
	if err := r.mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return err
	}
	for _, directory := range []string{"/sys/firmware/efi/efivars", stateMount} {
		if err := os.MkdirAll(r.path(directory), 0755); err != nil {
			return err
		}
	}
	data, err := readBounded(r.path("/"+initParamsPath), maxInitParamsBytes)
	if err != nil {
		return fmt.Errorf("read init parameters: %w", err)
	}
	params, err := parseInitParams(data)
	if err != nil {
		return err
	}
	if err := r.loadModules(); err != nil {
		return err
	}
	if err := r.mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", 0, ""); err != nil {
		return err
	}
	if params.StateUUID != "" {
		if err := r.mountOffTargetState(params.StateUUID); err != nil {
			return err
		}
	} else if err := os.Chmod(r.path(stateMount), 0700); err != nil {
		return err
	}
	switch params.Mode {
	case initModeUKI:
		err = r.bootUKI(params)
	case initModeMeasuredBLS:
		err = r.bootMeasuredBLS()
	default:
		err = errInitParams
	}
	if err != nil {
		return err
	}
	if err := r.configureNetwork(); err != nil {
		return err
	}
	// Native TPM sessions lock current and future process memory; the child
	// must not inherit the kernel's small default memlock ceiling.
	if err := r.sys.SetMemlockUnlimited(); err != nil {
		return fmt.Errorf("raise memlock limit: %w", err)
	}
	return r.sys.RunRecovery()
}

// readBounded reads one regular, non-symlink file of at most limit bytes.
func readBounded(name string, limit int64) (_ []byte, err error) {
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: exceeds %d bytes", name, limit)
	}
	return data, nil
}

func readDirectoryNames(name string, limit int) ([]string, error) {
	directory, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	names, err := directory.Readdirnames(limit + 1)
	if err = errors.Join(err, directory.Close()); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > limit {
		return nil, fmt.Errorf("%s: more than %d entries", name, limit)
	}
	slices.Sort(names)
	return names, nil
}

func (r *initRun) loadModules() error {
	data, err := readBounded(r.path("/"+moduleLoadPath), maxModuleLoadBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read module list: %w", err)
	}
	names, err := parseModuleLoad(data)
	if err != nil || len(names) == 0 {
		return err
	}
	release, err := r.sys.KernelRelease()
	if err != nil {
		return err
	}
	if release == "" || release == "." || release == ".." || strings.ContainsAny(release, "/\x00") || len(release) > 64 {
		return errors.New("recoveryboot: invalid_kernel_release")
	}
	for _, name := range names {
		if err := r.sys.LoadModule(path.Join("/lib/modules", release, name+".ko")); err != nil {
			return fmt.Errorf("load module %s: %w", name, err)
		}
	}
	return nil
}

const (
	filesystemExt4 = "ext4"
	filesystemVFAT = "vfat"
)

// probeFilesystem returns the volume identifier as blkid formats it: the
// lowercase ext superblock UUID or the uppercase FAT volume serial.
func probeFilesystem(head []byte, kind string) (string, bool) {
	if len(head) < blockProbeBytes {
		return "", false
	}
	switch kind {
	case filesystemExt4:
		superblock := head[1024:]
		if binary.LittleEndian.Uint16(superblock[0x38:]) != 0xef53 {
			return "", false
		}
		u := superblock[0x68 : 0x68+16]
		return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]), true
	case filesystemVFAT:
		if head[510] != 0x55 || head[511] != 0xaa || head[16] == 0 || binary.LittleEndian.Uint16(head[14:]) == 0 {
			return "", false
		}
		switch binary.LittleEndian.Uint16(head[11:]) {
		case 512, 1024, 2048, 4096:
		default:
			return "", false
		}
		if cluster := head[13]; cluster == 0 || cluster&(cluster-1) != 0 {
			return "", false
		}
		var serial []byte
		switch {
		case string(head[82:90]) == "FAT32   " && head[66] == 0x29:
			serial = head[67:71]
		case head[38] == 0x29 && (string(head[54:62]) == "FAT12   " || string(head[54:62]) == "FAT16   "):
			serial = head[39:43]
		default:
			return "", false
		}
		return fmt.Sprintf("%02X%02X-%02X%02X", serial[3], serial[2], serial[1], serial[0]), true
	}
	return "", false
}

// findFilesystem scans every kernel block device for one filesystem of kind
// with the identifier, retrying while storage enumerates. Two matches are
// refused rather than resolved by enumeration order.
func (r *initRun) findFilesystem(kind, identifier string) (string, error) {
	for range filesystemAttempts {
		found, err := r.scanBlockDevices(kind, identifier)
		if err != nil || found != "" {
			return found, err
		}
		r.sys.Sleep(filesystemRetryDelay)
	}
	return "", fmt.Errorf("recoveryboot: %s filesystem %s not found", kind, identifier)
}

func (r *initRun) scanBlockDevices(kind, identifier string) (string, error) {
	names, err := readDirectoryNames(r.path("/sys/class/block"), maxBlockDevices)
	if err != nil {
		return "", err
	}
	var found string
	for _, name := range names {
		device := strings.ReplaceAll(name, "!", "/")
		if name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || strings.Contains(device, "..") {
			continue
		}
		numbers, err := readBounded(r.path("/sys/class/block/"+name+"/dev"), 32)
		if err != nil {
			continue
		}
		major, minor, ok := strings.Cut(strings.TrimSuffix(string(numbers), "\n"), ":")
		majorValue, majorErr := strconv.ParseUint(major, 10, 32)
		minorValue, minorErr := strconv.ParseUint(minor, 10, 32)
		if !ok || majorErr != nil || minorErr != nil {
			continue
		}
		head, err := r.sys.ReadBlockHead("/dev/"+device, unix.Mkdev(uint32(majorValue), uint32(minorValue)))
		if err != nil {
			continue
		}
		value, ok := probeFilesystem(head, kind)
		if !ok || (kind == filesystemExt4 && value != identifier) || (kind == filesystemVFAT && !strings.EqualFold(value, identifier)) {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("recoveryboot: ambiguous %s filesystem %s", kind, identifier)
		}
		found = "/dev/" + device
	}
	return found, nil
}

func (r *initRun) mountOffTargetState(identifier string) error {
	device, err := r.findFilesystem(filesystemExt4, identifier)
	if err != nil {
		return err
	}
	return r.mount(device, stateMount, "ext4", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
}

// bootUKI hands recovery-run the systemd-boot-selected image, its optional TPM
// capsule and the embedded signer certificate. The entry only selects paths;
// recovery-run authenticates the copied image and capsule independently.
func (r *initRun) bootUKI(params initParams) error {
	selected, err := readBounded(r.path(loaderEntrySelected), 4+maxLoaderEntryBytes)
	if err != nil {
		return fmt.Errorf("read selected loader entry: %w", err)
	}
	entry, action, err := selectedRecoveryEntry(selected)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.path(espMount), 0755); err != nil {
		return err
	}
	device, err := r.findFilesystem(filesystemVFAT, params.ESPUUID)
	if err != nil {
		return err
	}
	if err := r.mount(device, espMount, "vfat", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	if err := r.copyBootFile(espMount+"/EFI/Linux/"+entry, stateMount+"/booted.efi", maxAuthenticodeImageBytes); err != nil {
		return err
	}
	if params.StateUUID == "" {
		if err := r.copyBootFile(espMount+"/EFI/Linux/lindm-recovery-"+action+".capsule", stateMount+"/capsule.pb", maxCapsuleBytes); err != nil {
			return err
		}
	}
	if err := r.copyBootFile("/etc/lindm/image-signing.pem", stateMount+"/image-signing.pem", maxAuthenticodeCertificateBytes); err != nil {
		return err
	}
	if err := r.sys.Unmount(espMount); err != nil {
		return fmt.Errorf("unmount %s: %w", espMount, err)
	}
	return nil
}

// bootMeasuredBLS needs no loader variable or ESP: recovery-run verifies the
// measured kernel options and event log, so only securityfs is added.
func (r *initRun) bootMeasuredBLS() error {
	return r.mount("securityfs", "/sys/kernel/security", "securityfs", 0, "")
}

// copyBootFile replaces target with a new root-owned mode-0400 copy of a
// regular source file, never following a symlink at either end.
func (r *initRun) copyBootFile(source, target string, limit int64) (err error) {
	in, err := os.OpenFile(r.path(source), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, in.Close()) }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return fmt.Errorf("recoveryboot: unsafe_boot_file: %s", source)
	}
	if err := unix.Unlink(r.path(target)); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("replace %s: %w", target, err)
	}
	out, err := os.OpenFile(r.path(target), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	copied, err := io.Copy(out, io.LimitReader(in, limit+1))
	if err != nil {
		return err
	}
	if copied > limit {
		return fmt.Errorf("recoveryboot: unsafe_boot_file: %s", source)
	}
	return out.Chmod(0400)
}

// configureNetwork brings loopback up, then tries each non-loopback interface
// in name order until one bounded DHCP exchange succeeds. Failure to raise a
// link or to apply an acknowledged lease is fatal, as before.
func (r *initRun) configureNetwork() error {
	if err := r.sys.LinkUp("lo"); err != nil {
		return fmt.Errorf("raise lo: %w", err)
	}
	names, err := readDirectoryNames(r.path("/sys/class/net"), maxNetworkInterfaces)
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == "lo" {
			continue
		}
		if name == "." || name == ".." || len(name) >= unix.IFNAMSIZ || strings.ContainsAny(name, "/\x00 \t\n:") {
			return fmt.Errorf("recoveryboot: invalid_interface_name %q", name)
		}
		if err := r.sys.LinkUp(name); err != nil {
			return fmt.Errorf("raise %s: %w", name, err)
		}
		lease, err := r.leaseOn(name)
		if err != nil {
			r.report("%s: %v", name, err)
			continue
		}
		return r.applyLease(name, lease)
	}
	return errors.New("recoveryboot: no_dhcp_lease")
}

func (r *initRun) hardwareAddress(iface string) ([]byte, error) {
	kind, err := readBounded(r.path("/sys/class/net/"+iface+"/type"), 16)
	if err != nil {
		return nil, err
	}
	if strings.TrimSuffix(string(kind), "\n") != "1" {
		return nil, errors.New("recoveryboot: dhcp_requires_ethernet")
	}
	text, err := readBounded(r.path("/sys/class/net/"+iface+"/address"), 64)
	if err != nil {
		return nil, err
	}
	fields := strings.Split(strings.TrimSuffix(string(text), "\n"), ":")
	if len(fields) != dhcpHardwareAddressLen {
		return nil, errors.New("recoveryboot: dhcp_requires_ethernet")
	}
	address := make([]byte, 0, dhcpHardwareAddressLen)
	for _, field := range fields {
		value, err := strconv.ParseUint(field, 16, 8)
		if err != nil || len(field) != 2 {
			return nil, errors.New("recoveryboot: dhcp_requires_ethernet")
		}
		address = append(address, byte(value))
	}
	return address, nil
}

func (r *initRun) leaseOn(iface string) (_ dhcpLease, err error) {
	mac, err := r.hardwareAddress(iface)
	if err != nil {
		return dhcpLease{}, err
	}
	// udhcpc's "deconfig" removed any existing address before discovery.
	if err := r.sys.FlushAddresses(iface); err != nil {
		return dhcpLease{}, fmt.Errorf("flush addresses: %w", err)
	}
	xid, err := r.sys.TransactionID()
	if err != nil {
		return dhcpLease{}, err
	}
	conn, err := r.sys.OpenDHCP(iface)
	if err != nil {
		return dhcpLease{}, err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	return acquireDHCPLease(conn, mac, xid, r.sys.Now)
}

func (r *initRun) applyLease(iface string, lease dhcpLease) error {
	if err := r.sys.ConfigureIPv4(iface, lease.Address, lease.Netmask); err != nil {
		return fmt.Errorf("configure %s: %w", iface, err)
	}
	if lease.HasRouter {
		if err := r.sys.ReplaceDefaultRoute(iface, lease.Router); err != nil {
			return fmt.Errorf("default route via %s: %w", iface, err)
		}
	}
	var resolver strings.Builder
	for _, server := range lease.DNS {
		fmt.Fprintf(&resolver, "nameserver %d.%d.%d.%d\n", server[0], server[1], server[2], server[3])
	}
	file, err := os.OpenFile(r.path(resolverConfiguration), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return err
	}
	_, err = io.WriteString(file, resolver.String())
	return errors.Join(err, file.Close())
}
