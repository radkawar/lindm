//go:build linux

package sysctlprovider

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type procKey struct {
	file      *os.File
	key, boot string
	stat      unix.Stat_t
	identity  []byte
}

func procPath(key string) string { return "/proc/sys/" + strings.ReplaceAll(key, ".", "/") }

// Root approval is necessary but cannot delegate power/destructive operations or
// weaken executor/authentication authority through the sysctl capability.
func authorityKey(key string) bool {
	for _, prefix := range []string{
		"kernel.panic", "kernel.softlockup", "kernel.hardlockup", "kernel.hung_task", "kernel.watchdog", "kernel.nmi_watchdog", "kernel.unknown_nmi_panic", "kernel.reboot", "kernel.poweroff_cmd", "kernel.ctrl-alt-del", "kernel.cad_pid", "kernel.sysrq", "kernel.kexec",
		"kernel.modules_disabled", "kernel.modprobe", "kernel.hotplug", "kernel.usermodehelper", "kernel.core_pattern", "kernel.unprivileged", "kernel.perf_event", "kernel.kptr_restrict", "kernel.dmesg_restrict", "kernel.ftrace", "kernel.io_uring", "kernel.yama.", "kernel.random.", "kernel.seccomp.", "kernel.keys.",
		"fs.suid_dumpable", "fs.protected_", "fs.binfmt_misc.", "vm.panic_on_oom", "vm.mmap_min_addr", "user.",
		// One-shot commands have no reconciliable value or ownership inverse.
		"vm.drop_caches", "vm.compact_memory", "net.ipv4.route.flush", "net.ipv6.route.flush",
	} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
func openProc(key string, writable bool) (*procKey, error) {
	flags := unix.O_RDONLY
	if writable {
		flags = unix.O_RDWR
	}
	fd, err := openProtected(procPath(key), flags)
	if err != nil {
		return nil, err
	}
	p := &procKey{file: os.NewFile(uintptr(fd), procPath(key)), key: key}
	fail := func(err error) (*procKey, error) { return nil, errors.Join(err, p.file.Close()) }
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return fail(err)
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return fail(ErrUnsupported)
	}
	if err := unix.Fstat(fd, &p.stat); err != nil {
		return fail(err)
	}
	if p.stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fail(ErrUnsupported)
	}
	boot, err := protectedRead("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return fail(err)
	}
	p.boot = strings.TrimSpace(string(boot))
	var network unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &network); err != nil {
		return fail(err)
	}
	// The procfs device and inode differ per mount namespace (ProtectProc=
	// gives each sandboxed unit its own instance), so only the boot, key and,
	// for per-namespace net.* keys, the network namespace identify the setting.
	// Other keys are observed from a private network namespace by the helper.
	var namespace unix.Stat_t
	if strings.HasPrefix(key, "net.") {
		namespace = network
	}
	identity := sha256.Sum256(fmt.Appendf(nil, "lindm.sysctl.native.v2:%s:%s:%d:%d", p.boot, key, namespace.Dev, namespace.Ino))
	p.identity = identity[:]
	return p, nil
}
func (p *procKey) close() error { return p.file.Close() }
func (p *procKey) read() (string, error) {
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(p.file, 4098))
	if err != nil {
		return "", err
	}
	if len(data) > 4097 || bytes.IndexByte(data, 0) >= 0 {
		return "", ErrUnsupported
	}
	value := strings.TrimSuffix(string(data), "\n")
	if len(value) > 4096 || strings.ContainsAny(value, "\r\n") {
		return "", ErrUnsupported
	}
	// Preserve the exact kernel representation, including internal tabs/spaces.
	return value, nil
}
func (p *procKey) unchanged(value string) error {
	fresh, err := openProc(p.key, false)
	if err != nil {
		return err
	}
	observed, readErr := fresh.read()
	closeErr := fresh.close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if !bytes.Equal(p.identity, fresh.identity) || observed != value {
		return ErrConflict
	}
	return nil
}
func (p *procKey) write(value string) error {
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// A single write is intentional: a short write may already have changed the
	// kernel and MUST NOT be replayed as a second fragment or attempted rollback.
	data := []byte(value + "\n")
	n, err := p.file.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
