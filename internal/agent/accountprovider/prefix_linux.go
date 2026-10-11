//go:build linux

package accountprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/statefs"
)

// ChrootAccountRoot reports products whose shadow tools must chroot (--root)
// into the account root rather than use --prefix. EL 9's shadow-utils 4.9 takes
// the SELinux label of a rewritten database from the prefixed path (var_run_t
// under /run), which locks every confined reader out of /etc/passwd and
// /etc/shadow, and its chage has no --prefix. In a chroot the tools label the
// real /etc paths; libselinux then needs the host procfs and selinuxfs there.
func ChrootAccountRoot(platform *resourcev1.PlatformProduct) bool {
	switch platform.GetOsId() {
	case "rhel", "almalinux":
		return strings.HasPrefix(platform.GetVersion(), "9.")
	default:
		return false
	}
}

// validateAccountRoot proves the helper-only account root exposes exactly the
// host /etc bind and no home, mail or data tree; a chroot root additionally
// holds only the host procfs, selinuxfs and read-only /usr binds (with EL's
// /bin -> usr/bin link, so the tools' own login-shell check sees the host
// shells). The launcher owns mount setup; this path is never taken from
// desired policy or a native argv field.
func validateAccountRoot(root string, chroot bool) (err error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Base(root) != "account-root" {
		return ErrUnsafe
	}
	fd, err := statefs.OpenDirectory(root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	// Only the exact /etc bind and the private mail-spool scratch tree exist.
	// A distribution default that creates a mailbox writes it there, never on
	// the host; it is discarded with the transaction directory.
	want, links := []string{"etc", "var"}, map[string]string(nil)
	if chroot {
		want, links = []string{"bin", "etc", "proc", "sys", "usr", "var"}, map[string]string{"bin": "usr/bin"}
	}
	if err = onlyEntries(root, want, links); err != nil {
		return err
	}
	if err = sameNode("/etc", filepath.Join(root, "etc"), true); err != nil {
		return fmt.Errorf("%w: account-root requires the exact protected /etc bind", err)
	}
	if !chroot {
		return nil
	}
	if err = onlyEntries(filepath.Join(root, "sys"), []string{"fs"}, nil); err != nil {
		return err
	}
	if err = onlyEntries(filepath.Join(root, "sys", "fs"), []string{"selinux"}, nil); err != nil {
		return err
	}
	for _, path := range []string{"/sys/fs/selinux", "/usr"} {
		if err = sameNode(path, filepath.Join(root, path), false); err != nil {
			return fmt.Errorf("%w: account-root requires the exact host %s bind", err, path)
		}
	}
	var usr unix.Statfs_t
	if err = unix.Statfs(filepath.Join(root, "usr"), &usr); err != nil {
		return err
	}
	if usr.Flags&unix.ST_RDONLY == 0 {
		return fmt.Errorf("%w: account-root /usr bind is writable", ErrUnsafe)
	}
	// systemd mounts the unit's own /proc instance, so the bound procfs is
	// identified as a procfs root showing this process in its pid namespace.
	proc := filepath.Join(root, "proc")
	var fs unix.Statfs_t
	var st unix.Stat_t
	if err = unix.Statfs(proc, &fs); err != nil {
		return err
	}
	if err = unix.Lstat(proc, &st); err != nil {
		return err
	}
	self, err := os.Readlink(filepath.Join(proc, "self"))
	if err != nil {
		return err
	}
	if fs.Type != unix.PROC_SUPER_MAGIC || st.Ino != 1 || self != strconv.Itoa(os.Getpid()) {
		return fmt.Errorf("%w: account-root requires this pid namespace's procfs", ErrUnsafe)
	}
	return nil
}

// onlyEntries requires dir to hold exactly the named directories, except that
// a name in links is a symbolic link with exactly that target.
func onlyEntries(dir string, names []string, links map[string]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != len(names) {
		return ErrUnsafe
	}
	for i, entry := range entries {
		if entry.Name() != names[i] {
			return ErrUnsafe
		}
		target, link := links[entry.Name()]
		if !link {
			if !entry.IsDir() {
				return ErrUnsafe
			}
			continue
		}
		if got, err := os.Readlink(filepath.Join(dir, entry.Name())); err != nil || got != target {
			return errors.Join(ErrUnsafe, err)
		}
	}
	return nil
}

// sameNode requires bound to be the host directory itself (a bind mount),
// and protected when it carries the account databases.
func sameNode(host, bound string, protected bool) error {
	var want, got unix.Stat_t
	if err := unix.Stat(host, &want); err != nil {
		return err
	}
	if err := unix.Lstat(bound, &got); err != nil {
		return err
	}
	if want.Dev != got.Dev || want.Ino != got.Ino || got.Mode&unix.S_IFMT != unix.S_IFDIR || (protected && (got.Uid != 0 || got.Mode&0022 != 0)) {
		return ErrUnsafe
	}
	return nil
}
func nativeToolOptions(ctx context.Context, run nativeRun, commands []command, chroot bool) (map[string]string, error) {
	if len(commands) == 0 {
		return nil, nil
	}
	if run == nil {
		return nil, ErrUnsupported
	}
	options := make(map[string]string, 7)
	for _, cmd := range commands {
		if _, ok := options[cmd.tool]; ok {
			continue
		}
		switch cmd.tool {
		case "/usr/sbin/groupadd", "/usr/sbin/groupmod", "/usr/sbin/groupdel", "/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/sbin/userdel", "/usr/bin/chage", "/usr/sbin/chpasswd":
		default:
			return nil, ErrUnsafe
		}
		help, err := run(ctx, nil, cmd.tool, "--help")
		if err != nil {
			return nil, err
		}
		// Selection is read-only and complete before authority consumption. chage
		// and chpasswd on Ubuntu 24.04 (shadow 4.13) support --root rather than
		// --prefix; a chroot product uses --root for every tool. There is no
		// failed-effect fallback. CAP_SYS_CHROOT belongs only to the fixed helper
		// for these variants.
		switch {
		case chroot && strings.Contains(string(help), "--root"):
			options[cmd.tool] = "--root"
		case !chroot && strings.Contains(string(help), "--prefix"):
			options[cmd.tool] = "--prefix"
		case !chroot && (cmd.tool == "/usr/bin/chage" || cmd.tool == "/usr/sbin/chpasswd") && strings.Contains(string(help), "--root"):
			options[cmd.tool] = "--root"
		default:
			return nil, fmt.Errorf("%w: native account-root interface unavailable", ErrUnsupported)
		}
	}
	return options, nil
}
func prefixCommands(commands []command, root string, options map[string]string) {
	for i := range commands {
		args := make([]string, 0, len(commands[i].args)+2)
		args = append(args, options[commands[i].tool], root)
		commands[i].args = append(args, commands[i].args...)
	}
}
