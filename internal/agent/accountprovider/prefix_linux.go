//go:build linux

package accountprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/statefs"
)

// validateAccountRoot proves the helper-only account root exposes exactly the
// host /etc bind and no home, mail or data tree. The launcher owns mount setup;
// this path is never taken from desired policy or a native argv field.
func validateAccountRoot(root string) (err error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Base(root) != "account-root" {
		return ErrUnsafe
	}
	fd, err := statefs.OpenDirectory(root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	// Only the exact /etc bind and the private mail-spool scratch tree exist.
	// A distribution default that creates a mailbox writes it there, never on
	// the host; it is discarded with the transaction directory.
	if len(entries) != 2 || entries[0].Name() != "etc" || !entries[0].IsDir() || entries[1].Name() != "var" || !entries[1].IsDir() {
		return ErrUnsafe
	}
	var host, bound unix.Stat_t
	if err = unix.Stat("/etc", &host); err != nil {
		return err
	}
	if err = unix.Lstat(filepath.Join(root, "etc"), &bound); err != nil {
		return err
	}
	if host.Dev != bound.Dev || host.Ino != bound.Ino || bound.Mode&unix.S_IFMT != unix.S_IFDIR || bound.Uid != 0 || bound.Mode&0022 != 0 {
		return fmt.Errorf("%w: account-root requires the exact protected /etc bind", ErrUnsafe)
	}
	return nil
}
func nativeToolOptions(ctx context.Context, run nativeRun, commands []command) (map[string]string, error) {
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
		case "/usr/sbin/groupadd", "/usr/sbin/groupmod", "/usr/sbin/groupdel", "/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/sbin/userdel", "/usr/bin/chage":
		default:
			return nil, ErrUnsafe
		}
		help, err := run(ctx, cmd.tool, "--help")
		if err != nil {
			return nil, err
		}
		// Selection is read-only and complete before authority consumption. chage on
		// Ubuntu 24.04 supports --root rather than --prefix; there is no failed-effect
		// fallback. CAP_SYS_CHROOT belongs only to the fixed helper for this variant.
		if strings.Contains(string(help), "--prefix") {
			options[cmd.tool] = "--prefix"
		} else if cmd.tool == "/usr/bin/chage" && strings.Contains(string(help), "--root") {
			options[cmd.tool] = "--root"
		} else {
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
