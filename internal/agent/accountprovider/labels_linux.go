// SPDX-License-Identifier: Apache-2.0

//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// accountDatabases are the shadow databases whose labels, and their "-"
// backups' labels, a native account command must leave unchanged.
var accountDatabases = []string{"passwd", "shadow", "group", "gshadow"}

const selinuxLabel = "security.selinux"

// keepDatabaseLabels wraps the native runner so the account databases keep
// their SELinux labels. shadow 4.20 sets no file context for a database it
// rewrites under --prefix or --root: Tumbleweed's /etc/passwd then inherited
// etc_t from /etc, and chage, which runs confined as passwd_t, could no longer
// open it. After each command every rewritten database and its backup carry
// the label the database had before the command. Without SELinux (no
// selinuxfs) the runner is unchanged.
func keepDatabaseLabels(run nativeRun, etc string) nativeRun {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err != nil {
		return run
	}
	return labeledRun(run, etc, selinuxLabel)
}

func labeledRun(run nativeRun, etc, attribute string) nativeRun {
	return func(ctx context.Context, stdin []byte, tool string, args ...string) ([]byte, error) {
		labels := make(map[string][]byte, len(accountDatabases))
		for _, name := range accountDatabases {
			label, err := fileLabel(filepath.Join(etc, name), attribute)
			if errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return nil, err
			}
			if label != nil {
				labels[name] = label
			}
		}
		out, err := run(ctx, stdin, tool, args...)
		return out, errors.Join(err, restoreLabels(etc, attribute, labels))
	}
}

func restoreLabels(etc, attribute string, labels map[string][]byte) error {
	for name, label := range labels {
		for _, path := range []string{filepath.Join(etc, name), filepath.Join(etc, name+"-")} {
			current, err := fileLabel(path, attribute)
			if errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			if bytes.Equal(current, label) {
				continue
			}
			if err := unix.Lsetxattr(path, attribute, label, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// fileLabel is path's label, nil when it carries none.
func fileLabel(path, attribute string) ([]byte, error) {
	label := make([]byte, 4096)
	size, err := unix.Lgetxattr(path, attribute, label)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return label[:size], nil
}
