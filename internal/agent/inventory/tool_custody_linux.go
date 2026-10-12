//go:build linux

package inventory

import (
	"context"
	"errors"
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/custody"
)

// toolCustodyPaths are the directories every native tool resolves through:
// nativeexec runs only executables under /usr/ and refuses one whose ancestry
// is not root-protected. Fedora Cloud Base 43-1.6 ships / as 0775.
var toolCustodyPaths = []string{"/", "/usr", "/usr/bin", "/usr/sbin", "/usr/libexec"}

// collectToolCustody reports the first tool directory that is not
// root-protected. A directory absent from the image cannot hold a tool.
func collectToolCustody(ctx context.Context, s detailSources) *inventoryv1.NativeToolCustody {
	for _, path := range toolCustodyPaths {
		if err := ctx.Err(); err != nil {
			return &inventoryv1.NativeToolCustody{Status: statusFor(err)}
		}
		info, err := s.stat(path)
		if errors.Is(err, fs.ErrNotExist) && path != "/" && path != "/usr" {
			continue
		}
		if err != nil {
			return &inventoryv1.NativeToolCustody{Status: statusFor(err)}
		}
		native, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() {
			return &inventoryv1.NativeToolCustody{Status: invalid}
		}
		stat := unix.Stat_t{Uid: native.Uid, Mode: native.Mode}
		if !custody.RootProtected(&stat) {
			return &inventoryv1.NativeToolCustody{Status: success, UnprotectedPath: path, OwnerUid: native.Uid, Mode: native.Mode & 0o7777}
		}
	}
	return &inventoryv1.NativeToolCustody{Status: success}
}
