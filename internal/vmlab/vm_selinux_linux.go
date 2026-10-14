// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"strings"
	"time"
)

// guestSELinuxMode records the kernel's SELinux enforcement state. It reads
// selinuxfs rather than relying on getenforce, which Tumbleweed does not ship
// although it boots SELinux enforcing.
func guestSELinuxMode(ctx context.Context, vm *guestVM) (string, error) {
	out, err := vm.run(ctx, "if test -e /sys/fs/selinux/enforce; then cat /sys/fs/selinux/enforce; else printf absent; fi", nil, 128, 10*time.Second)
	if err != nil {
		return "", err
	}
	return selinuxModeFromEnforce(string(out))
}

func selinuxModeFromEnforce(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "1":
		return "Enforcing", nil
	case "0":
		return "Permissive", nil
	case "absent":
		return "Disabled", nil
	default:
		return "", errors.New("unexpected SELinux enforce state")
	}
}
