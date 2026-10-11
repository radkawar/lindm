//go:build linux

package sysctlprovider

import (
	"context"
	"errors"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/inventory"
)

func nativeBackend(ctx context.Context, platform *resourcev1.PlatformProduct) (*resourcev1.BackendSelection, error) {
	if err := validateMessage(platform); err != nil {
		return nil, err
	}
	switch platform.GetOsId() {
	case "ubuntu", "fedora":
	case "rhel", "almalinux":
		// Of Enterprise Linux only EL 9 is qualified.
		if !strings.HasPrefix(platform.GetVersion(), "9.") {
			return nil, ErrUnsupported
		}
	default:
		return nil, ErrUnsupported
	}
	for _, marker := range []string{"/run/ostree-booted", "/etc/NIXOS", "/etc/transactional-update.conf"} {
		if _, err := os.Stat(marker); err == nil {
			return nil, ErrUnsupported
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	actual, err := inventory.HostPlatform(ctx)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(actual, platform) {
		return nil, ErrConflict
	}
	version, err := protectedRead("/proc/sys/kernel/osrelease", 128)
	if err != nil {
		return nil, err
	}
	return &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_PROC_SYSCTL, NativeVersion: strings.TrimSpace(string(version)), ProviderVersion: "1", Product: proto.CloneOf(platform)}, nil
}
