// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sysctlprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/inventory"
	"lindm/internal/platform"
)

func nativeBackend(ctx context.Context, product *resourcev1.PlatformProduct) (*resourcev1.BackendSelection, error) {
	if err := validateMessage(product); err != nil {
		return nil, err
	}
	if err := platform.Of(product).Gate(platform.Sysctl); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
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
	if !proto.Equal(actual, product) {
		return nil, ErrConflict
	}
	version, err := rootRead("/proc/sys/kernel/osrelease", 128)
	if err != nil {
		return nil, err
	}
	return &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_PROC_SYSCTL, NativeVersion: strings.TrimSpace(string(version)), ProviderVersion: "1", Product: proto.CloneOf(product)}, nil
}
