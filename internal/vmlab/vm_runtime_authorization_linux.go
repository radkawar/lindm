// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"os"
	"runtime"
	"strings"
	"time"

	"lindm/internal/devlab"
)

// VMRuntimeAuthorizationEvidence keeps the controller/server platform distinct
// from the installed agent's guest. A guest run is not server-platform evidence.
type VMRuntimeAuthorizationEvidence struct {
	ServerOS           string                               `json:"server_os"`
	ServerArchitecture string                               `json:"server_architecture"`
	ServerOSRelease    string                               `json:"server_os_release"`
	GuestOSRelease     string                               `json:"guest_os_release"`
	GuestKernel        string                               `json:"guest_kernel"`
	Authority          *devlab.RuntimeAuthorizationEvidence `json:"authority,omitempty"`
}

func exerciseRuntimeAuthorization(ctx context.Context, vm *guestVM, fixture *devlab.AuthorityFixture, result *VMDispatchResult) error {
	evidence := &VMRuntimeAuthorizationEvidence{ServerOS: runtime.GOOS, ServerArchitecture: runtime.GOARCH}
	result.RuntimeAuthorization = evidence
	serverRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	evidence.ServerOSRelease = string(serverRelease)
	guestRelease, err := vm.run(ctx, "cat /etc/os-release", nil, 16<<10, 10*time.Second)
	if err != nil {
		return err
	}
	evidence.GuestOSRelease = string(guestRelease)
	kernel, err := vm.run(ctx, "uname -srmo", nil, 4096, 10*time.Second)
	if err != nil {
		return err
	}
	evidence.GuestKernel = strings.TrimSpace(string(kernel))
	evidence.Authority, err = devlab.ExerciseRuntimeAuthorization(ctx, fixture, result.DeviceID)
	return err
}
