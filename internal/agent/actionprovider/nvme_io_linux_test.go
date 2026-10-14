// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestNVMeAdminSubmitsClosedCommandOnPinnedDescriptor(t *testing.T) {
	// An ordinary temporary file stands in for the pinned descriptor only; the
	// injected submitter performs no ioctl.
	file, err := os.CreateTemp(t.TempDir(), "descriptor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	calls := 0
	p := &Provider{admin: func(got *os.File, command *nvmeAdminCommand, data []byte) (uint32, error) {
		calls++
		want := nvmeAdminCommand{Opcode: 6, NSID: 7, TimeoutMS: nvmeAdminTimeoutMS}
		if got != file || *command != want || len(data) != nvmeIdentifyBytes {
			t.Fatalf("unexpected admin submission: %+v data=%d", *command, len(data))
		}
		data[0] = 0x5a
		return 0, nil
	}}
	if data, err := p.nvmeAdmin(t.Context(), file, 6, 7, 0, nvmeIdentifyBytes); err != nil || calls != 1 || len(data) != nvmeIdentifyBytes || data[0] != 0x5a {
		t.Fatalf("native read: %v, calls=%d", err, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.nvmeAdmin(ctx, file, 6, 7, 0, nvmeIdentifyBytes); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled native read issued: %v, calls=%d", err, calls)
	}
	for _, length := range []int{-1, nvmeAdminMaxBytes + 1} {
		if _, err := p.nvmeAdmin(t.Context(), file, 6, 7, 0, length); !errors.Is(err, ErrUnsupported) || calls != 1 {
			t.Fatalf("unbounded read-back %d submitted: %v", length, err)
		}
	}
}

// The ioctl argument must match struct nvme_passthru_cmd and its _IOWR number.
func TestNVMeAdminCommandMatchesKernelABI(t *testing.T) {
	const size = 72
	if unsafe.Sizeof(nvmeAdminCommand{}) != size || unsafe.Offsetof(nvmeAdminCommand{}.Addr) != 24 || unsafe.Offsetof(nvmeAdminCommand{}.CDW10) != 40 || unsafe.Offsetof(nvmeAdminCommand{}.TimeoutMS) != 64 {
		t.Fatal("nvmeAdminCommand layout differs from struct nvme_passthru_cmd")
	}
	if want := uint32(3)<<30 | size<<16 | 'N'<<8 | 0x41; nvmeIoctlAdminCmd != want {
		t.Fatalf("NVME_IOCTL_ADMIN_CMD = %#x, want %#x", nvmeIoctlAdminCmd, want)
	}
}

// Only an explicit generic Invalid Command Opcode/Field completion is
// unsupported; any other status or submission error stays an ordinary failure.
// Neither is evidence that erasure occurred.
func TestNVMeAdminMapsCompletionStatus(t *testing.T) {
	for _, test := range []struct {
		status      uint32
		err         error
		unsupported bool
	}{
		{status: 0x01, unsupported: true},
		{status: 0x02, unsupported: true},
		{status: 0x4002, unsupported: true},
		{status: 0x101},
		{status: 0x06},
		{err: unix.EIO},
		{err: unix.EPERM},
	} {
		p := &Provider{admin: fakeNVMeAdmin(func(nvmeAdminCommand, int) ([]byte, uint32, error) { return nil, test.status, test.err })}
		data, err := p.nvmeAdmin(t.Context(), nil, 0x84, 0, 2, 0)
		if err == nil || data != nil || errors.Is(err, ErrUnsupported) != test.unsupported {
			t.Fatalf("status %#x err %v: got %v", test.status, test.err, err)
		}
	}
}

func TestNVMeScopeDiscoveryUsesReadOnlyNativeIdentity(t *testing.T) {
	// Protocol fixtures exercise discovery and approval binding, not real ioctls.
	for _, absent := range []bool{false, true} {
		for _, fallback := range []bool{false, true} {
			action := nvmeActionFixture(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, false)
			controllerData, namespaceData := nvmeControllerFixture(), nvmeNamespaceFixture()
			if absent {
				clear(namespaceData[104:128])
				action.Target.Wwn = ""
				action.NvmeScope.Identity.Basis = agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID
			}
			if fallback {
				action.Target.Wwn = "nvme.1b36-746573742d636f6e74726f6c6c6572-646973706f7361626c65204e564d652066697874757265-00000001"
				action.NvmeScope.Identity.Basis = agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID
			}
			calls := 0
			p := &Provider{admin: fakeNVMeAdmin(func(command nvmeAdminCommand, length int) ([]byte, uint32, error) {
				calls++
				if command.Opcode != 6 || length != nvmeIdentifyBytes {
					t.Fatalf("discovery issued non-Identify command: %+v", command)
				}
				if calls == 1 && command.NSID == 0 && command.CDW10 == 1 {
					return controllerData, 0, nil
				}
				if calls == 2 && command.NSID == 1 && command.CDW10 == 0 {
					return namespaceData, 0, nil
				}
				t.Fatalf("unexpected discovery command: %+v", command)
				return nil, 0, ErrUnsupported
			})}
			scope, err := p.readNVMeSanitizeScope(t.Context(), nil, action.Target, 1)
			if err != nil || calls != 2 || !proto.Equal(scope, action.NvmeScope) || scope.GetControllerWide() {
				t.Fatalf("discovered scope: %v %v, calls=%d", scope, err, calls)
			}
			action.NvmeScope = scope
			inventory := nvmeNamespaceListFixture(1)
			plan, err := nvmePlan(action, 1, controllerData, namespaceData, inventory, inventory)
			if err != nil || !proto.Equal(plan.GetScope(), scope) {
				t.Fatalf("discovered identity cannot bind native plan: %v %v", plan, err)
			}
		}
	}
}

func TestReadNVMeSanitizeScopeRefusesNonBlockDescriptor(t *testing.T) {
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	target := nvmeActionFixture(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, false).Target
	if _, err := ReadNVMeSanitizeScope(t.Context(), file, target); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("non-block descriptor accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ReadNVMeSanitizeScope(ctx, file, target); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled discovery accepted: %v", err)
	}
}

func TestNVMeSamplingDetectsUnchangedNonzeroMedia(t *testing.T) {
	data := bytes.Repeat([]byte{0xa5}, 1<<20)
	before, err := readNVMeSamples(t.Context(), bytes.NewReader(data), uint64(len(data)), nil)
	if err != nil || before.read != nvmeSampleCount {
		t.Fatalf("before samples: %v %d", err, before.read)
	}
	if _, err := readNVMeSamples(t.Context(), bytes.NewReader(data), uint64(len(data)), &before); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("unchanged data falsely verified: %v", err)
	}
	clear(data)
	after, err := readNVMeSamples(t.Context(), bytes.NewReader(data), uint64(len(data)), &before)
	if err != nil || after.read != nvmeSampleCount || after.digest == before.digest {
		t.Fatalf("changed data samples: %v %d", err, after.read)
	}
	// Zero preimages may remain zero; NVMe may also return an indeterminate
	// nonzero erased pattern. Neither pattern alone is native completion proof.
	if _, err := readNVMeSamples(t.Context(), bytes.NewReader(data), uint64(len(data)), &after); err != nil {
		t.Fatal(err)
	}
	for i := range data {
		data[i] = 0xff
	}
	if _, err := readNVMeSamples(t.Context(), bytes.NewReader(data), uint64(len(data)), &before); err != nil {
		t.Fatalf("valid indeterminate erase pattern rejected: %v", err)
	}
}

func TestNVMeSamplingRejectsShortReadAndCancellation(t *testing.T) {
	if _, err := readNVMeSamples(t.Context(), bytes.NewReader(nil), 4096, nil); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("short sample read: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if samples, err := readNVMeSamples(ctx, bytes.NewReader(make([]byte, 4096)), 4096, nil); !errors.Is(err, context.Canceled) || samples.read != 0 {
		t.Fatalf("canceled sampling: %v %d", err, samples.read)
	}
}
