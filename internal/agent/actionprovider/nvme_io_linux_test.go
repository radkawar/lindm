//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestNVMeAdminUsesClosedCommandAndExactInheritedDescriptor(t *testing.T) {
	// An ordinary temporary file stands in for descriptor transport only; the
	// injected runner does not invoke any native tool or ioctl.
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
	p := &Provider{run: func(_ context.Context, request nativeRequest) ([]byte, error) {
		calls++
		want := []string{"admin-passthru", "/proc/self/fd/3", "--opcode=6", "--namespace-id=7", "--cdw10=0", "--timeout=60000", "--data-len=4096", "--read", "--raw-binary"}
		if request.command != nvme || !slices.Equal(request.args, want) || len(request.files) != 1 || request.files[0] != file || len(request.input) != 0 {
			t.Fatalf("unexpected native request: %+v", request)
		}
		return make([]byte, 4096), nil
	}}
	if _, err := p.nvmeAdmin(t.Context(), file, 6, 7, 0, 4096); err != nil || calls != 1 {
		t.Fatalf("native read: %v, calls=%d", err, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.nvmeAdmin(ctx, file, 6, 7, 0, 4096); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled native read issued: %v, calls=%d", err, calls)
	}
}

func TestNVMeAdminRejectsTruncatedAndOversizedReadback(t *testing.T) {
	for _, size := range []int{0, 4095, 4097, outputLimit + 1} {
		p := &Provider{run: func(context.Context, nativeRequest) ([]byte, error) { return make([]byte, size), nil }}
		if _, err := p.nvmeAdmin(t.Context(), nil, 6, 1, 0, 4096); !errors.Is(err, ErrNotVerified) {
			t.Fatalf("accepted native output of size %d: %v", size, err)
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
			p := &Provider{run: func(_ context.Context, request nativeRequest) ([]byte, error) {
				calls++
				if request.command != nvme || !slices.Contains(request.args, "--opcode=6") ||
					!slices.Contains(request.args, "--read") || !slices.Contains(request.args, "--raw-binary") ||
					!slices.Contains(request.args, "--data-len=4096") {
					t.Fatalf("discovery issued non-Identify command: %+v", request)
				}
				if calls == 1 && slices.Contains(request.args, "--namespace-id=0") && slices.Contains(request.args, "--cdw10=1") {
					return controllerData, nil
				}
				if calls == 2 && slices.Contains(request.args, "--namespace-id=1") && slices.Contains(request.args, "--cdw10=0") {
					return namespaceData, nil
				}
				t.Fatalf("unexpected discovery command: %+v", request)
				return nil, ErrUnsupported
			}}
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

func TestNVMeExplicitUnsupportedDiagnosticIsNotCompletionProof(t *testing.T) {
	for _, text := range []string{
		"NVMe status: INVALID_OPCODE: unsupported command",
		"NVMe status: Invalid Command Opcode",
		"NVMe status: INVALID_FIELD: unsupported field",
		"NVMe status: Invalid Field in Command",
	} {
		if !nvmeUnsupportedDiagnostic([]byte(text)) {
			t.Fatalf("explicit refusal not recognized: %q", text)
		}
	}
	for _, text := range []string{"", "Permission denied", "Input/output error", "Connection timed out", "Success"} {
		if nvmeUnsupportedDiagnostic([]byte(text)) {
			t.Fatalf("unrelated native result mislabeled unsupported: %q", text)
		}
	}
}
