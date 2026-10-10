//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"testing"
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
