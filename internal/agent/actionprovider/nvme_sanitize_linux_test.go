//go:build linux

package actionprovider

import (
	"context"
	"errors"
	"slices"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestNVMeFormatSubmitsOnlyApprovedMethodAfterDurableGate(t *testing.T) {
	for _, test := range []struct {
		method agentv1.SanitizeMethod
		cdw10  string
	}{
		{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, "--cdw10=515"},
		{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_CRYPTO_ERASE, "--cdw10=1027"},
	} {
		gates, calls := 0, 0
		p := &Provider{run: func(_ context.Context, request nativeRequest) ([]byte, error) {
			calls++
			want := []string{"admin-passthru", "/proc/self/fd/3", "--opcode=128", "--namespace-id=7", test.cdw10, "--timeout=60000"}
			if gates != 1 || request.command != nvme || !slices.Equal(request.args, want) {
				t.Fatalf("unguarded or different method: %+v, gates=%d", request, gates)
			}
			return nil, nil
		}}
		result := &agentv1.NVMeSanitizeVerification{}
		gate := func(context.Context) error { gates++; return nil }
		if err := p.startNVMeCommand(t.Context(), nil, test.method, 7, 3, gate, result); err != nil || gates != 1 || calls != 1 || !result.GetNativeCommandCompleted() {
			t.Fatalf("format completion: %v gates=%d calls=%d result=%v", err, gates, calls, result)
		}
		// Native CQE alone must not manufacture sampling or overall verification.
		if result.GetSamplesRead() != 0 || len(result.GetSampleSha256()) != 0 {
			t.Fatal("command completion fabricated sampling")
		}
	}
}

func TestNVMeDeniedGateNeverIssuesCommand(t *testing.T) {
	calls := 0
	p := &Provider{run: func(context.Context, nativeRequest) ([]byte, error) { calls++; return nil, nil }}
	denied := errors.New("authority expired")
	err := p.startNVMeCommand(t.Context(), nil, agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, 1, 0, func(context.Context) error { return denied }, &agentv1.NVMeSanitizeVerification{})
	if !errors.Is(err, denied) || errors.Is(err, ErrOutcomeUnknown) || calls != 0 {
		t.Fatalf("denied authority issued effect: %v calls=%d", err, calls)
	}
}

func TestNVMeUncertainOrUnsupportedCommandNeverFallsBackOrRetries(t *testing.T) {
	for _, nativeErr := range []error{context.Canceled, context.DeadlineExceeded, ErrUnsupported, errors.New("controller I/O failure")} {
		for _, method := range []agentv1.SanitizeMethod{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE} {
			calls := 0
			p := &Provider{run: func(_ context.Context, request nativeRequest) ([]byte, error) {
				calls++
				if request.command != nvme {
					t.Fatal("native method silently replaced")
				}
				return nil, nativeErr
			}}
			result := &agentv1.NVMeSanitizeVerification{}
			err := p.startNVMeCommand(t.Context(), nil, method, 1, 0, func(context.Context) error { return nil }, result)
			if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, nativeErr) || calls != 1 || result.GetNativeCommandCompleted() {
				t.Fatalf("ambiguous command lost consumed unknown state: %v calls=%d result=%v", err, calls, result)
			}
		}
	}
}

func TestNVMeSanitizeRequiresNativeCompletionLog(t *testing.T) {
	for _, test := range []struct {
		method   agentv1.SanitizeMethod
		command  uint32
		argument string
	}{
		{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE, 2, "--cdw10=2"},
		{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_CRYPTO_ERASE, 4, "--cdw10=4"},
	} {
		for _, status := range []uint16{0x101, 1, 3, 0x104} {
			calls := 0
			p := &Provider{run: func(_ context.Context, request nativeRequest) ([]byte, error) {
				calls++
				if calls == 1 {
					want := []string{"admin-passthru", "/proc/self/fd/3", "--opcode=132", "--namespace-id=0", test.argument, "--timeout=60000"}
					if !slices.Equal(request.args, want) {
						t.Fatalf("wrong sanitize command: %v", request.args)
					}
					return nil, nil
				}
				if !slices.Contains(request.args, "--opcode=2") || !slices.Contains(request.args, "--data-len=512") {
					t.Fatalf("sanitization restarted instead of polling: %v", request.args)
				}
				return nvmeSanitizeLogFixture(0xffff, status, test.command), nil
			}}
			result := &agentv1.NVMeSanitizeVerification{}
			err := p.startNVMeCommand(t.Context(), nil, test.method, 1, 0, func(context.Context) error { return nil }, result)
			if calls != 2 || result.GetSanitizeStatus() != uint32(status) || result.GetSanitizeCommandDword10() != test.command {
				t.Fatalf("native status not retained: calls=%d result=%v", calls, result)
			}
			if status == 0x101 {
				if err != nil || !result.GetNativeCommandCompleted() {
					t.Fatalf("valid controller completion: %v", err)
				}
			} else if !errors.Is(err, ErrOutcomeUnknown) || result.GetNativeCommandCompleted() {
				t.Fatalf("invalid native log reported success: %v result=%v", err, result)
			}
		}
	}
}

func TestNVMeInterruptedPollingRetainsPartialEvidenceWithoutRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	p := &Provider{run: func(_ context.Context, request nativeRequest) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		if calls != 2 || !slices.Contains(request.args, "--opcode=2") {
			t.Fatalf("unexpected command after consumption: %v", request.args)
		}
		cancel()
		return nvmeSanitizeLogFixture(1234, 2, 2), nil
	}}
	result := &agentv1.NVMeSanitizeVerification{}
	err := p.startNVMeCommand(ctx, nil, agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE, 1, 0, func(context.Context) error { return nil }, result)
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, context.Canceled) || calls != 2 || result.GetNativeCommandCompleted() || result.GetSanitizeStatus() != 2 || result.GetSanitizeProgress() != 1234 || result.GetSanitizeCommandDword10() != 2 {
		t.Fatalf("interruption lost durable partial evidence: %v calls=%d result=%v", err, calls, result)
	}
}
