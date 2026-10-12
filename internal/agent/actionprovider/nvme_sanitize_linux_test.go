//go:build linux

package actionprovider

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestNVMeFormatSubmitsOnlyApprovedMethodAfterDurableGate(t *testing.T) {
	for _, test := range []struct {
		method agentv1.SanitizeMethod
		cdw10  uint32
	}{
		{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, 515},
		{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_CRYPTO_ERASE, 1027},
	} {
		gates, rechecks, calls := 0, 0, 0
		p := &Provider{admin: fakeNVMeAdmin(func(command nvmeAdminCommand, length int) ([]byte, uint32, error) {
			calls++
			want := nvmeAdminCommand{Opcode: 0x80, NSID: 7, CDW10: test.cdw10, TimeoutMS: nvmeAdminTimeoutMS}
			if gates != 1 || rechecks != 1 || command != want || length != 0 {
				t.Fatalf("unguarded or different method: %+v, gates=%d", command, gates)
			}
			return nil, 0, nil
		})}
		result := &agentv1.NVMeSanitizeVerification{}
		gate := func(context.Context) error { gates++; return nil }
		revalidate := func(context.Context) error {
			if gates != 1 || calls != 0 {
				t.Fatal("native binding not rechecked after gate and before effect")
			}
			rechecks++
			return nil
		}
		if err := p.startNVMeCommand(t.Context(), nil, test.method, 7, 3, gate, revalidate, result); err != nil || gates != 1 || rechecks != 1 || calls != 1 || !result.GetNativeCommandCompleted() {
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
	p := &Provider{admin: fakeNVMeAdmin(func(nvmeAdminCommand, int) ([]byte, uint32, error) { calls++; return nil, 0, nil })}
	denied := errors.New("authority expired")
	err := p.startNVMeCommand(t.Context(), nil, agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, 1, 0, func(context.Context) error { return denied }, func(context.Context) error {
		t.Fatal("native recheck ran after denied gate")
		return nil
	}, &agentv1.NVMeSanitizeVerification{})
	if !errors.Is(err, denied) || errors.Is(err, ErrOutcomeUnknown) || calls != 0 {
		t.Fatalf("denied authority issued effect: %v calls=%d", err, calls)
	}
}

func TestNVMeUncertainOrUnsupportedCommandNeverFallsBackOrRetries(t *testing.T) {
	for _, nativeErr := range []error{context.Canceled, context.DeadlineExceeded, ErrUnsupported, errors.New("controller I/O failure")} {
		for _, method := range []agentv1.SanitizeMethod{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE} {
			calls := 0
			p := &Provider{admin: fakeNVMeAdmin(func(command nvmeAdminCommand, _ int) ([]byte, uint32, error) {
				calls++
				if command.Opcode != 0x80 && command.Opcode != 0x84 {
					t.Fatal("native method silently replaced")
				}
				return nil, 0, nativeErr
			})}
			result := &agentv1.NVMeSanitizeVerification{}
			err := p.startNVMeCommand(t.Context(), nil, method, 1, 0, func(context.Context) error { return nil }, func(context.Context) error { return nil }, result)
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
		argument uint32
	}{
		{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE, 2, 2},
		{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_CRYPTO_ERASE, 4, 4},
	} {
		for _, status := range []uint16{0x101, 1, 3, 0x104} {
			calls := 0
			p := &Provider{admin: fakeNVMeAdmin(func(command nvmeAdminCommand, length int) ([]byte, uint32, error) {
				calls++
				if calls == 1 {
					want := nvmeAdminCommand{Opcode: 0x84, CDW10: test.argument, TimeoutMS: nvmeAdminTimeoutMS}
					if command != want || length != 0 {
						t.Fatalf("wrong sanitize command: %+v", command)
					}
					return nil, 0, nil
				}
				if command.Opcode != 0x02 || length != nvmeSanitizeLogBytes {
					t.Fatalf("sanitization restarted instead of polling: %+v", command)
				}
				return nvmeSanitizeLogFixture(0xffff, status, test.command), 0, nil
			})}
			result := &agentv1.NVMeSanitizeVerification{}
			err := p.startNVMeCommand(t.Context(), nil, test.method, 1, 0, func(context.Context) error { return nil }, func(context.Context) error { return nil }, result)
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
	p := &Provider{admin: fakeNVMeAdmin(func(command nvmeAdminCommand, _ int) ([]byte, uint32, error) {
		calls++
		if calls == 1 {
			return nil, 0, nil
		}
		if calls != 2 || command.Opcode != 0x02 {
			t.Fatalf("unexpected command after consumption: %+v", command)
		}
		cancel()
		return nvmeSanitizeLogFixture(1234, 2, 2), 0, nil
	})}
	result := &agentv1.NVMeSanitizeVerification{}
	err := p.startNVMeCommand(ctx, nil, agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE, 1, 0, func(context.Context) error { return nil }, func(context.Context) error { return nil }, result)
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, context.Canceled) || calls != 2 || result.GetNativeCommandCompleted() || result.GetSanitizeStatus() != 2 || result.GetSanitizeProgress() != 1234 || result.GetSanitizeCommandDword10() != 2 {
		t.Fatalf("interruption lost durable partial evidence: %v calls=%d result=%v", err, calls, result)
	}
}

func TestNVMeCommandRefusesIdentityChangesDuringDurableGate(t *testing.T) {
	// Injected protocol observations, not native device qualification. Exercise
	// the effect boundary with real plan parsing and a gate-time identity change.
	for _, tc := range []struct {
		name   string
		mutate func(*agentv1.SanitizeAction, []byte, []byte, *uint32)
	}{
		{"namespace NID disappears", func(_ *agentv1.SanitizeAction, _, n []byte, _ *uint32) { clear(n[104:128]) }},
		{"namespace basis downgrade", func(a *agentv1.SanitizeAction, _, n []byte, _ *uint32) {
			clear(n[104:128])
			a.Target.Wwn = "nvme.1b36-746573742d636f6e74726f6c6c6572-646973706f7361626c65204e564d652066697874757265-00000001"
		}},
		{"controller serial", func(_ *agentv1.SanitizeAction, c, _ []byte, _ *uint32) { c[4] = 'X' }},
		{"controller model", func(_ *agentv1.SanitizeAction, c, _ []byte, _ *uint32) { c[24] = 'X' }},
		{"controller firmware", func(_ *agentv1.SanitizeAction, c, _ []byte, _ *uint32) { c[64] = '2' }},
		{"controller vendor", func(_ *agentv1.SanitizeAction, c, _ []byte, _ *uint32) { c[0]++ }},
		{"controller subsystem vendor", func(_ *agentv1.SanitizeAction, c, _ []byte, _ *uint32) { c[2]++ }},
		{"controller ID", func(_ *agentv1.SanitizeAction, c, _ []byte, _ *uint32) { c[78]++ }},
		{"namespace ID", func(_ *agentv1.SanitizeAction, _, _ []byte, nsid *uint32) { *nsid = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action := nvmeActionFixture(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, false)
			controller, namespace, inventory := nvmeControllerFixture(), nvmeNamespaceFixture(), nvmeNamespaceListFixture(1)
			nsid := uint32(1)
			before, err := nvmePlan(action, nsid, controller, namespace, inventory, inventory)
			if err != nil {
				t.Fatal(err)
			}
			calls, gates, rechecks := 0, 0, 0
			p := &Provider{admin: fakeNVMeAdmin(func(nvmeAdminCommand, int) ([]byte, uint32, error) { calls++; return nil, 0, nil })}
			gate := func(context.Context) error {
				gates++
				tc.mutate(action, controller, namespace, &nsid)
				return nil
			}
			revalidate := func(context.Context) error {
				rechecks++
				current, err := nvmePlan(action, nsid, controller, namespace, inventory, inventory)
				if err != nil || !proto.Equal(current, before) {
					return errors.Join(ErrConflict, err)
				}
				return nil
			}
			result := &agentv1.NVMeSanitizeVerification{ObservedScope: before}
			err = p.startNVMeCommand(t.Context(), nil, action.Method, 1, 0, gate, revalidate, result)
			if !errors.Is(err, ErrConflict) || errors.Is(err, ErrOutcomeUnknown) || calls != 0 || gates != 1 || rechecks != 1 || result.GetNativeCommandCompleted() {
				t.Fatalf("changed native binding issued effect: %v calls=%d gates=%d rechecks=%d result=%v", err, calls, gates, rechecks, result)
			}
		})
	}
}
