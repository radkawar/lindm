//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/recovery"
	"lindm/internal/agent/recoveryboot"
)

// The native boot seam never touches host firmware, disks or reboot. Signature,
// original journal and off-target journal paths below are real implementations.
type recoveryBootBoundary struct {
	key             ed25519.PrivateKey
	stages          atomic.Int32
	arms            atomic.Int32
	reboots         atomic.Int32
	provisions      atomic.Int32
	beforeArm       func()
	beforeStage     func() error
	beforeFinalGate func()
	custodyCheck    func(context.Context) error
	capsule         []byte
	armDeadline     time.Time
}

func (n *recoveryBootBoundary) Preflight(ctx context.Context, request recoveryboot.StageRequest) error {
	if request.TrustedTPMCustody != nil {
		return request.TrustedTPMCustody(ctx)
	}
	return nil
}
func (n *recoveryBootBoundary) ProvisionKey(string) (ed25519.PrivateKey, error) {
	n.provisions.Add(1)
	return bytes.Clone(n.key), nil
}
func (n *recoveryBootBoundary) Stage(ctx context.Context, request recoveryboot.StageRequest) (recoveryBootStaged, error) {
	n.custodyCheck = request.TrustedTPMCustody
	if n.custodyCheck != nil {
		if err := n.custodyCheck(ctx); err != nil {
			return nil, err
		}
	}
	if n.beforeStage != nil {
		if err := n.beforeStage(); err != nil {
			return nil, err
		}
	}
	n.stages.Add(1)
	return n, nil
}
func (n *recoveryBootBoundary) Arm(ctx context.Context, gate func(context.Context) error) error {
	n.armDeadline, _ = ctx.Deadline()
	if n.beforeArm != nil {
		n.beforeArm()
	}
	if n.custodyCheck != nil {
		if err := n.custodyCheck(ctx); err != nil {
			return err
		}
	}
	if err := gate(ctx); err != nil {
		return err
	}
	if n.beforeFinalGate != nil {
		n.beforeFinalGate()
	}
	if err := gate(ctx); err != nil {
		return err
	}
	n.arms.Add(1)
	return nil
}
func (n *recoveryBootBoundary) Rollback(context.Context) error { return nil }
func (n *recoveryBootBoundary) Reboot(context.Context) error   { n.reboots.Add(1); return nil }
func (n *recoveryBootBoundary) WriteCapsule(directory, actionID string, snapshot []byte) (string, []byte, error) {
	path := filepath.Join(directory, actionID+".capsule")
	if err := os.WriteFile(path, snapshot, 0600); err != nil {
		return "", nil, err
	}
	n.capsule = bytes.Clone(snapshot)
	return path, digestBytes(snapshot), nil
}

func (n *actionBoundary) PrepareRecovery(_ context.Context, spec *agentv1.DeviceActionSpec) (*agentv1.DeviceActionPlan, error) {
	return &agentv1.DeviceActionPlan{Spec: proto.CloneOf(spec), Before: &agentv1.DeviceActionObservation{ObservedAt: protoTimestamp(time.Date(2031, 9, 1, 0, 0, 0, 0, time.UTC)), Supported: true, OffTargetJournal: true, Target: proto.CloneOf(spec.GetSanitize().GetTarget())}}, nil
}
func (n *actionBoundary) RecoveryTargetDevices(context.Context, *agentv1.DeviceActionPlan) ([]string, error) {
	return []string{"/dev/qualified-test-target"}, nil
}

func newRecoveryBootFixture(t *testing.T) (*deviceActionFixture, *recoveryBootBoundary, *agentv1.DeviceActionIntent) {
	t.Helper()
	return newRecoveryBootFixtureWithSetup(t, nil)
}

func newRecoveryBootFixtureWithSetup(t *testing.T, setup func(*deviceActionFixture)) (*deviceActionFixture, *recoveryBootBoundary, *agentv1.DeviceActionIntent) {
	t.Helper()
	f := newDeviceActionFixture(t)
	plan, start := delegate(t, f.planKey), delegate(t, f.startKey)
	plan.Capabilities, start.Capabilities = []string{"device.sanitize.v1"}, []string{"device.sanitize.v1"}
	start.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
	callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, delegationDocument(f.fix.deploy.String(), 1, 2, 0, f.now, plan, start), f.fix.rootKey)})
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	image := bytes.Repeat([]byte{9}, 32)
	f.svc.recoveryConfig = &RecoveryBootConfig{StateDirectory: directory, ImagePath: "/qualified/recovery.efi", ImageSHA256: image, ImageSize: 1024, CertificatePath: "/qualified/signing.pem", CertificateSHA256: bytes.Repeat([]byte{7}, 32), ESPPath: "/qualified/esp", Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET}
	native := &recoveryBootBoundary{key: testKey(t)}
	f.svc.recoveryBoot = native
	if setup != nil {
		setup(f)
	}
	target := &agentv1.StorageTarget{Wwn: "original-whole-disk", Serial: "original-disk-serial", SizeBytes: 1 << 30}
	media, err := digestMessage(target)
	if err != nil {
		t.Fatal(err)
	}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: target, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE, Recovery: &agentv1.RecoveryBootSpec{ImageSha256: image, MediaSha256: media, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}}}}
	intent := f.actionIntent(t, 1, spec)
	intent.DelegationVersion = 2
	envelope := mustSign(t, f.svc.authority, intent, f.planKey)
	if _, err := f.svc.PrepareDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.PrepareDeviceActionRecoveryRequest{IntentEnvelope: envelope})); err != nil {
		t.Fatal(err)
	}
	return f, native, intent
}

func recoveryBootEnvelopes(t *testing.T, f *deviceActionFixture, intent *agentv1.DeviceActionIntent) ([]byte, []byte, *agentv1.DeviceActionStartGrant) {
	t.Helper()
	record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
	handoff, err := protectedRecoveryHandoff(record)
	if err != nil {
		t.Fatal(err)
	}
	credential := mustSign(t, f.svc.authority, &agentv1.DeviceActionRecoveryCredential{CredentialId: uuid.NewString(), Handoff: handoff, RootVersion: 1, DelegationVersion: 2, IssuedAt: protoTimestamp(f.now), ExpiresAt: protoTimestamp(f.now.Add(5 * time.Minute))}, f.startKey)
	binding := &agentv1.DeviceActionApprovalBinding{DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SpecSha256: intent.GetSpecSha256(), ExpiresAt: intent.GetExpiresAt()}
	grant := &agentv1.DeviceActionStartGrant{Challenge: proto.CloneOf(record.GetChallenge()), ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), RootVersion: 1, DelegationVersion: 2, NotBefore: record.GetChallenge().GetIssuedAt(), ExpiresAt: record.GetChallenge().GetExpiresAt(), Approvals: []*agentv1.DeviceActionHumanApproval{{ActorId: intent.GetActorId(), AuthorizationVersion: 1, Binding: proto.CloneOf(binding)}, {ActorId: uuid.NewString(), AuthorizationVersion: 1, Binding: proto.CloneOf(binding)}}}
	digest, err := digestMessage(handoff)
	if err != nil {
		t.Fatal(err)
	}
	boot := mustSign(t, f.svc.authority, &agentv1.DeviceActionRecoveryBootGrant{Grant: grant, HandoffSha256: digest}, f.startKey)
	return credential, boot, grant
}

func TestRecoveryBootRequiresPurposeGrantAndDurableConsumption(t *testing.T) {
	f, native, intent := newRecoveryBootFixture(t)
	credential, boot, ordinary := recoveryBootEnvelopes(t, f, intent)
	for _, envelope := range [][]byte{nil, credential, mustSign(t, f.svc.authority, ordinary, f.startKey)} {
		if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: envelope})); err == nil {
			t.Fatal("credential or ordinary start authorized reboot")
		}
	}
	if _, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: boot})); err == nil {
		t.Fatal("BOOT-purpose authority entered ordinary effect path")
	}
	native.beforeStage = func() error {
		r, _, err := f.svc.store.LoadDeviceAction(t.Context(), intent.GetActionId())
		if err != nil {
			return err
		}
		if r.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || !bytes.Equal(r.GetRecoveryBootGrantEnvelope(), boot) || len(r.GetStartGrantEnvelope()) != 0 {
			return errors.New("boot staging preceded durable purpose consumption")
		}
		return nil
	}
	request := &agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot}
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	f.svc.operations.Wait()
	if native.stages.Load() != 1 || native.arms.Load() != 1 || native.reboots.Load() != 1 {
		t.Fatal("fresh boot did not reach native one-shot boundary")
	}
	offTarget, err := recovery.OpenJournal(f.svc.recoveryConfig.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	stored := new(agentv1.RecoveryJournal)
	found, err := offTarget.Load(stored)
	if err != nil || !found || !bytes.Equal(stored.GetCredentialEnvelope(), credential) {
		t.Fatalf("scoped recovery credential missing: found=%v err=%v", found, err)
	}
	if consumed, err := offTarget.Consumed(); err != nil || consumed {
		t.Fatalf("boot consumed wipe marker: consumed=%v err=%v", consumed, err)
	}
	if err := offTarget.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	if native.reboots.Load() != 1 {
		t.Fatal("exact boot grant retry rebooted twice")
	}
	f.reopenActions(t)
	status := awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	if status.GetFailure() != agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED {
		t.Fatal("original executor restart fabricated recovery proof")
	}
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	if native.reboots.Load() != 1 {
		t.Fatal("restart replayed boot commitment")
	}
}

func TestRecoveryBootRechecksExpiryImmediatelyBeforeArm(t *testing.T) {
	f, native, intent := newRecoveryBootFixture(t)
	credential, boot, _ := recoveryBootEnvelopes(t, f, intent)
	native.beforeArm = func() { f.bootClock.Add(uint64(31 * time.Second)) }
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot})); err != nil {
		t.Fatal(err)
	}
	f.svc.operations.Wait()
	awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	if native.arms.Load() != 0 || native.reboots.Load() != 0 {
		t.Fatal("long-lived credential extended BOOT grant beyond 30 seconds")
	}
}

func TestRecoveryBootRejectsDifferentGrantOnRetry(t *testing.T) {
	f, native, intent := newRecoveryBootFixture(t)
	credential, boot, _ := recoveryBootEnvelopes(t, f, intent)
	request := &agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot}
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	f.svc.operations.Wait()
	changed := proto.CloneOf(request)
	changed.BootGrantEnvelope = append(bytes.Clone(boot), ' ')
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed reboot grant retry accepted: %v", err)
	}
	if native.reboots.Load() != 1 {
		t.Fatal("changed grant repeated reboot")
	}
}

func TestRecoveryBootAuthorityChangeBeforeArmStopsReboot(t *testing.T) {
	for _, cause := range []string{"delegation", "reboot", "incarnation"} {
		t.Run(cause, func(t *testing.T) {
			f, native, intent := newRecoveryBootFixture(t)
			credential, boot, _ := recoveryBootEnvelopes(t, f, intent)
			native.beforeArm = func() {
				switch cause {
				case "delegation":
					f.actionDelegation(t, 3)
				case "reboot":
					f.boot = uuid.NewString()
				case "incarnation":
					f.svc.incarnation = uuid.NewString()
				}
			}
			if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot})); err != nil {
				t.Fatal(err)
			}
			f.svc.operations.Wait()
			awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
			if native.arms.Load() != 0 || native.reboots.Load() != 0 {
				t.Fatal("revoked BOOT authority reached native arm or reboot")
			}
		})
	}
}

func TestRecoveryBootRequiresTwoHumansEvenWithCredential(t *testing.T) {
	f, native, intent := newRecoveryBootFixture(t)
	credential, _, grant := recoveryBootEnvelopes(t, f, intent)
	record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
	handoff, err := protectedRecoveryHandoff(record)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := digestMessage(handoff)
	if err != nil {
		t.Fatal(err)
	}
	grant.Approvals = nil
	boot := mustSign(t, f.svc.authority, &agentv1.DeviceActionRecoveryBootGrant{Grant: grant, HandoffSha256: digest}, f.startKey)
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot})); err == nil {
		t.Fatal("long-lived recovery credential bypassed two-human BOOT approval")
	}
	if native.stages.Load() != 0 || native.arms.Load() != 0 || native.reboots.Load() != 0 {
		t.Fatal("unapproved recovery changed boot state")
	}
}

type recoveryPendingBoundary struct {
	key        ed25519.PrivateKey
	store      *recoveryStoreBoundary
	beforeSeal func() error
	seals      atomic.Int32
	closes     atomic.Int32
}

func (p *recoveryPendingBoundary) PublicKey() ed25519.PublicKey {
	return bytes.Clone(p.key[ed25519.SeedSize:])
}
func (p *recoveryPendingBoundary) Check(context.Context) error {
	if p.closes.Load() != 0 {
		return errors.New("pending custody closed")
	}
	return nil
}
func (p *recoveryPendingBoundary) Close() error { p.closes.Add(1); return nil }
func (p *recoveryPendingBoundary) Seal(_ context.Context, handoff *agentv1.DeviceActionRecoveryHandoff, pcr []byte, initial *agentv1.RecoveryJournal) (recoveryTPMStore, error) {
	p.seals.Add(1)
	if p.beforeSeal != nil {
		if err := p.beforeSeal(); err != nil {
			return nil, err
		}
	}
	if len(pcr) != 32 || !proto.Equal(handoff, initial.GetHandoff()) {
		return nil, errors.New("unbound TPM custody request")
	}
	p.store.initial = proto.CloneOf(initial)
	return p.store, nil
}

type recoveryStoreBoundary struct {
	initial *agentv1.RecoveryJournal
	checks  atomic.Int32
	closes  atomic.Int32
}

func (s *recoveryStoreBoundary) Snapshot() ([]byte, error) { return proto.Marshal(s.initial) }
func (s *recoveryStoreBoundary) Check(context.Context) error {
	s.checks.Add(1)
	if s.closes.Load() != 0 {
		return errors.New("sealed custody closed")
	}
	return nil
}
func (s *recoveryStoreBoundary) Close() error { s.closes.Add(1); return nil }

func TestRecoveryBootTPMCustodyConsumesBeforeSealAndNeverReplays(t *testing.T) {
	for _, phase := range []string{"sealed", "interrupted_reservation"} {
		t.Run(phase, func(t *testing.T) {
			interrupted := phase == "interrupted_reservation"
			pending := &recoveryPendingBoundary{key: testKey(t), store: &recoveryStoreBoundary{}}
			f, native, intent := newRecoveryBootFixtureWithSetup(t, func(f *deviceActionFixture) {
				f.svc.recoveryConfig.Custody = agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM
				f.svc.recoveryConfig.ExpectedPCR11SHA256 = bytes.Repeat([]byte{3}, 32)
				f.svc.recoveryTPM = func() (recoveryTPMPending, error) { return pending, nil }
			})
			credential, boot, _ := recoveryBootEnvelopes(t, f, intent)
			if pending.seals.Load() != 0 || native.provisions.Load() != 0 {
				t.Fatal("Prepare changed TPM or provisioned a disk key")
			}
			pending.beforeSeal = func() error {
				record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
				if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || !bytes.Equal(record.GetRecoveryBootGrantEnvelope(), boot) {
					return errors.New("TPM mutation preceded durable BOOT consumption")
				}
				if interrupted {
					return errors.New("reservation interrupted after native mutation")
				}
				return nil
			}
			request := &agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot}
			if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(request)); err != nil {
				t.Fatal(err)
			}
			f.svc.operations.Wait()
			state := agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
			if interrupted {
				state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
			}
			awaitDeviceAction(t, f.svc, intent.GetActionId(), state)
			if pending.seals.Load() != 1 || pending.closes.Load() != 1 || f.svc.recoveryPending != nil {
				t.Fatal("pending TPM key ownership was not consumed exactly once")
			}
			if interrupted {
				if native.stages.Load() != 0 || native.reboots.Load() != 0 {
					t.Fatal("ambiguous TPM reservation reached boot")
				}
			} else {
				if native.reboots.Load() != 1 || pending.store.checks.Load() < 2 || pending.store.closes.Load() != 1 {
					t.Fatal("sealed custody was not rechecked and released")
				}
				checkpoint := new(agentv1.RecoveryJournal)
				if err := proto.Unmarshal(native.capsule, checkpoint); err != nil {
					t.Fatal(err)
				}
				if checkpoint.GetHandoff().GetCustody() != agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM || checkpoint.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED || len(checkpoint.GetStartGrantEnvelope()) != 0 || checkpoint.GetCheckpoint() != nil || !bytes.Equal(checkpoint.GetCredentialEnvelope(), credential) || !proto.Equal(checkpoint.GetAcceptedRoot(), checkpoint.GetCredentialRoot()) || checkpoint.GetTrustAcceptedAt() == nil {
					t.Fatal("capsule lost scoped initial authority or preconsumed wipe")
				}
				if bytes.Contains(native.capsule, pending.key) {
					t.Fatal("private recovery key leaked to disk capsule")
				}
			}
			if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(request)); err != nil {
				t.Fatal(err)
			}
			if pending.seals.Load() != 1 {
				t.Fatal("duplicate BOOT grant repeated TPM mutation")
			}
		})
	}
}

func TestRecoveryBootTPMLostPendingKeyCannotConsumeGrant(t *testing.T) {
	pending := &recoveryPendingBoundary{key: testKey(t), store: &recoveryStoreBoundary{}}
	f, native, intent := newRecoveryBootFixtureWithSetup(t, func(f *deviceActionFixture) {
		f.svc.recoveryConfig.Custody = agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM
		f.svc.recoveryConfig.ExpectedPCR11SHA256 = bytes.Repeat([]byte{3}, 32)
		f.svc.recoveryTPM = func() (recoveryTPMPending, error) { return pending, nil }
	})
	credential, boot, _ := recoveryBootEnvelopes(t, f, intent)
	_ = pending.Close()
	f.svc.recoveryPending = nil
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot})); err == nil {
		t.Fatal("lost original-boot key authorized recovery")
	}
	record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
	if len(record.GetRecoveryBootGrantEnvelope()) != 0 || pending.seals.Load() != 0 || native.reboots.Load() != 0 {
		t.Fatal("missing pending custody consumed BOOT or changed TPM")
	}
}

func TestRecoveryBootNativeContextUsesActualGrantExpiry(t *testing.T) {
	f, native, intent := newRecoveryBootFixture(t)
	credential, _, grant := recoveryBootEnvelopes(t, f, intent)
	grant.ExpiresAt = protoTimestamp(f.now.Add(5 * time.Second))
	record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
	handoff, err := protectedRecoveryHandoff(record)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := digestMessage(handoff)
	if err != nil {
		t.Fatal(err)
	}
	boot := mustSign(t, f.svc.authority, &agentv1.DeviceActionRecoveryBootGrant{Grant: grant, HandoffSha256: digest}, f.startKey)
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot})); err != nil {
		t.Fatal(err)
	}
	f.svc.operations.Wait()
	if native.reboots.Load() != 1 || native.armDeadline.IsZero() || native.armDeadline.After(time.Now().Add(5*time.Second)) {
		t.Fatal("native arm context outlived the actual BOOT grant")
	}
}

func TestRecoveryBootPostHashGateRejectsSuspendElapsedLifetime(t *testing.T) {
	f, native, intent := newRecoveryBootFixture(t)
	credential, boot, _ := recoveryBootEnvelopes(t, f, intent)
	native.beforeFinalGate = func() { f.bootClock.Add(uint64(31 * time.Second)) }
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot})); err != nil {
		t.Fatal(err)
	}
	f.svc.operations.Wait()
	awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	if native.arms.Load() != 0 || native.reboots.Load() != 0 {
		t.Fatal("posthash CLOCK_BOOTTIME expiry reached native boot")
	}
}
