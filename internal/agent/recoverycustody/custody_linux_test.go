//go:build linux

package recoverycustody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// These tests never open a host TPM. The fake models only the non-atomic
// counter/checkpoint boundary, including failures on either side of the write.
type memoryTPM struct {
	state         nativeState
	payload, auth []byte
	occupied      bool
	crash         string
	advances      int
}

func (m *memoryTPM) check(context.Context) ([]byte, error) {
	if m.occupied {
		return nil, ErrOccupied
	}
	return bytes.Repeat([]byte{7}, 32), nil
}
func (m *memoryTPM) reserve(_ context.Context, payload, policy, auth []byte, initial func([]byte, uint64) ([]byte, error)) (nativeState, error) {
	if m.occupied {
		return nativeState{}, ErrOccupied
	}
	m.occupied = true
	m.payload, m.auth = bytes.Clone(payload), bytes.Clone(auth)
	m.state.name = append([]byte{0, 11}, bytes.Repeat([]byte{9}, 32)...)
	m.state.policy = bytes.Clone(policy)
	if m.crash == "after-reserve" {
		return nativeState{}, ErrUnknown
	}
	m.state.counter = 1
	data, err := initial(m.state.name, m.state.counter)
	if err != nil {
		return nativeState{}, err
	}
	m.state.data = data
	return m.state, nil
}
func (m *memoryTPM) open(context.Context) ([]byte, nativeState, error) {
	if !m.occupied || len(m.payload) != 64 || !bytes.Equal(m.payload[32:], m.auth) {
		return nil, nativeState{}, ErrUnknown
	}
	return bytes.Clone(m.payload), m.state, nil
}
func (m *memoryTPM) read(_ context.Context, auth []byte) (nativeState, error) {
	if !m.occupied || !bytes.Equal(auth, m.auth) {
		return nativeState{}, ErrUnknown
	}
	return m.state, nil
}
func (m *memoryTPM) advance(ctx context.Context, auth []byte, expected uint64, next func(uint64) ([]byte, error)) (nativeState, error) {
	if _, err := m.read(ctx, auth); err != nil {
		return nativeState{}, err
	}
	if expected != m.state.counter || expected == ^uint64(0) {
		return nativeState{}, ErrUnknown
	}
	m.advances++
	m.state.counter++
	if m.crash == "after-counter" {
		return nativeState{}, ErrUnknown
	}
	data, err := next(m.state.counter)
	if err != nil {
		return nativeState{}, err
	}
	m.state.data = data
	if m.crash == "after-write" {
		return nativeState{}, ErrUnknown
	}
	return m.state, nil
}

func pendingFixture(t *testing.T) (*Pending, *memoryTPM) {
	t.Helper()
	validate, err := validator()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := locked(96)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, 32))
	copy(secret, key)
	clear(key)
	copy(secret[64:], bytes.Repeat([]byte{29}, 32))
	backend := &memoryTPM{}
	pending := &Pending{secret: secret, backend: backend, validator: validate}
	t.Cleanup(func() {
		if err := pending.Close(); err != nil {
			t.Error(err)
		}
	})
	return pending, backend
}
func journalFixture(key ed25519.PublicKey) *agentv1.RecoveryJournal {
	const id = "ae04fc3a-f3f4-4f97-9675-207bb5404c8c"
	now := time.Date(2031, 9, 1, 0, 0, 0, 0, time.UTC)
	digest := bytes.Repeat([]byte{5}, 32)
	target := &agentv1.StorageTarget{Serial: "qualified-original-disk", Wwn: "qualified-wwn", SizeBytes: 1 << 30}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: target, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE, Recovery: &agentv1.RecoveryBootSpec{ImageSha256: digest, MediaSha256: digest, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}}}}
	plan := &agentv1.DeviceActionPlan{ActionId: id, Spec: spec, Before: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(now), Supported: true, Target: target}}
	intent := &agentv1.DeviceActionIntent{DeploymentId: id, DeviceId: id, EnrollmentGeneration: id, ActionId: id, ActorId: id, ActionSequence: 1, RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 1, NotBefore: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Minute)), Spec: spec, SpecSha256: digest}
	challenge := &agentv1.DeviceActionChallenge{DeploymentId: id, DeviceId: id, EnrollmentGeneration: id, ActionId: id, ActionSequence: 1, IntentSha256: digest, SpecSha256: digest, NativePlanSha256: digest, Nonce: digest, BootId: id, ExecutorIncarnation: id, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), NativePlan: plan}
	handoff := &agentv1.DeviceActionRecoveryHandoff{Intent: intent, NativePlanSha256: digest, RecoveryImageSha256: digest, MediaSha256: digest, RecoveryPublicKey: key, OriginalBootId: id, ExpiresAt: timestamppb.New(now.Add(time.Minute)), Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM, IntentSha256: digest, Challenge: challenge}
	root := &agentv1.ExecutionRoot{DeploymentId: id, Version: 1, NotBefore: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)), Threshold: 1, Keys: []*agentv1.ExecutionKey{{KeyId: strings.Repeat("a", 64), PublicKey: key}}}
	return &agentv1.RecoveryJournal{FormatVersion: 1, CredentialEnvelope: []byte("fixture credential, verified by caller"), IntentEnvelope: []byte("fixture intent, verified by caller"), AcceptedRoot: root, DelegationEnvelope: []byte("fixture delegation"), Handoff: handoff, State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE, AcceptedAt: timestamppb.New(now), CredentialRoot: proto.CloneOf(root), CredentialDelegationEnvelope: []byte("fixture original delegation"), TrustAcceptedAt: timestamppb.New(now)}
}
func sealedFixture(t *testing.T) (*Store, *memoryTPM, []byte) {
	t.Helper()
	pending, backend := pendingFixture(t)
	initial := journalFixture(pending.PublicKey())
	store, err := pending.Seal(t.Context(), initial.Handoff, bytes.Repeat([]byte{11}, 32), initial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	capsule, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return store, backend, capsule
}
func TestSealAndOpenExactCapsule(t *testing.T) {
	store, backend, capsule := sealedFixture(t)
	opened, err := openWithBackend(t.Context(), capsule, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := opened.Close(); err != nil {
			t.Error(err)
		}
	}()
	if !bytes.Equal(opened.PublicKey(), store.PublicKey()) {
		t.Fatal("unsealed key changed")
	}
	var journal agentv1.RecoveryJournal
	if ok, err := opened.Load(&journal); err != nil || !ok {
		t.Fatalf("load=%v %v", ok, err)
	}
	if journal.GetHandoff().GetCustody() != agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM {
		t.Fatal("wrong custody")
	}
	if _, err := backend.check(t.Context()); !errors.Is(err, ErrOccupied) {
		t.Fatal("existing action reservation was reusable")
	}
	if _, err := store.MarshalJSON(); err == nil {
		t.Fatal("private store serialized")
	}
	if strings.Contains(fmt.Sprint(store), string(store.Signer())) {
		t.Fatal("private key in debug text")
	}
}
func TestConsumeSurvivesLostProcessAndOldCapsule(t *testing.T) {
	store, backend, capsule := sealedFixture(t)
	if err := store.Consume(); err != nil {
		t.Fatal(err)
	}
	if consumed, err := store.Consumed(); err != nil || !consumed {
		t.Fatalf("consumed=%v %v", consumed, err)
	}
	if err := store.Consume(); !errors.Is(err, ErrConsumed) {
		t.Fatalf("repeat consume: %v", err)
	}
	calls := 0
	loader := func(context.Context, ed25519.PrivateKey, *agentv1.RecoveryJournal, []byte) ([]byte, error) {
		calls++
		return capsule, nil
	}
	if _, err := openWithBackend(t.Context(), capsule, backend, loader); !errors.Is(err, ErrConsumed) {
		t.Fatalf("old capsule reopened spent action: %v", err)
	}
	if calls != 0 || backend.advances != 1 {
		t.Fatal("consumed action fetched/recommitted")
	}
}
func TestCrashPoisonsReservationWithoutRollback(t *testing.T) {
	for _, boundary := range []string{"after-counter", "after-write"} {
		t.Run(boundary, func(t *testing.T) {
			store, backend, capsule := sealedFixture(t)
			backend.crash = boundary
			if err := store.Consume(); !errors.Is(err, ErrUnknown) {
				t.Fatalf("ambiguous commit: %v", err)
			}
			backend.crash = ""
			if err := store.Consume(); !errors.Is(err, ErrUnknown) {
				t.Fatalf("ambiguous commit replayed: %v", err)
			}
			if _, err := openWithBackend(t.Context(), capsule, backend, nil); err == nil {
				t.Fatal("crashed action reopened")
			}
			if backend.advances != 1 {
				t.Fatal("ambiguous NV advance repeated")
			}
		})
	}
	pending, backend := pendingFixture(t)
	backend.crash = "after-reserve"
	initial := journalFixture(pending.PublicKey())
	if _, err := pending.Seal(t.Context(), initial.Handoff, bytes.Repeat([]byte{11}, 32), initial); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	backend.crash = ""
	if _, err := pending.Seal(t.Context(), initial.Handoff, bytes.Repeat([]byte{11}, 32), initial); !errors.Is(err, ErrOccupied) {
		t.Fatalf("partial reservation overwritten: %v", err)
	}
}
func TestWrongCapsuleKeyAndNVAuthorityFailClosed(t *testing.T) {
	for _, mutation := range []string{"capsule", "key", "auth", "counter", "object", "policy"} {
		t.Run(mutation, func(t *testing.T) {
			_, backend, capsule := sealedFixture(t)
			switch mutation {
			case "capsule":
				capsule[0] ^= 1
			case "key":
				backend.payload[0] ^= 1
			case "auth":
				backend.payload[32] ^= 1
			case "counter":
				backend.state.counter++
			case "object":
				backend.state.name = bytes.Clone(backend.state.name)
				backend.state.name[2] ^= 1
			case "policy":
				backend.state.policy = bytes.Clone(backend.state.policy)
				backend.state.policy[0] ^= 1
			}
			if _, err := openWithBackend(t.Context(), capsule, backend, nil); err == nil {
				t.Fatal("untrusted recovery material accepted")
			}
			if backend.advances != 0 {
				t.Fatal("failed open mutated TPM")
			}
		})
	}
}
func TestServerSnapshotReconstructsOnlyExactCurrentUnconsumedJournal(t *testing.T) {
	store, backend, capsule := sealedFixture(t)
	var next agentv1.RecoveryJournal
	if ok, err := store.Load(&next); err != nil || !ok {
		t.Fatal(err)
	}
	id := next.Handoff.Intent.ActionId
	next.Checkpoint = &agentv1.RecoveryCheckpoint{CredentialId: id, ActionId: id, BootId: id, ExecutorIncarnation: id, Sequence: 1, Phase: agentv1.RecoveryPhase_RECOVERY_PHASE_BOOTED, At: next.AcceptedAt}
	if err := store.Save(&next); err != nil {
		t.Fatal(err)
	}
	current, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openWithBackend(t.Context(), capsule, backend, nil); !errors.Is(err, ErrUnknown) {
		t.Fatalf("stale capsule opened without current snapshot: %v", err)
	}
	for _, wrong := range []bool{true, false} {
		calls := 0
		opened, err := openWithBackend(t.Context(), capsule, backend, func(_ context.Context, key ed25519.PrivateKey, original *agentv1.RecoveryJournal, expected []byte) ([]byte, error) {
			calls++
			if !bytes.Equal(key[32:], store.PublicKey()) || original.Checkpoint != nil {
				t.Fatal("loader did not receive authenticated original identity")
			}
			digest := sha256.Sum256(current)
			if !bytes.Equal(expected, digest[:]) {
				t.Fatal("wrong expected NV digest")
			}
			if wrong {
				return capsule, nil
			}
			return current, nil
		})
		if calls != 1 {
			t.Fatal("snapshot loader not invoked exactly once")
		}
		if wrong {
			if !errors.Is(err, ErrUnknown) {
				t.Fatalf("stale server snapshot accepted: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := opened.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// No transition may claim that an effect was committed before consumption.
	next.Checkpoint.Phase = agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED
	next.Checkpoint.GrantSha256 = bytes.Repeat([]byte{3}, 32)
	if err := store.Save(&next); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unconsumed effect checkpoint accepted: %v", err)
	}
}
func TestNVCheckpointFramingRejectsUnknownAndNonzeroPadding(t *testing.T) {
	store, backend, _ := sealedFixture(t)
	for _, mutation := range []string{"length", "padding", "unknown", "short"} {
		t.Run(mutation, func(t *testing.T) {
			data := bytes.Clone(backend.state.data)
			switch mutation {
			case "length":
				binary.BigEndian.PutUint32(data, ^uint32(0))
			case "padding":
				data[len(data)-1] = 1
			case "short":
				data = data[:len(data)-1]
			case "unknown":
				length := int(binary.BigEndian.Uint32(data))
				payload := bytes.Clone(data[4 : 4+length])
				payload = protowire.AppendTag(payload, 100, protowire.VarintType)
				payload = protowire.AppendVarint(payload, 1)
				clear(data)
				binary.BigEndian.PutUint32(data, uint32(len(payload)))
				copy(data[4:], payload)
			}
			if _, err := decodeCheckpoint(store.validator, data); err == nil {
				t.Fatal("unbounded/unknown NV payload accepted")
			}
		})
	}
}
func TestPCRPolicyBindsBothMeasurementsAndUnsealOnly(t *testing.T) {
	pcr7, pcr11 := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{11}, 32)
	policy, err := recoveryPolicy(pcr7, pcr11)
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []int{7, 11} {
		seven, eleven := bytes.Clone(pcr7), bytes.Clone(pcr11)
		if which == 7 {
			seven[0] ^= 1
		} else {
			eleven[0] ^= 1
		}
		changed, err := recoveryPolicy(seven, eleven)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(changed, policy) {
			t.Fatalf("PCR%d not bound", which)
		}
	}
	if _, err := recoveryPolicy(nil, pcr11); !errors.Is(err, ErrUnsupported) {
		t.Fatal("missing SecureBoot PCR accepted")
	}
	public := sealedTemplate(policy)
	if public.ObjectAttributes.UserWithAuth || !public.ObjectAttributes.AdminWithPolicy || !public.ObjectAttributes.FixedTPM || !public.ObjectAttributes.FixedParent || !bytes.Equal(public.AuthPolicy.Buffer, policy) {
		t.Fatal("sealed object permits a password/migration policy bypass")
	}
	selection := pcrSelection()
	if len(selection.PCRSelections) != 1 || selection.PCRSelections[0].Hash != tpm2.TPMAlgSHA256 || !bytes.Equal(selection.PCRSelections[0].PCRSelect, []byte{0x80, 0x08, 0}) {
		t.Fatal("unexpected PCR scope")
	}
}
func TestNVPermissionsAreExactAndSynchronous(t *testing.T) {
	for _, index := range []uint32{CounterIndex, CheckpointIndex} {
		public := nvTemplate(index)
		if err := validateNVPublic(&public, index); err != nil {
			t.Fatal(err)
		}
		public.Attributes.Written = true
		if err := validateNVPublic(&public, index); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*tpm2.TPMSNVPublic){
			func(p *tpm2.TPMSNVPublic) { p.Attributes.OwnerWrite = true },
			func(p *tpm2.TPMSNVPublic) { p.Attributes.OwnerRead = true },
			func(p *tpm2.TPMSNVPublic) { p.Attributes.PolicyWrite = true },
			func(p *tpm2.TPMSNVPublic) { p.Attributes.Orderly = true },
			func(p *tpm2.TPMSNVPublic) { p.DataSize++ },
			func(p *tpm2.TPMSNVPublic) { p.NameAlg = tpm2.TPMAlgSHA1 },
			func(p *tpm2.TPMSNVPublic) { p.NVIndex++ },
			func(p *tpm2.TPMSNVPublic) { p.AuthPolicy.Buffer = []byte{1} },
		} {
			changed := public
			mutate(&changed)
			if err := validateNVPublic(&changed, index); err == nil {
				t.Fatal("foreign or weakened NV index accepted")
			}
		}
	}
	if err := validateNVPublic(nil, 0x01801234); !errors.Is(err, ErrUnsupported) {
		t.Fatal("caller-selected NV index accepted")
	}
}

func TestCheckActionRetainsExactSignedScopeAndCurrentAnchor(t *testing.T) {
	store, backend, _ := sealedFixture(t)
	if err := store.CheckAction(t.Context(), proto.CloneOf(store.action)); err != nil {
		t.Fatal(err)
	}
	wrong := proto.CloneOf(store.action)
	wrong.GetSanitize().Target.Serial = "different-disk"
	if err := store.CheckAction(t.Context(), wrong); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("different target acquired RAM-journal exception: %v", err)
	}
	wrong = proto.CloneOf(store.action)
	wrong.GetSanitize().Recovery.ImageSha256[0] ^= 1
	if err := store.CheckAction(t.Context(), wrong); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("different approved image acquired custody: %v", err)
	}
	backend.state.counter++
	if err := store.CheckAction(t.Context(), store.action); !errors.Is(err, ErrUnknown) {
		t.Fatalf("lost durable anchor accepted: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckAction(t.Context(), store.action); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed custody accepted: %v", err)
	}
}

type replyTPM func([]byte) ([]byte, error)

func (reply replyTPM) Send(command []byte) ([]byte, error) { return reply(command) }

func TestNativeReservationNeverOverwritesAnOccupiedHandle(t *testing.T) {
	for _, occupied := range []uint32{PersistentHandle, CounterIndex, CheckpointIndex} {
		var queried []uint32
		device := replyTPM(func(input []byte) ([]byte, error) {
			if len(input) != 22 || binary.BigEndian.Uint16(input[:2]) != uint16(tpm2.TPMSTNoSessions) || binary.BigEndian.Uint32(input[2:6]) != uint32(len(input)) {
				t.Fatal("unexpected GetCapability transport frame")
			}
			// UnmarshalCommand consumes a cpHash preimage, not a wire frame.
			// GetCapability has no handles: remove only tag and total size.
			command, err := tpm2.UnmarshalCommand[tpm2.GetCapability, tpm2.GetCapabilityResponse](input[6:])
			if err != nil {
				return nil, err
			}
			if command.Capability != tpm2.TPMCapHandles || command.PropertyCount != 1 {
				t.Fatal("unexpected TPM query scope")
			}
			queried = append(queried, command.Property)
			handles := &tpm2.TPMLHandle{}
			if command.Property == occupied {
				handles.Handle = []tpm2.TPMHandle{tpm2.TPMHandle(occupied)}
			}
			response := &tpm2.GetCapabilityResponse{CapabilityData: tpm2.TPMSCapabilityData{Capability: tpm2.TPMCapHandles, Data: tpm2.NewTPMUCapabilities(tpm2.TPMCapHandles, handles)}}
			preimage, err := tpm2.MarshalResponse(command, response)
			if err != nil {
				return nil, err
			}
			// MarshalResponse returns responseCode || commandCode || params.
			// The transport requires tag || size || responseCode || params.
			wire := make([]byte, 10+len(preimage)-8)
			binary.BigEndian.PutUint16(wire[:2], uint16(tpm2.TPMSTNoSessions))
			binary.BigEndian.PutUint32(wire[2:6], uint32(len(wire)))
			copy(wire[6:10], preimage[:4])
			copy(wire[10:], preimage[8:])
			return wire, nil
		})
		if err := reservedVacant(device); !errors.Is(err, ErrOccupied) {
			t.Fatalf("occupied %#x accepted: %v", occupied, err)
		}
		if len(queried) == 0 || queried[len(queried)-1] != occupied {
			t.Fatal("continued beyond occupied reservation")
		}
	}
}

func TestTPMTransportBoundsAndCancellation(t *testing.T) {
	calls := 0
	inner := replyTPM(func([]byte) ([]byte, error) { calls++; return make([]byte, 65537), nil })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (boundedTPM{ctx: ctx, inner: inner}).Send(nil); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("canceled transport sent command: %v", err)
	}
	transport := boundedTPM{ctx: t.Context(), inner: inner}
	if _, err := transport.Send(make([]byte, 65537)); !errors.Is(err, ErrUnsupported) || calls != 0 {
		t.Fatalf("oversized command sent: %v", err)
	}
	if _, err := transport.Send(nil); !errors.Is(err, ErrUnsupported) || calls != 1 {
		t.Fatalf("oversized response accepted: %v", err)
	}
}
