//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// These tests exercise provider safety decisions with a deterministic native
// state machine. They do not claim cryptsetup/TPM/nft or physical qualification.
type luksFixture struct {
	p             *Provider
	plan          *agentv1.DeviceActionPlan
	keys          map[string][]byte
	tokens        map[string]luksToken
	fail          string
	gates         int
	retirements   int
	tokenRemovals int
	sealedHash    []byte
}

const fixtureAction = "0f6c3ec5-f054-45ec-b1dc-5cfb20961ab1"
const fixtureLUKS = "94993d55-31da-45ab-946c-d2e4ac878b0e"

func newLUKSFixture(t *testing.T) *luksFixture {
	t.Helper()
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	f := &luksFixture{keys: map[string][]byte{"0": []byte("owner-recovery"), "1": []byte("previous-managed")}, tokens: map[string]luksToken{"0": {Type: "lindm-recovery", Keyslots: []string{"1"}, KeySHA256: strings.Repeat("a", 64), ActionID: "5639f53d-6105-478f-aaf1-347268bb22a2"}}}
	target := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: fixtureLUKS, Wwn: "0x5000000000000001", Serial: "qualified-test-medium", SizeBytes: 64 << 20}
	qualified := &agentv1.QualifiedActionTarget{Target: target, OwnerRecoveryKeyslot: 0, AllowRecoveryRotation: true}
	f.p = &Provider{config: &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{qualified}}, validate: validator, gate: make(chan struct{}, 1), clock: func() time.Time { return time.Unix(1800000000, 0) }}
	path := filepath.Join(t.TempDir(), "non-native-test-target")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	f.p.resolve = func(_ context.Context, spec *agentv1.DeviceActionSpec, _ bool) (*targetHandle, error) {
		if !proto.Equal(specTarget(spec), target) {
			return nil, ErrConflict
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		return &targetHandle{file: file, qualification: qualified, node: blockNode{Path: path, UUID: fixtureLUKS, Size: target.SizeBytes}}, nil
	}
	f.p.run = f.native
	f.p.seal = func(_ context.Context, binding *agentv1.RecoveryKeyBinding, spec *agentv1.DeviceActionSpec, key []byte) ([]byte, error) {
		if len(key) != 64 || strings.IndexFunc(string(key), func(c rune) bool { return (c < '0' || c > '9') && (c < 'a' || c > 'f') }) != -1 {
			return nil, errors.New("nonprintable recovery key")
		}
		if binding.GetActionId() != fixtureAction || binding.GetLuksUuid() != fixtureLUKS || binding.GetNewKeyslot() != 2 || spec.GetEscrowRotate() == nil {
			return nil, errors.New("wrong sealing binding")
		}
		hash := sha256.Sum256(key)
		f.sealedHash = slices.Clone(hash[:])
		return []byte("opaque-test-ciphertext-not-a-real-envelope"), nil
	}
	old := uint32(1)
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: target, EscrowKeyId: strings.Repeat("b", 64), EscrowPublicKey: bytes.Repeat([]byte{1}, 256), RetireKeyslot: &old}}}
	before, err := f.p.Observe(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	f.plan, err = f.p.Plan(context.Background(), spec, before)
	if err != nil {
		t.Fatal(err)
	}
	f.plan.ActionId = fixtureAction
	f.plan.RecoveryBinding.DeviceId = "1b0fa740-4e8c-4938-8d24-6455c0b45b8d"
	f.plan.RecoveryBinding.EnrollmentGeneration = "31c6a42c-d448-4861-97fc-cfcd5e34b915"
	f.plan.RecoveryBinding.ActionId = fixtureAction
	return f
}

func argument(args []string, name string) string {
	for index, value := range args {
		if value == name && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

func readTestSecret(file *os.File) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return nil, errors.Join(err, ErrCredential)
	}
	return data, nil
}

func (f *luksFixture) native(_ context.Context, request nativeRequest) ([]byte, error) {
	if request.command != cryptsetup || len(request.args) == 0 {
		return nil, errors.New("unexpected native operation")
	}
	switch request.args[0] {
	case "luksUUID":
		return []byte(fixtureLUKS + "\n"), nil
	case "luksDump":
		keys := make(map[string]json.RawMessage, len(f.keys))
		for slot := range f.keys {
			keys[slot] = json.RawMessage(`{"type":"luks2"}`)
		}
		return json.Marshal(map[string]any{"keyslots": keys, "tokens": f.tokens, "segments": map[string]any{"0": map[string]string{"type": "crypt", "offset": "16777216"}}})
	case "open":
		slot := argument(request.args, "--key-slot")
		credential, err := readTestSecret(request.files[1])
		if err != nil {
			return nil, err
		}
		defer clear(credential)
		if f.fail == "new-unlock" && slot == "2" {
			return nil, errors.New("replacement unlock failure")
		}
		if !bytes.Equal(f.keys[slot], credential) {
			return nil, errors.New("wrong credential")
		}
		return nil, nil
	case "luksAddKey":
		owner, err := readTestSecret(request.files[1])
		if err != nil {
			return nil, err
		}
		defer clear(owner)
		key, err := readTestSecret(request.files[2])
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(owner, f.keys["0"]) {
			clear(key)
			return nil, errors.New("wrong owner")
		}
		if bytes.Contains([]byte(strings.Join(request.args, " ")), key) {
			clear(key)
			return nil, errors.New("plaintext in argv")
		}
		f.keys[argument(request.args, "--key-slot")] = key
		if f.fail == "add-crash" {
			return nil, context.Canceled
		}
		return nil, nil
	case "token":
		if len(request.args) > 1 && request.args[1] == "remove" {
			f.tokenRemovals++
			if f.fail == "token-remove-crash" {
				return nil, context.Canceled
			}
			id := argument(request.args, "--token-id")
			token, exists := f.tokens[id]
			if !exists || token.Type != "lindm-recovery" || len(token.Keyslots) != 0 {
				return nil, errors.New("attempted unrelated token removal")
			}
			delete(f.tokens, id)
			return nil, nil
		}
		if f.fail == "token-crash" {
			return nil, context.Canceled
		}
		var token luksToken
		if err := json.Unmarshal(request.input, &token); err != nil {
			return nil, err
		}
		f.tokens[argument(request.args, "--token-id")] = token
		return nil, nil
	case "luksKillSlot":
		f.retirements++
		old := request.args[len(request.args)-1]
		if old == "0" || old == strconv.FormatUint(uint64(f.plan.GetRecoveryBinding().GetNewKeyslot()), 10) {
			return nil, errors.New("protected key retirement")
		}
		if f.fail == "kill-crash" {
			return nil, context.Canceled
		}
		delete(f.keys, old)
		for id, token := range f.tokens {
			if slices.Contains(token.Keyslots, old) {
				token.Keyslots = slices.DeleteFunc(token.Keyslots, func(slot string) bool { return slot == old })
				f.tokens[id] = token
				if f.fail == "changed-retired-token" && token.Type == "lindm-recovery" && len(token.Keyslots) == 0 {
					token.ActionID = "externally-changed"
					f.tokens[id] = token
				}
			}
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected native verb %q", request.args[0])
	}
}

func (f *luksFixture) gate(context.Context) error { f.gates++; return nil }

func TestRotationStagesUnlockBeforeReceiptAndRetainsOwner(t *testing.T) {
	f := newLUKSFixture(t)
	stage, err := f.p.Apply(context.Background(), f.plan, []byte("owner-recovery"), f.gate)
	if err != nil {
		t.Fatal(err)
	}
	if stage.GetVerified() || stage.GetEscrow() == nil || f.retirements != 0 || len(f.keys) != 3 || f.gates != 1 {
		t.Fatal("rotation did not stop at durable-escrow boundary")
	}
	if !bytes.Equal(stage.GetEscrow().GetRecoveryKeySha256(), f.sealedHash) {
		t.Fatal("staged escrow is not bound to tested key")
	}
	if !slices.Equal(stage.GetAfter().GetOccupiedKeyslots(), []uint32{0, 1, 2}) || len(stage.GetAfter().GetLuksTokens()) != 2 {
		t.Fatal("staged observation omitted the replacement slot or token")
	}
	newToken := stage.GetAfter().GetLuksTokens()[1]
	if newToken.GetTokenId() != stage.GetEscrow().GetTokenId() || newToken.GetType() != "lindm-recovery" || !slices.Equal(newToken.GetKeyslots(), []uint32{2}) {
		t.Fatal("staged token inventory did not bind the replacement slot")
	}
	verified, err := f.p.Verify(context.Background(), f.plan, stage)
	if err != nil || verified.GetVerified() {
		t.Fatalf("pre-receipt verification: %v", err)
	}
	result, err := f.p.ConfirmEscrow(context.Background(), f.plan, stage, []byte("owner-recovery"), f.gate)
	if err != nil {
		t.Fatal(err)
	}
	if !result.GetVerified() || f.retirements != 1 || len(f.keys) != 2 || !bytes.Equal(f.keys["0"], []byte("owner-recovery")) || f.keys["2"] == nil {
		t.Fatal("retirement did not preserve both recovery paths")
	}
	if !slices.Equal(result.GetAfter().GetOccupiedKeyslots(), []uint32{0, 2}) {
		t.Fatal("confirmed observation retained a retired occupied slot")
	}
	for _, token := range result.GetAfter().GetLuksTokens() {
		if slices.Contains(token.GetKeyslots(), uint32(1)) {
			t.Fatal("confirmed token still references retired slot")
		}
	}
}

func TestRotationCrashNeverRetiresEitherExistingSlot(t *testing.T) {
	for _, phase := range []string{"add-crash", "new-unlock", "token-crash"} {
		t.Run(phase, func(t *testing.T) {
			f := newLUKSFixture(t)
			f.fail = phase
			_, err := f.p.Apply(context.Background(), f.plan, []byte("owner-recovery"), f.gate)
			if !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("uncertain mutation lost unknown state: %v", err)
			}
			if f.keys["0"] == nil || f.keys["1"] == nil || f.retirements != 0 {
				t.Fatal("uncertain stage retired recovery")
			}
		})
	}
}

func TestWrongCredentialAndTargetCannotCrossGate(t *testing.T) {
	for _, variant := range []string{"missing", "wrong", "target", "metadata", "owner-retirement"} {
		t.Run(variant, func(t *testing.T) {
			f := newLUKSFixture(t)
			credential := []byte("owner-recovery")
			switch variant {
			case "missing":
				credential = nil
			case "wrong":
				credential = []byte("wrong-owner")
			case "target":
				f.plan.Spec.GetEscrowRotate().Target.Serial = "other-disk"
			case "metadata":
				f.keys["3"] = []byte("externally-added")
			case "owner-retirement":
				owner := uint32(0)
				f.plan.Spec.GetEscrowRotate().RetireKeyslot = &owner
			}
			_, err := f.p.Apply(context.Background(), f.plan, credential, f.gate)
			if err == nil || f.gates != 0 || f.retirements != 0 || f.keys["2"] != nil {
				t.Fatalf("unsafe preflight crossed gate: %v", err)
			}
			if variant == "missing" && !errors.Is(err, ErrCredential) {
				t.Fatalf("missing one-shot credential is not recoverable preflight: %v", err)
			}
		})
	}
}

func TestReceiptDenialChangedStageAndCrashRetainBothSlots(t *testing.T) {
	for _, variant := range []string{"receipt-denied", "wrong-luks", "wrong-key", "wrong-slot", "changed-native", "missing-owner", "kill-crash"} {
		t.Run(variant, func(t *testing.T) {
			f := newLUKSFixture(t)
			stage, err := f.p.Apply(context.Background(), f.plan, []byte("owner-recovery"), f.gate)
			if err != nil {
				t.Fatal(err)
			}
			gate := f.gate
			switch variant {
			case "receipt-denied":
				gate = func(context.Context) error { return errors.New("authenticated receipt rejected") }
			case "wrong-luks":
				stage.Escrow.LuksUuid = "66c79834-613c-488b-9443-cb6b66a8bce7"
			case "wrong-key":
				stage.Escrow.RecoveryKeySha256[0] ^= 1
			case "wrong-slot":
				stage.Escrow.NewKeyslot = 0
			case "changed-native":
				f.keys["3"] = []byte("external-key")
			case "missing-owner":
				delete(f.keys, "0")
			case "kill-crash":
				f.fail = "kill-crash"
			}
			_, err = f.p.ConfirmEscrow(context.Background(), f.plan, stage, []byte("owner-recovery"), gate)
			if err == nil || f.keys["1"] == nil || f.keys["2"] == nil {
				t.Fatalf("ambiguous receipt/retirement lost slots: %v", err)
			}
			if variant != "kill-crash" && f.retirements != 0 {
				t.Fatal("invalid receipt or native stage reached retirement")
			}
			if variant == "kill-crash" && !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("interrupted retirement did not stay unknown")
			}
		})
	}
}

func TestMetadataRefusesUnboundedOrInconsistentLayouts(t *testing.T) {
	for name, raw := range map[string][]byte{
		"oversized":         bytes.Repeat([]byte{'x'}, outputLimit+1),
		"missing":           []byte(`{}`),
		"dangling-token":    []byte(`{"keyslots":{"0":{}},"tokens":{"0":{"type":"other","keyslots":["1"]}},"segments":{"0":{"offset":"16777216","type":"crypt"}}}`),
		"noncanonical-slot": []byte(`{"keyslots":{"01":{}},"tokens":{},"segments":{"0":{"offset":"16777216","type":"crypt"}}}`),
		"multi-segment":     []byte(`{"keyslots":{"0":{}},"tokens":{},"segments":{"0":{},"1":{}}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseMetadata(raw); err == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}

func TestGraphicalLockRequiresActualLockedHint(t *testing.T) {
	for _, locked := range []bool{false, true} {
		p := &Provider{sessionNative: func(context.Context, string) ([]graphicalSession, error) {
			return []graphicalSession{{ID: "1", Locked: locked}}, nil
		}}
		got, _, err := p.sessions(context.Background(), false)
		if err != nil || got != locked {
			t.Fatalf("graphical lock=%v observation=%v error=%v", locked, got, err)
		}
	}
}

func TestSlotNumbersAreCanonicalAndBounded(t *testing.T) {
	for _, value := range []string{"-1", "32", "01", "../0", "0;poweroff", ""} {
		if _, err := slotNumber(value); err == nil {
			t.Fatalf("accepted slot %q", value)
		}
	}
	for value := uint32(0); value < 32; value++ {
		got, err := slotNumber(strconv.FormatUint(uint64(value), 10))
		if err != nil || got != value {
			t.Fatal("rejected native canonical slot")
		}
	}
}

// Inputs follow systemd's `--version` first-line format, "systemd N (pkg)".
func TestTPMBindingRequiresDescriptorUnlockAndTokenPlugin(t *testing.T) {
	for output, want := range map[string]bool{
		"systemd 249 (249.11-0ubuntu3.16)\n+PAM +AUDIT +SELINUX": false,
		"systemd 251 (251.4-1)\n":                                false,
		"systemd 252 (252.39-1~deb12u1)\n+PAM":                   true,
		"systemd 255 (255.4-1ubuntu8.12)\n":                      true,
		"systemd 257 (257.9-1~deb13u1)\n":                        true,
		"systemd 258.1\n":                                        true,
		"systemd\n":                                              false,
		"cryptenroll 999\n":                                      false,
		"systemd v999\n":                                         false,
		"":                                                       false,
	} {
		if got := cryptenrollBindsTPM2([]byte(output)); got != want {
			t.Errorf("cryptenrollBindsTPM2(%q) = %t, want %t", output, got, want)
		}
	}
}

func TestLockWaitsForAcknowledgementWithoutRepeatingEffect(t *testing.T) {
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	effects, afterRequests := 0, 0
	p := &Provider{config: &agentv1.DeviceActionProviderConfig{AllowSessionLock: true}, validate: validator, gate: make(chan struct{}, 1), clock: time.Now}
	p.sessionNative = func(_ context.Context, operation string) ([]graphicalSession, error) {
		switch operation {
		case "observe":
			locked := false
			if effects > 0 {
				afterRequests++
				locked = afterRequests > 1
			}
			return []graphicalSession{{ID: "1", Locked: locked}}, nil
		case "lock":
			effects++
			return nil, nil
		default:
			return nil, errors.New("unexpected session operation")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}
	before, err := p.Observe(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.Plan(ctx, spec, before)
	if err != nil {
		t.Fatal(err)
	}
	plan.ActionId = fixtureAction
	result, err := p.Apply(ctx, plan, nil, func(context.Context) error { return nil })
	if err != nil || !result.GetVerified() || effects != 1 {
		t.Fatalf("asynchronous acknowledgement result=%v effects=%d error=%v", result.GetVerified(), effects, err)
	}
}

func TestTokenInventoryIncludesAssociationsButNoCredentialPayloads(t *testing.T) {
	fixture := newLUKSFixture(t)
	metadata, err := parseMetadata([]byte(`{"keyslots":{"7":{},"2":{},"0":{}},"tokens":{"8":{"type":"systemd-tpm2","keyslots":["7"],"tpm2-blob":"sealed-secret-material","tpm2-pcrs":[7]},"1":{"type":"vendor-custom","keyslots":["2","0"],"password":"vendor-secret-material"}},"segments":{"0":{"type":"crypt","offset":"16777216"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	observation := proto.CloneOf(fixture.plan.Before)
	if err := fixture.p.populateLUKSObservation(observation, metadata, bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatal(err)
	}
	if !observation.GetTpm2Bound() || !slices.Equal(observation.GetOccupiedKeyslots(), []uint32{0, 2, 7}) {
		t.Fatal("native slot or TPM observation omitted")
	}
	tokens := observation.GetLuksTokens()
	if len(tokens) != 2 || tokens[0].GetTokenId() != 1 || tokens[0].GetType() != "vendor-custom" || !slices.Equal(tokens[0].GetKeyslots(), []uint32{0, 2}) || tokens[1].GetTokenId() != 8 || tokens[1].GetType() != "systemd-tpm2" || !slices.Equal(tokens[1].GetKeyslots(), []uint32{7}) {
		t.Fatal("public token identities/associations were lost or unordered")
	}
	encoded, err := proto.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("sealed-secret-material")) || bytes.Contains(encoded, []byte("vendor-secret-material")) {
		t.Fatal("token credential payload escaped into observation")
	}
	for _, invalid := range []luksToken{{Type: strings.Repeat("x", 129), Keyslots: []string{"0"}}, {Type: "bad\ntype", Keyslots: []string{"0"}}, {Type: "systemd-tpm2", Keyslots: []string{"0", "0"}}} {
		metadata.Tokens = map[string]luksToken{"0": invalid}
		if err := fixture.p.populateLUKSObservation(observation, metadata, bytes.Repeat([]byte{0x42}, 32)); err == nil {
			t.Fatal("invalid native token inventory bypassed schema bounds")
		}
	}
}

func TestRepeatedRotationReclaimsOnlyRetiredOwnedTokens(t *testing.T) {
	fixture := newLUKSFixture(t)
	fixture.tokens["28"] = luksToken{Type: "lindm-recovery", Keyslots: []string{"1"}, KeySHA256: strings.Repeat("c", 64), ActionID: "78f66f69-6409-4448-8dc9-9d00bf77b508"}
	fixture.tokens["29"] = luksToken{Type: "vendor-empty"}
	fixture.tokens["30"] = luksToken{Type: "vendor-owner", Keyslots: []string{"0"}}
	fixture.tokens["31"] = luksToken{Type: "vendor-shared", Keyslots: []string{"0", "1"}}
	fixture.p.seal = func(_ context.Context, binding *agentv1.RecoveryKeyBinding, _ *agentv1.DeviceActionSpec, key []byte) ([]byte, error) {
		if binding.GetNewKeyslot() == 0 || len(key) != 64 {
			return nil, errors.New("unsafe replacement binding")
		}
		return []byte("opaque-test-ciphertext"), nil
	}
	old := uint32(1)
	for iteration := range 40 {
		spec := proto.CloneOf(fixture.plan.Spec)
		spec.GetEscrowRotate().RetireKeyslot = proto.Uint32(old)
		before, err := fixture.p.Observe(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := fixture.p.Plan(context.Background(), spec, before)
		if err != nil {
			t.Fatalf("rotation %d could not plan: %v", iteration, err)
		}
		plan.ActionId = fmt.Sprintf("00000000-0000-4000-8000-%012x", iteration+1)
		plan.RecoveryBinding.DeviceId = fixture.plan.RecoveryBinding.DeviceId
		plan.RecoveryBinding.EnrollmentGeneration = fixture.plan.RecoveryBinding.EnrollmentGeneration
		plan.RecoveryBinding.ActionId = plan.ActionId
		fixture.plan = plan
		stage, err := fixture.p.Apply(context.Background(), plan, []byte("owner-recovery"), fixture.gate)
		if err != nil {
			t.Fatalf("rotation %d stage: %v", iteration, err)
		}
		result, err := fixture.p.ConfirmEscrow(context.Background(), plan, stage, []byte("owner-recovery"), fixture.gate)
		if err != nil || !result.GetVerified() {
			t.Fatalf("rotation %d confirmation: %v", iteration, err)
		}
		if len(fixture.keys) != 2 || len(fixture.tokens) != 4 || fixture.tokenRemovals != iteration+2 {
			t.Fatal("retired token namespace leaked across rotations")
		}
		if fixture.tokens["29"].Type != "vendor-empty" || !slices.Equal(fixture.tokens["30"].Keyslots, []string{"0"}) || !slices.Equal(fixture.tokens["31"].Keyslots, []string{"0"}) {
			t.Fatal("rotation removed an unrelated or owner token")
		}
		old = stage.GetEscrow().GetNewKeyslot()
	}
}

func TestRetiredTokenCleanupFailureStaysUnknownWithoutReplay(t *testing.T) {
	for _, phase := range []string{"token-remove-crash", "changed-retired-token"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newLUKSFixture(t)
			stage, err := fixture.p.Apply(context.Background(), fixture.plan, []byte("owner-recovery"), fixture.gate)
			if err != nil {
				t.Fatal(err)
			}
			fixture.fail = phase
			_, err = fixture.p.ConfirmEscrow(context.Background(), fixture.plan, stage, []byte("owner-recovery"), fixture.gate)
			if !errors.Is(err, ErrOutcomeUnknown) || fixture.keys["0"] == nil || fixture.keys["2"] == nil {
				t.Fatalf("uncertain metadata cleanup lost working recovery: %v", err)
			}
			if _, exists := fixture.tokens["0"]; !exists {
				t.Fatal("changed or interrupted old token was removed")
			}
			if phase == "changed-retired-token" && fixture.tokenRemovals != 0 {
				t.Fatal("changed token reached native removal")
			}
			gates, removals := fixture.gates, fixture.tokenRemovals
			if _, err := fixture.p.ConfirmEscrow(context.Background(), fixture.plan, stage, []byte("owner-recovery"), fixture.gate); err == nil {
				t.Fatal("ambiguous retirement was replayed")
			}
			if fixture.gates != gates || fixture.tokenRemovals != removals || fixture.retirements != 1 {
				t.Fatal("replayed confirmation repeated a native effect")
			}
		})
	}
}
