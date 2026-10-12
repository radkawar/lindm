//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

// tpmFixture is a deterministic systemd-cryptenroll/cryptsetup state machine
// for the managed TPM2 bind. It does not claim TPM, PCR or boot qualification.
type tpmFixture struct {
	p        *Provider
	target   *agentv1.StorageTarget
	owner    []byte
	slots    map[string]bool
	tokens   map[string]json.RawMessage
	jsonSize int
	fail     string
	enrolls  int
	imports  int
	gates    int
	pcrlock  bool
}

const fixtureSealed = `{"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":"c2VhbGVkLW9iamVjdA==","tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256","tpm2-primary-alg":"ecc","tpm2-policy-hash":"2035"}`

func newTPMFixture(t *testing.T, release string) *tpmFixture {
	t.Helper()
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	row, ok := platform.Lookup(release)
	if !ok {
		t.Fatalf("no registry row %s", release)
	}
	f := &tpmFixture{owner: []byte("owner-recovery"), slots: map[string]bool{"0": true}, tokens: map[string]json.RawMessage{}, jsonSize: 12288}
	f.target = &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: fixtureLUKS, Wwn: "0x5000000000000001", Serial: "qualified-test-medium", SizeBytes: 64 << 20}
	qualified := &agentv1.QualifiedActionTarget{Target: f.target, OwnerRecoveryKeyslot: 0, AllowTpm2Binding: true}
	f.p = &Provider{config: &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{qualified}}, validate: validator, gate: make(chan struct{}, 1), clock: func() time.Time { return time.Unix(1800000000, 0) }}
	path := filepath.Join(t.TempDir(), "non-native-test-target")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	f.p.resolve = func(_ context.Context, spec *agentv1.DeviceActionSpec, _ bool) (*targetHandle, error) {
		if !proto.Equal(specTarget(spec), f.target) {
			return nil, ErrConflict
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		return &targetHandle{file: file, qualification: qualified, node: blockNode{Path: path, UUID: fixtureLUKS, Size: f.target.SizeBytes}}, nil
	}
	f.p.run = f.native
	f.p.hostRelease = func() (*platform.Release, error) { return row, nil }
	f.p.pcrlockPolicy = func() (bool, error) { return f.pcrlock, nil }
	return f
}

func (f *tpmFixture) dump() ([]byte, error) {
	keyslots := make(map[string]json.RawMessage, len(f.slots))
	for slot := range f.slots {
		keyslots[slot] = json.RawMessage(`{"type":"luks2"}`)
	}
	return json.Marshal(map[string]any{"keyslots": keyslots, "tokens": f.tokens, "segments": map[string]any{"0": map[string]string{"type": "crypt", "offset": "16777216"}}, "config": map[string]string{"json_size": strconv.Itoa(f.jsonSize), "keyslots_size": "16744448"}})
}

func (f *tpmFixture) native(_ context.Context, request nativeRequest) ([]byte, error) {
	if request.command == cryptenroll {
		if slices.Equal(request.args, []string{"--version"}) {
			return []byte("systemd 255 (255.4-1ubuntu8.17)\n+TPM2\n"), nil
		}
		f.enrolls++
		owner, err := readTestSecret(request.files[1])
		if err != nil {
			return nil, err
		}
		defer clear(owner)
		if !bytes.Equal(owner, f.owner) || !slices.Contains(request.args, "--tpm2-pcrs=7") || slices.Contains(request.args, "--tpm2-pcrlock=") != f.pcrlock {
			return nil, errors.New("unexpected enrollment")
		}
		f.slots["1"] = true
		id, err := freeTokens(&luksMetadata{Tokens: f.parsedTokens()}, 1)
		if err != nil {
			return nil, err
		}
		f.tokens[strconv.FormatUint(uint64(id[0]), 10)] = json.RawMessage(fixtureSealed)
		return nil, nil
	}
	if request.command != cryptsetup || len(request.args) == 0 {
		return nil, errors.New("unexpected native operation")
	}
	switch request.args[0] {
	case "luksUUID":
		return []byte(fixtureLUKS + "\n"), nil
	case "luksDump":
		return f.dump()
	case "open":
		if slices.Contains(request.args, "--token-only") {
			if f.fail == "stale" {
				return nil, errors.New("PCR policy no longer matches")
			}
			slot := argument(request.args, "--key-slot")
			for _, token := range f.parsedTokens() {
				if token.Type == "systemd-tpm2" && slices.Equal(token.Keyslots, []string{slot}) {
					return nil, nil
				}
			}
			return nil, errors.New("no token unsealed")
		}
		credential, err := readTestSecret(request.files[1])
		if err != nil {
			return nil, err
		}
		defer clear(credential)
		if argument(request.args, "--key-slot") != "0" || !bytes.Equal(credential, f.owner) {
			return nil, errors.New("wrong credential")
		}
		return nil, nil
	case "token":
		id := argument(request.args, "--token-id")
		switch request.args[1] {
		case "export":
			token, ok := f.tokens[id]
			if !ok {
				return nil, errors.New("no token")
			}
			return append(slices.Clone(token), '\n'), nil
		case "import":
			f.imports++
			if f.fail == "import" && f.imports == 2 {
				return nil, context.Canceled
			}
			if _, occupied := f.tokens[id]; occupied {
				return nil, errors.New("token id occupied")
			}
			f.tokens[id] = json.RawMessage(bytes.TrimSpace(request.input))
			return nil, nil
		}
	}
	return nil, fmt.Errorf("unexpected native verb %q", strings.Join(request.args, " "))
}

func (f *tpmFixture) parsedTokens() map[string]luksToken {
	tokens := make(map[string]luksToken, len(f.tokens))
	for id, raw := range f.tokens {
		var token luksToken
		if err := json.Unmarshal(raw, &token); err == nil {
			tokens[id] = token
		}
	}
	return tokens
}

func (f *tpmFixture) gate(context.Context) error { f.gates++; return nil }

// plan builds the signed plan from the current native metadata, as Observe
// does on a host whose TPM resource manager exists.
func (f *tpmFixture) plan(t *testing.T) *agentv1.DeviceActionPlan {
	t.Helper()
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{Target: f.target, Pcrs: []uint32{7}}}}
	handle, err := f.p.resolve(context.Background(), spec, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := handle.file.Close(); err != nil {
			t.Error(err)
		}
	})
	metadata, hash, err := f.p.metadata(context.Background(), handle.file)
	if err != nil {
		t.Fatal(err)
	}
	before := &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(f.p.clock()), Supported: true, Target: proto.CloneOf(f.target)}
	if err := f.p.populateLUKSObservation(before, metadata, hash); err != nil {
		t.Fatal(err)
	}
	plan, err := f.p.Plan(context.Background(), spec, before)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func (f *tpmFixture) bind(t *testing.T, plan *agentv1.DeviceActionPlan) (err error) {
	t.Helper()
	handle, err := f.p.resolve(context.Background(), plan.GetSpec(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { err = errors.Join(err, handle.file.Close()) }()
	return f.p.bindTPM(context.Background(), plan, handle, slices.Clone(f.owner), f.gate)
}

// Ubuntu 24.04's systemd-tpm2 cannot retry a PCR change within one token, so
// its one sealed keyslot gets identical token references, each a further
// unseal at boot; a release whose systemd retries itself keeps one token.
func TestTPMBindWritesTheReleaseTokenReferences(t *testing.T) {
	for release, want := range map[string]int{"ubuntu-24.04": platform.TPM2NextTokenReferences, "pop-24.04": platform.TPM2NextTokenReferences, "ubuntu-26.04": 1, "debian-12": 1} {
		t.Run(release, func(t *testing.T) {
			f := newTPMFixture(t, release)
			plan := f.plan(t)
			if err := f.bind(t, plan); err != nil {
				t.Fatal(err)
			}
			if f.enrolls != 1 || f.gates != 1 || len(f.slots) != 2 {
				t.Fatalf("bind enrolled %d keyslots behind %d gates", f.enrolls, f.gates)
			}
			references := 0
			for _, raw := range f.tokens {
				if !bytes.Equal(raw, []byte(fixtureSealed)) {
					t.Fatalf("token reference is not the enrolled sealed object: %s", raw)
				}
				references++
			}
			if references != want {
				t.Fatalf("%d token references, want %d", references, want)
			}
			verified, err := f.p.verify(context.Background(), plan, &agentv1.DeviceActionVerification{})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(verified.GetEvidence(), fmt.Sprintf("as %d identical token reference(s)", want)) {
				t.Fatalf("evidence omits the reference count: %q", verified.GetEvidence())
			}
		})
	}
}

// The Tumbleweed encrypted guest carried /var/lib/systemd/pcrlock.json, which
// cryptenroll adds to every enrollment unasked: a bind after a deliberate PCR 7
// change then failed its own token-only unseal. With a pcrlock policy present
// the bind turns it off and seals exactly the approved PCRs.
func TestTPMBindKeepsExactPCRsDespitePCRLockPolicy(t *testing.T) {
	for _, pcrlock := range []bool{false, true} {
		f := newTPMFixture(t, "opensuse-tumbleweed")
		f.pcrlock = pcrlock
		if err := f.bind(t, f.plan(t)); err != nil || f.enrolls != 1 {
			t.Fatalf("pcrlock=%t: enrolls %d: %v", pcrlock, f.enrolls, err)
		}
	}
}

// A bind that would run out of tokens or LUKS2 JSON midway is refused before
// the effect gate; an interrupted or altered reference set never verifies.
func TestTPMBindReferencesAreCompleteOrUnverified(t *testing.T) {
	t.Run("json area", func(t *testing.T) {
		f := newTPMFixture(t, "ubuntu-24.04")
		f.jsonSize = 4096
		err := f.bind(t, f.plan(t))
		if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "luks2_metadata_space_exhausted") || f.gates != 0 || f.enrolls != 0 {
			t.Fatalf("undersized header was not refused before the gate: %v", err)
		}
	})
	t.Run("tokens", func(t *testing.T) {
		f := newTPMFixture(t, "ubuntu-24.04")
		for id := range 30 {
			f.tokens[strconv.Itoa(id)] = json.RawMessage(`{"type":"vendor","keyslots":[]}`)
		}
		err := f.bind(t, f.plan(t))
		if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "no_free_token") || f.gates != 0 {
			t.Fatalf("missing token capacity was not refused before the gate: %v", err)
		}
	})
	t.Run("interrupted", func(t *testing.T) {
		f := newTPMFixture(t, "ubuntu-24.04")
		f.fail = "import"
		plan := f.plan(t)
		if err := f.bind(t, plan); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("interrupted references = %v, want outcome unknown", err)
		}
		if _, err := f.p.verify(context.Background(), plan, &agentv1.DeviceActionVerification{}); !errors.Is(err, ErrNotVerified) {
			t.Fatalf("partial reference set verified: %v", err)
		}
	})
	t.Run("altered", func(t *testing.T) {
		f := newTPMFixture(t, "ubuntu-24.04")
		plan := f.plan(t)
		if err := f.bind(t, plan); err != nil {
			t.Fatal(err)
		}
		for id, raw := range f.tokens {
			if id != "0" {
				f.tokens[id] = bytes.Replace(raw, []byte("c2VhbGVkLW9iamVjdA=="), []byte("b3RoZXItb2JqZWN0"), 1)
				break
			}
		}
		if _, err := f.p.verify(context.Background(), plan, &agentv1.DeviceActionVerification{}); !errors.Is(err, ErrNotVerified) {
			t.Fatalf("a reference to another sealed object verified: %v", err)
		}
	})
}

// legacyBind is the header an agent before the reference fix left: owner slot
// 0 and one product systemd-tpm2 token naming keyslot 1.
func (f *tpmFixture) legacyBind() {
	f.slots["1"] = true
	f.tokens["0"] = json.RawMessage(fixtureSealed)
}

// repairPlan is the plan Observe signs for a TPM2 bind of this target: it
// freezes the repair keyslot when tpm2RepairCandidate finds one.
func (f *tpmFixture) repairPlan(t *testing.T) (*agentv1.DeviceActionPlan, bool) {
	t.Helper()
	plan := f.plan(t)
	handle, err := f.p.resolve(context.Background(), plan.GetSpec(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := handle.file.Close(); err != nil {
			t.Error(err)
		}
	}()
	metadata, _, err := f.p.metadata(context.Background(), handle.file)
	if err != nil {
		t.Fatal(err)
	}
	references, err := f.p.tpm2References()
	if err != nil {
		t.Fatal(err)
	}
	slot, ok, err := f.p.tpm2RepairCandidate(context.Background(), handle.file, metadata, []uint32{7}, 0, references)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		plan.Before.Tpm2ReferenceRepairKeyslot = &slot
	}
	return plan, ok
}

func (f *tpmFixture) repair(t *testing.T, plan *agentv1.DeviceActionPlan) (err error) {
	t.Helper()
	handle, err := f.p.resolve(context.Background(), plan.GetSpec(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { err = errors.Join(err, handle.file.Close()) }()
	return f.p.repairTPMReferences(context.Background(), plan, handle, f.gate)
}

// A bind made by an older agent (one token) is completed in place on a
// release that needs four: identical copies naming the same keyslot, no new
// keyslot, no cryptenroll and no owner credential.
func TestTPMBindRepairsLegacyReferencesWithoutCredential(t *testing.T) {
	f := newTPMFixture(t, "ubuntu-24.04")
	f.legacyBind()
	plan, ok := f.repairPlan(t)
	if !ok || plan.GetBefore().GetTpm2ReferenceRepairKeyslot() != 1 {
		t.Fatal("legacy one-reference bind was not planned as a repair of keyslot 1")
	}
	f.owner = nil // any credential read would now fail
	if err := f.repair(t, plan); err != nil {
		t.Fatal(err)
	}
	if f.enrolls != 0 || f.gates != 1 || len(f.slots) != 2 {
		t.Fatalf("repair enrolled %d keyslots, crossed %d gates, left %d keyslots", f.enrolls, f.gates, len(f.slots))
	}
	if len(f.tokens) != platform.TPM2NextTokenReferences {
		t.Fatalf("%d token references after repair", len(f.tokens))
	}
	for id, raw := range f.tokens {
		if !bytes.Equal(raw, []byte(fixtureSealed)) {
			t.Fatalf("token %s is not the legacy sealed object", id)
		}
	}
	verified, err := f.p.verify(context.Background(), plan, &agentv1.DeviceActionVerification{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verified.GetEvidence(), "keyslot 1 completed to 4 identical token references") {
		t.Fatalf("evidence does not describe the repair: %q", verified.GetEvidence())
	}
	// Repaired, the bind is no longer a repair candidate.
	if _, again := f.repairPlan(t); again {
		t.Fatal("a complete reference set was planned for repair again")
	}
}

// Only a working product bind with the exact PCRs, identical references and
// too few of them is repaired; anything else stays a fresh bind.
func TestTPMBindRepairCandidates(t *testing.T) {
	for name, setup := range map[string]func(*tpmFixture){
		"release needs one": func(*tpmFixture) {},
		"stale policy":      func(f *tpmFixture) { f.fail = "stale" },
		"other PCRs": func(f *tpmFixture) {
			f.tokens["0"] = json.RawMessage(strings.Replace(fixtureSealed, `"tpm2-pcrs":[7]`, `"tpm2-pcrs":[7,11]`, 1))
		},
		"differing references": func(f *tpmFixture) {
			f.tokens["1"] = json.RawMessage(strings.Replace(fixtureSealed, "c2VhbGVkLW9iamVjdA==", "b3RoZXItb2JqZWN0", 1))
		},
		"owner slot": func(f *tpmFixture) {
			f.tokens["0"] = json.RawMessage(strings.Replace(fixtureSealed, `"keyslots":["1"]`, `"keyslots":["0"]`, 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			release := "ubuntu-24.04"
			if name == "release needs one" {
				release = "ubuntu-26.04"
			}
			f := newTPMFixture(t, release)
			f.legacyBind()
			setup(f)
			if _, ok := f.repairPlan(t); ok {
				t.Fatal("planned as a reference repair")
			}
		})
	}
}

// The repair is refused before its gate when the header lacks room, or when
// the header changed since the signed plan.
func TestTPMBindRepairRefusalsPrecedeEffect(t *testing.T) {
	t.Run("space", func(t *testing.T) {
		f := newTPMFixture(t, "ubuntu-24.04")
		f.legacyBind()
		f.jsonSize = 2000
		plan, ok := f.repairPlan(t)
		if !ok {
			t.Fatal("not a repair")
		}
		err := f.repair(t, plan)
		if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "luks2_metadata_space_exhausted") || f.gates != 0 {
			t.Fatalf("undersized LUKS2 JSON area not refused before the gate: %v", err)
		}
	})
	t.Run("changed header", func(t *testing.T) {
		f := newTPMFixture(t, "ubuntu-24.04")
		f.legacyBind()
		plan, ok := f.repairPlan(t)
		if !ok {
			t.Fatal("not a repair")
		}
		f.tokens["5"] = json.RawMessage(`{"type":"vendor","keyslots":[]}`)
		if err := f.repair(t, plan); !errors.Is(err, ErrConflict) || f.gates != 0 {
			t.Fatalf("header change after signing not refused before the gate: %v", err)
		}
	})
	t.Run("precondition", func(t *testing.T) {
		slot := uint32(1)
		before := &agentv1.DeviceActionObservation{Supported: true, Tpm2ReferenceRepairKeyslot: &slot}
		if samePrecondition(before, &agentv1.DeviceActionObservation{Supported: true}) || samePrecondition(&agentv1.DeviceActionObservation{Supported: true}, before) {
			t.Fatal("a repair plan matched a fresh-bind observation")
		}
	})
}
