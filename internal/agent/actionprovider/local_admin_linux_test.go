//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/privatecustody"
)

// privateCustodyAdapter uses the real installation custody with the same
// binding fields the journal derives, without opening a SQLite journal.
type privateCustodyAdapter struct{ custody *privatecustody.Custody }

func (a privateCustodyAdapter) binding(b *agentv1.LocalAdminPasswordBinding) []byte {
	return privatecustody.Binding("test-local-admin", b.GetActionId(), b.GetAccountName(), strconv.FormatUint(uint64(b.GetAccountUid()), 10))
}
func (a privateCustodyAdapter) SealLocalAdminPassword(b *agentv1.LocalAdminPasswordBinding, password []byte) (*agentv1.PrivateCustodyEnvelope, error) {
	return a.custody.Seal(password, a.binding(b))
}
func (a privateCustodyAdapter) OpenLocalAdminPassword(b *agentv1.LocalAdminPasswordBinding, envelope *agentv1.PrivateCustodyEnvelope) ([]byte, error) {
	return a.custody.Open(envelope, a.binding(b))
}

type localAdminFixture struct {
	p        *Provider
	accounts map[string]*agentv1.AccountLockSnapshot
	sealed   [][]byte
	native   []nativeRequest
	gates    int
	// set models chpasswd's shadow rewrite for the deterministic fixture.
	set func(name string)
}

func newLocalAdminFixture(t *testing.T) *localAdminFixture {
	t.Helper()
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	custody, err := privatecustody.Initialize(directory, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(custody.Close)
	f := &localAdminFixture{accounts: map[string]*agentv1.AccountLockSnapshot{
		"lapsadmin": {Username: "lapsadmin", Uid: 1001, ShadowEntry: "lapsadmin:$y$j9T$old$hash:19000:0:99999:7:::"},
		"toor":      {Username: "toor", Uid: 0, ShadowEntry: "toor:$y$j9T$root$hash:19000:0:99999:7:::"},
		"operator":  {Username: "operator", Uid: 1002, ShadowEntry: "operator:$y$j9T$op$hash:19000:0:99999:7:::"},
	}}
	f.set = func(name string) {
		f.accounts[name].ShadowEntry = name + ":$y$j9T$new$hash:20000:0:99999:7:::"
	}
	f.p = &Provider{config: &agentv1.DeviceActionProviderConfig{LocalAdminAccounts: []string{"lapsadmin", "toor", "absent"}}, validate: validator, gate: make(chan struct{}, 1), clock: func() time.Time { return time.Unix(1800000000, 0) }}
	f.p.run = func(_ context.Context, request nativeRequest) ([]byte, error) {
		f.native = append(f.native, nativeRequest{command: request.command, args: request.args, input: bytes.Clone(request.input), files: request.files})
		if request.command != chpasswd {
			return nil, errors.New("unexpected native operation")
		}
		name, _, _ := strings.Cut(string(request.input), ":")
		f.set(name)
		return nil, nil
	}
	f.p.localAdmin = &localAdminNative{
		seal: func(_ context.Context, binding *agentv1.LocalAdminPasswordBinding, spec *agentv1.DeviceActionSpec, password []byte) ([]byte, error) {
			if binding.GetAccountName() != spec.GetLocalAdminPasswordRotate().GetAccountName() {
				return nil, errors.New("wrong sealing binding")
			}
			f.sealed = append(f.sealed, bytes.Clone(password))
			return []byte("opaque-server-sealed-fixture"), nil
		},
		custody: privateCustodyAdapter{custody},
		accounts: func(context.Context) (map[string]*agentv1.AccountLockSnapshot, error) {
			clone := make(map[string]*agentv1.AccountLockSnapshot, len(f.accounts))
			for name, account := range f.accounts {
				clone[name] = proto.CloneOf(account)
			}
			return clone, nil
		},
		root: "/",
	}
	return f
}

func localAdminSpec(account string) *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LocalAdminPasswordRotate{LocalAdminPasswordRotate: &agentv1.LocalAdminPasswordRotateAction{AccountName: account, EscrowKeyId: strings.Repeat("d", 64), EscrowPublicKey: bytes.Repeat([]byte{1}, 256)}}}
}

func (f *localAdminFixture) gate(context.Context) error {
	f.gates++
	return nil
}

func (f *localAdminFixture) plan(t *testing.T) *agentv1.DeviceActionPlan {
	t.Helper()
	spec := localAdminSpec("lapsadmin")
	before, err := f.p.Observe(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.p.Plan(t.Context(), spec, before)
	if err != nil {
		t.Fatal(err)
	}
	plan.ActionId = fixtureAction
	plan.LocalAdminBinding.DeviceId = "1b0fa740-4e8c-4938-8d24-6455c0b45b8d"
	plan.LocalAdminBinding.EnrollmentGeneration = "31c6a42c-d448-4861-97fc-cfcd5e34b915"
	plan.LocalAdminBinding.ActionId = fixtureAction
	return plan
}

func TestLocalAdminObservationRequiresAllowlistedNonRootAccount(t *testing.T) {
	f := newLocalAdminFixture(t)
	for account, reason := range map[string]string{"operator": "local_admin_account_not_allowlisted", "toor": "local_admin_root_refused", "absent": "local_admin_account_missing", "root": "local_admin_account_not_allowlisted"} {
		observation, err := f.p.Observe(t.Context(), localAdminSpec(account))
		if err != nil {
			t.Fatal(err)
		}
		if observation.GetSupported() || observation.GetReason() != reason {
			t.Fatalf("%s: supported=%v reason=%q", account, observation.GetSupported(), observation.GetReason())
		}
		if _, err := f.p.Plan(t.Context(), localAdminSpec(account), observation); err == nil {
			t.Fatalf("%s: refused account planned", account)
		}
	}
	plan := f.plan(t)
	want := &agentv1.LocalAdminAccountObservation{AccountName: "lapsadmin", AccountUid: 1001, PasswordUsable: true, PasswordChangedDay: 19000}
	if !proto.Equal(plan.GetBefore().GetLocalAdmin(), want) || plan.GetLocalAdminBinding().GetAccountUid() != 1001 {
		t.Fatalf("observed plan: %v", plan)
	}
	if len(f.native) != 0 {
		t.Fatal("observation ran a native tool")
	}
}

func TestLocalAdminStageEscrowsWithoutNativeChange(t *testing.T) {
	f := newLocalAdminFixture(t)
	plan := f.plan(t)
	before := proto.CloneOf(f.accounts["lapsadmin"])
	stage, envelope, err := f.p.StageLocalAdminPassword(t.Context(), plan, f.gate)
	if err != nil {
		t.Fatal(err)
	}
	if f.gates != 1 || len(f.native) != 0 || !proto.Equal(f.accounts["lapsadmin"], before) {
		t.Fatal("phase one changed the account or skipped its gate")
	}
	if len(f.sealed) != 1 || len(f.sealed[0]) != 26 || strings.Trim(string(f.sealed[0]), localAdminAlphabet) != "" {
		t.Fatalf("generated password shape: %d", len(f.sealed[0]))
	}
	digest := sha256.Sum256(f.sealed[0])
	escrow := stage.GetEscrow()
	if !proto.Equal(escrow.GetLocalAdmin(), plan.GetLocalAdminBinding()) || !bytes.Equal(escrow.GetRecoveryKeySha256(), digest[:]) || escrow.GetLuksUuid() != "" || stage.GetVerified() {
		t.Fatalf("staged escrow: %v", escrow)
	}
	encoded, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, f.sealed[0]) || bytes.Contains([]byte(stage.String()), f.sealed[0]) {
		t.Fatal("plaintext left custody")
	}
	// A renumbered account is a different principal: refuse before the gate.
	f.accounts["lapsadmin"].Uid = 1005
	if _, _, err := f.p.StageLocalAdminPassword(t.Context(), plan, f.gate); !errors.Is(err, ErrConflict) || f.gates != 1 {
		t.Fatalf("renumbered account staged: %v", err)
	}
}

func TestLocalAdminSetUsesStagedCustodyAndVerifiesShadow(t *testing.T) {
	f := newLocalAdminFixture(t)
	plan := f.plan(t)
	stage, envelope, err := f.p.StageLocalAdminPassword(t.Context(), plan, f.gate)
	if err != nil {
		t.Fatal(err)
	}
	// Only the exact staged escrow and its custody authorize the native set.
	wrongStage := proto.CloneOf(stage)
	wrongStage.Escrow.LocalAdmin.AccountUid = 1002
	if _, err := f.p.SetLocalAdminPassword(t.Context(), plan, wrongStage, envelope, f.gate); !errors.Is(err, ErrConflict) {
		t.Fatalf("rebound stage: %v", err)
	}
	otherEnvelope, err := f.p.localAdmin.custody.SealLocalAdminPassword(&agentv1.LocalAdminPasswordBinding{ActionId: uuid.NewString(), AccountName: "lapsadmin", AccountUid: 1001}, f.sealed[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.SetLocalAdminPassword(t.Context(), plan, stage, otherEnvelope, f.gate); err == nil {
		t.Fatal("custody of another action opened")
	}
	if f.gates != 1 || len(f.native) != 0 {
		t.Fatal("refused set consumed authority or ran chpasswd")
	}
	result, err := f.p.SetLocalAdminPassword(t.Context(), plan, stage, envelope, f.gate)
	if err != nil {
		t.Fatal(err)
	}
	if f.gates != 2 || len(f.native) != 1 || !result.GetVerified() || result.GetAfter().GetLocalAdmin().GetPasswordChangedDay() != 20000 || !proto.Equal(result.GetEscrow(), stage.GetEscrow()) {
		t.Fatalf("set result: %v", result)
	}
	call := f.native[0]
	if len(call.args) != 0 || len(call.files) != 0 || string(call.input) != "lapsadmin:"+string(f.sealed[0])+"\n" {
		t.Fatal("chpasswd did not receive exactly one stdin record")
	}
	for name, failure := range map[string]func(){
		"native failure": func() {
			f.p.run = func(context.Context, nativeRequest) ([]byte, error) { return nil, errors.New("interrupted") }
		},
		"unchanged shadow": func() {
			f.p.run = func(context.Context, nativeRequest) ([]byte, error) { return nil, nil }
		},
		"locked result": func() {
			f.p.run = func(context.Context, nativeRequest) ([]byte, error) {
				f.accounts["lapsadmin"].ShadowEntry = "lapsadmin:!$y$j9T$locked:20001:0:99999:7:::"
				return nil, nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			failure()
			if _, err := f.p.SetLocalAdminPassword(t.Context(), plan, stage, envelope, f.gate); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("ambiguous set: %v", err)
			}
		})
	}
}

// Root-only: real chpasswd against a temporary root. PAM modules cannot load in
// the chroot, so this seam passes SHA512 explicitly; production uses system
// hashing in "/". It proves the stdin protocol and shadow verification only.
func TestLocalAdminNativeChpasswdTemporaryRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := exec.LookPath(executable[chpasswd]); err != nil {
		t.Skip("chpasswd unavailable")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(root, "etc")
	if err := os.Mkdir(etc, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]struct {
		content string
		mode    os.FileMode
	}{
		"passwd":     {"root:x:0:0:root:/root:/bin/sh\nlapsadmin:x:1001:1001::/home/lapsadmin:/bin/sh\n", 0644},
		"shadow":     {"root:*:19000:0:99999:7:::\nlapsadmin:!:19000:0:99999:7:::\n", 0640},
		"group":      {"root:x:0:\nlapsadmin:x:1001:\n", 0644},
		"login.defs": {"ENCRYPT_METHOD SHA512\n", 0644},
	}
	for name, file := range files {
		if err := os.WriteFile(filepath.Join(etc, name), []byte(file.content), file.mode); err != nil {
			t.Fatal(err)
		}
	}
	f := newLocalAdminFixture(t)
	locker := &accountLocker{root: root}
	f.p.run = runNative
	f.p.localAdmin.accounts = locker.readAccounts
	f.p.localAdmin.root = root
	f.p.config.LocalAdminAccounts = []string{"lapsadmin"}
	plan := f.plan(t)
	stage, envelope, err := f.p.StageLocalAdminPassword(t.Context(), plan, f.gate)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.p.SetLocalAdminPassword(t.Context(), plan, stage, envelope, f.gate)
	if err != nil {
		if errors.Is(err, ErrOutcomeUnknown) && strings.Contains(err.Error(), "native") {
			t.Skipf("chpasswd cannot run in this temporary root: %v", err)
		}
		t.Fatal(err)
	}
	shadow, err := os.ReadFile(filepath.Join(etc, "shadow"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.GetVerified() || !bytes.Contains(shadow, []byte("lapsadmin:$6$")) || bytes.Contains(shadow, f.sealed[0]) {
		t.Fatal("native set did not install a hashed usable password")
	}
}
