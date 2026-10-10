//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
)

func accountFixture(t *testing.T, password, expiry string) (*Provider, string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("real private-root shadow tests require root")
	}
	if _, err := os.Stat(executable[usermod]); errors.Is(err, os.ErrNotExist) {
		t.Skip("native shadow-utils usermod is unavailable")
	} else if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	shadow := "root:!:20000:0:99999:7:::\nalice:" + password + ":20000:0:99999:7::" + expiry + ":\nbreakglass:!:20000:0:99999:7:::\nservice:*:20000:0:99999:7:::\n"
	files := map[string]string{
		"passwd":     "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\nbreakglass:x:1001:1001:Break Glass:/home/breakglass:/bin/bash\nservice:x:999:999:Service:/nonexistent:/usr/sbin/nologin\n",
		"shadow":     shadow,
		"login.defs": "UID_MIN 1000\nUID_MAX 60000\n",
		"shells":     "/bin/bash\n/usr/sbin/nologin\n",
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(root, "etc", name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := journal.Initialize(t.Context(), directory, &agentv1.ExecutorJournalState{
		FormatVersion: 1, InstallationId: uuid.NewString(), ExecutionRootJson: []byte("test-root"), BootstrapEnvelope: []byte("test-envelope"),
		BootstrapVerifiedAt: timestamppb.Now(), EnrollmentTransactionId: uuid.NewString(), IdentityPrivateKey: make([]byte, ed25519.PrivateKeySize),
		EnrollmentCsrPem: bytes.Repeat([]byte{'x'}, 64), PendingGrant: strings.Repeat("g", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{config: &agentv1.DeviceActionProviderConfig{AllowAccountLock: true, ProtectedAccounts: []string{"breakglass"}}, accounts: &accountLocker{store: store, root: root}, run: runNative, clock: func() time.Time { return time.Unix(21000*86400, 0) }, sessionNative: func(context.Context, string) ([]graphicalSession, error) { return nil, nil }}
	t.Cleanup(func() { _ = p.accounts.store.Close() })
	return p, directory, shadow
}

func accountPlan(t *testing.T, p *Provider, spec *agentv1.DeviceActionSpec) *agentv1.DeviceActionPlan {
	t.Helper()
	observation := &agentv1.DeviceActionObservation{Supported: true, ObservedAt: timestamppb.Now()}
	if spec.GetReleaseLock() != nil {
		if err := p.observeReleaseLock(t.Context(), spec, observation); err != nil {
			t.Fatal(err)
		}
	} else {
		_, digest, err := p.sessions(t.Context(), false)
		if err != nil {
			t.Fatal(err)
		}
		observation.MetadataSha256 = digest
		if err := p.observeAccountLock(t.Context(), spec, observation); err != nil {
			t.Fatal(err)
		}
	}
	return &agentv1.DeviceActionPlan{Spec: spec, Before: observation, ActionId: uuid.NewString()}
}

func aliceLockSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{Usernames: []string{"alice"}}}}
}

func accountReleaseSpec(id string) *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: id}}}
}

func TestNativeAccountLockAndReleaseExactShadow(t *testing.T) {
	for _, password := range []string{"$6$private-test-hash", "!$6$prelocked", "*", ""} {
		t.Run("password-shape-"+string(rune('a'+len(password))), func(t *testing.T) {
			p, _, original := accountFixture(t, password, "")
			plan := accountPlan(t, p, aliceLockSpec())
			p.run = func(ctx context.Context, request nativeRequest) ([]byte, error) {
				ledger, _, err := p.accounts.store.LoadAccountLock(ctx, plan.GetActionId())
				if err != nil || len(ledger.GetAccounts()) != 1 {
					t.Fatalf("native effect preceded journal: %v", err)
				}
				if strings.Contains(strings.Join(request.args, " "), "$6$") {
					t.Fatal("password hash escaped to argv")
				}
				return runNative(ctx, request)
			}
			if err := p.applyAccountLock(t.Context(), plan); err != nil {
				t.Fatal(err)
			}
			verification := &agentv1.DeviceActionVerification{After: new(agentv1.DeviceActionObservation)}
			if err := p.verifyAccountLock(t.Context(), plan, verification); err != nil || !slices.Equal(verification.GetAfter().GetDisabledAccounts(), []string{"alice"}) {
				t.Fatalf("lock not verified: %v", err)
			}
			encoded, err := proto.Marshal(verification)
			if err != nil || bytes.Contains(encoded, []byte("$6$")) {
				t.Fatal("public observation contains shadow material")
			}
			release := accountPlan(t, p, accountReleaseSpec(plan.GetActionId()))
			if err := p.applyReleaseLock(t.Context(), release); err != nil {
				t.Fatal(err)
			}
			if err := p.verifyAccountLock(t.Context(), release, verification); err != nil || !verification.GetVerified() {
				t.Fatalf("release not verified: %v", err)
			}
			shadow, err := p.accounts.readLocal(t.Context(), "shadow")
			if err != nil || string(shadow) != original {
				t.Fatalf("exact prior state not restored: %v", err)
			}
			p.run = func(context.Context, nativeRequest) ([]byte, error) {
				t.Fatal("idempotent release invoked native tool")
				return nil, nil
			}
			if err := p.applyReleaseLock(t.Context(), accountPlan(t, p, accountReleaseSpec(plan.GetActionId()))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAccountLockPreservesAdministrativeChanges(t *testing.T) {
	for _, changed := range []string{"password", "expiry", "identity", "deleted"} {
		t.Run(changed, func(t *testing.T) {
			p, _, _ := accountFixture(t, "$6$private-test-hash", "")
			plan := accountPlan(t, p, aliceLockSpec())
			if err := p.applyAccountLock(t.Context(), plan); err != nil {
				t.Fatal(err)
			}
			name := "shadow"
			if changed == "identity" {
				name = "passwd"
			}
			path := filepath.Join(p.accounts.root, "etc", name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch changed {
			case "password":
				data = bytes.Replace(data, []byte("!$6$private-test-hash"), []byte("!$6$administrator"), 1)
			case "expiry":
				data = bytes.Replace(data, []byte("::1:"), []byte("::2:"), 1)
			case "identity":
				data = bytes.Replace(data, []byte("alice:x:1000:"), []byte("alice:x:2000:"), 1)
			case "deleted":
				lines := strings.Split(string(data), "\n")
				lines = slices.DeleteFunc(lines, func(line string) bool { return strings.HasPrefix(line, "alice:") })
				data = []byte(strings.Join(lines, "\n"))
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			p.run = func(context.Context, nativeRequest) ([]byte, error) {
				t.Fatal("administrator state was overwritten")
				return nil, nil
			}
			release := accountPlan(t, p, accountReleaseSpec(plan.GetActionId()))
			if err := p.applyReleaseLock(t.Context(), release); err != nil {
				t.Fatal(err)
			}
			verification := new(agentv1.DeviceActionVerification)
			if err := p.verifyAccountLock(t.Context(), release, verification); err != nil || !slices.Equal(verification.GetAfter().GetPreservedAccounts(), []string{"alice"}) {
				t.Fatalf("admin change not preserved: %v", err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, data) {
				t.Fatal("release changed administrator bytes")
			}
		})
	}
}

func TestAccountSelectionAndAlreadyExpiredOwnership(t *testing.T) {
	p, _, _ := accountFixture(t, "$6$private-test-hash", "1")
	for _, name := range []string{"root", "breakglass", "directory-only"} {
		spec := aliceLockSpec()
		spec.GetLockSessions().Usernames = []string{name}
		if err := p.observeAccountLock(t.Context(), spec, new(agentv1.DeviceActionObservation)); !errors.Is(err, ErrConflict) {
			t.Fatalf("unsafe selection %s: %v", name, err)
		}
	}
	all := aliceLockSpec()
	all.GetLockSessions().Usernames = nil
	all.GetLockSessions().AllHumanAccounts = true
	selected, err := p.selectedAccounts(t.Context(), all)
	if err != nil || len(selected) != 1 || selected[0].GetUsername() != "alice" {
		t.Fatalf("human selection wrong: %v", err)
	}
	p.run = func(context.Context, nativeRequest) ([]byte, error) {
		t.Fatal("already expired state claimed")
		return nil, nil
	}
	plan := accountPlan(t, p, all)
	if err := p.applyAccountLock(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	ledger, _, err := p.accounts.store.LoadAccountLock(t.Context(), plan.GetActionId())
	if err != nil || ledger.GetAccounts()[0].GetPhase() != agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED {
		t.Fatalf("expired account ownership: %v", err)
	}
	p.config.ProtectedAccounts = nil
	if _, err := p.selectedAccounts(t.Context(), all); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("all-human without break glass: %v", err)
	}
}

func TestAccountNativeFailureAndFreshReleaseRecovery(t *testing.T) {
	p, directory, _ := accountFixture(t, "$6$private-test-hash", "")
	plan := accountPlan(t, p, aliceLockSpec())
	if err := p.applyAccountLock(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	release := accountPlan(t, p, accountReleaseSpec(plan.GetActionId()))
	p.run = func(context.Context, nativeRequest) ([]byte, error) { return nil, errors.New("private-native-failure") }
	if err := p.applyReleaseLock(t.Context(), release); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("failure not unknown: %v", err)
	}
	if err := p.accounts.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := journal.Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	p.accounts.store = store
	same := accountPlan(t, p, accountReleaseSpec(plan.GetActionId()))
	same.ActionId = release.GetActionId()
	p.run = func(context.Context, nativeRequest) ([]byte, error) {
		t.Fatal("same unknown release auto-retried")
		return nil, nil
	}
	if err := p.applyReleaseLock(t.Context(), same); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unknown same-action release: %v", err)
	}
	p.run = runNative
	fresh := accountPlan(t, p, accountReleaseSpec(plan.GetActionId()))
	if err := p.applyReleaseLock(t.Context(), fresh); err != nil {
		t.Fatal(err)
	}
}

func TestAccountNativeStagingPreservesConcurrentAdminEdit(t *testing.T) {
	p, _, _ := accountFixture(t, "$6$private-test-hash", "")
	plan := accountPlan(t, p, aliceLockSpec())
	path := filepath.Join(p.accounts.root, "etc", "shadow")
	var edited []byte
	p.run = func(ctx context.Context, request nativeRequest) ([]byte, error) {
		out, err := runNative(ctx, request)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		edited = bytes.Replace(data, []byte("$6$private-test-hash"), []byte("$6$administrator"), 1)
		return out, os.WriteFile(path, edited, 0600)
	}
	if err := p.applyAccountLock(t.Context(), plan); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("race not held: %v", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, edited) {
		t.Fatal("staged native output overwrote independent edit")
	}
}

func TestAccountNativeForeignLocksNeverRemoved(t *testing.T) {
	for _, content := range []string{"999999999\x00", "malicious-pid", "1\x00"} {
		p, _, _ := accountFixture(t, "$6$private-test-hash", "")
		path := filepath.Join(p.accounts.root, "etc", "passwd.lock")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		plan := accountPlan(t, p, aliceLockSpec())
		p.run = func(context.Context, nativeRequest) ([]byte, error) { t.Fatal("foreign lock ignored"); return nil, nil }
		if err := p.applyAccountLock(t.Context(), plan); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("foreign lock not held: %v", err)
		}
		actual, err := os.ReadFile(path)
		if err != nil || string(actual) != content {
			t.Fatal("foreign lock was changed")
		}
	}
}

func TestAccountNativeCrashStageRecovery(t *testing.T) {
	if root := os.Getenv("LINDM_ACCOUNT_CRASH_ROOT"); root != "" {
		p := &Provider{accounts: &accountLocker{root: root}}
		p.run = func(ctx context.Context, request nativeRequest) ([]byte, error) {
			out, err := runNative(ctx, request)
			if err != nil {
				os.Exit(81)
			}
			_ = unix.Kill(os.Getpid(), unix.SIGKILL)
			return out, err
		}
		before, err := p.accounts.lookup(t.Context(), "alice")
		if err != nil {
			os.Exit(82)
		}
		after := proto.CloneOf(before)
		fields := strings.Split(after.GetShadowEntry(), ":")
		fields[1], fields[7] = strings.TrimPrefix(fields[1], "!"), ""
		after.ShadowEntry = strings.Join(fields, ":")
		_ = p.changeAccount(t.Context(), os.Getenv("LINDM_ACCOUNT_CRASH_ACTION"), before, after, false)
		os.Exit(83)
	}
	p, _, _ := accountFixture(t, "$6$private-test-hash", "")
	plan := accountPlan(t, p, aliceLockSpec())
	if err := p.applyAccountLock(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	ledger, revision, err := p.accounts.store.LoadAccountLock(t.Context(), plan.GetActionId())
	if err != nil {
		t.Fatal(err)
	}
	ledger.Accounts[0].Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING
	ledger.Accounts[0].ReleaseActionId = uuid.NewString()
	if _, err := p.accounts.store.UpdateAccountLock(t.Context(), revision, ledger); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestAccountNativeCrashStageRecovery$")
	cmd.Env = append(os.Environ(), "LINDM_ACCOUNT_CRASH_ROOT="+p.accounts.root, "LINDM_ACCOUNT_CRASH_ACTION="+plan.GetActionId())
	if err := cmd.Run(); err == nil {
		t.Fatal("crash child survived")
	}
	stage := accountStage(filepath.Join(p.accounts.root, "etc"), plan.GetActionId(), "alice")
	if _, err := os.Stat(filepath.Join(stage, "etc", "shadow")); err != nil {
		t.Fatalf("child did not reach staged crash boundary: %v", err)
	}
	release := accountPlan(t, p, accountReleaseSpec(plan.GetActionId()))
	if err := p.applyReleaseLock(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private crashed stage retained: %v", err)
	}
}

func TestAccountShadowMetadataAndFutureExpirySurvive(t *testing.T) {
	p, _, original := accountFixture(t, "$6$private-test-hash", "25000")
	path := filepath.Join(p.accounts.root, "etc", "shadow")
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	xattr := []byte("retained-native-shadow-label")
	err := unix.Setxattr(path, "user.lindm-test", xattr, 0)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
		t.Skip("shadow xattr test requires filesystem xattrs")
	}
	if err != nil {
		t.Fatal(err)
	}
	plan := accountPlan(t, p, aliceLockSpec())
	if err := p.applyAccountLock(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := p.applyReleaseLock(t.Context(), accountPlan(t, p, accountReleaseSpec(plan.GetActionId()))); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != original {
		t.Fatal("future expiry or shadow attributes changed")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatal("shadow mode changed")
	}
	value := make([]byte, 128)
	n, err := unix.Getxattr(path, "user.lindm-test", value)
	if err != nil || !bytes.Equal(value[:n], xattr) {
		t.Fatal("shadow xattr lost")
	}
}

func TestAccountPreconditionsAndNativeFailureNeverReplay(t *testing.T) {
	p, _, _ := accountFixture(t, "$6$private-test-hash", "")
	plan := accountPlan(t, p, aliceLockSpec())
	path := filepath.Join(p.accounts.root, "etc", "passwd")
	prior, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Replace(prior, []byte("Alice:"), []byte("Changed:"), 1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.applyAccountLock(t.Context(), plan); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale account digest accepted: %v", err)
	}
	if _, _, err := p.accounts.store.LoadAccountLock(t.Context(), plan.GetActionId()); !errors.Is(err, journal.ErrAccountLockNotFound) {
		t.Fatal("stale precondition acquired ownership")
	}
	plan = accountPlan(t, p, aliceLockSpec())
	calls := 0
	p.run = func(context.Context, nativeRequest) ([]byte, error) {
		calls++
		return nil, errors.New("interrupted native staging")
	}
	if err := p.applyAccountLock(t.Context(), plan); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("native failure not unknown: %v", err)
	}
	if err := p.applyAccountLock(t.Context(), plan); !errors.Is(err, journal.ErrAccountLockRejected) {
		t.Fatalf("ambiguous lock replay accepted: %v", err)
	}
	if calls != 1 {
		t.Fatal("native effect replayed")
	}
	release := accountPlan(t, p, accountReleaseSpec(plan.GetActionId()))
	if err := p.applyReleaseLock(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("release mutated unchanged pre-lock state")
	}
}

func TestSessionOnlyReleaseDoesNotRequireAccountOptIn(t *testing.T) {
	p := &Provider{config: new(agentv1.DeviceActionProviderConfig)}
	release := accountPlan(t, p, accountReleaseSpec(uuid.NewString()))
	if err := p.applyReleaseLock(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	verification := new(agentv1.DeviceActionVerification)
	if err := p.verifyAccountLock(t.Context(), release, verification); err != nil || !verification.GetVerified() {
		t.Fatalf("session-only release failed: %v", err)
	}
	if len(verification.GetAfter().GetDisabledAccounts()) != 0 || !strings.Contains(verification.GetEvidence(), "not unlocked") {
		t.Fatal("session-only release claimed account or screen effects")
	}
}
