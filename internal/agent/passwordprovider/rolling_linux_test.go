//go:build linux

package passwordprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
)

const nativeStackFixture = `#%PAM-1.0
# preserved administrator comment
auth required pam_faillock.so preauth
-auth [success=2 default=ignore] pam_systemd_home.so
auth [success=1 default=bad] pam_unix.so try_first_pass nullok
auth [default=die] pam_faillock.so authfail
auth optional pam_permit.so
auth required pam_faillock.so authsucc
account required pam_unix.so
-password [success=1 default=ignore] pam_systemd_home.so
password required pam_unix.so try_first_pass nullok shadow
password optional pam_permit.so
session required pam_limits.so
`

func archPolicyFixture() *agentv1.ResourceOwnershipSnapshot {
	s := policyFixture()
	s.PasswordPolicy.Files = s.PasswordPolicy.Files[:4]
	s.PasswordPolicy.ManagerProfile = "native-pam"
	s.PasswordPolicy.EnabledFeatures = []agentv1.PasswordNativeFeature{3}
	for _, kind := range []agentv1.PasswordNativeFile{9, 10} {
		s.PasswordPolicy.Files = append(s.PasswordPolicy.Files, &agentv1.PasswordNativeFileSnapshot{Kind: kind, State: &resourcev1.ManagedFileObservation{Path: filePath(kind)}})
	}
	setFileContent(nativeFile(s, 9), []byte(nativeStackFixture))
	return s
}

func TestNativePAMOwnedIncludeRoundtrip(t *testing.T) {
	before := archPolicyFixture()
	d := &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14), HistoryCount: proto.Uint32(5)}
	target, err := targetSnapshot(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	if err := targetNativePAM(before, target, nil); err != nil {
		t.Fatal(err)
	}
	stack := nativeFile(target, 9).GetContent()
	base, included, err := splitNativePAM(stack)
	if err != nil || !included || !bytes.Equal(base, []byte(nativeStackFixture)) {
		t.Fatalf("unrelated authentication bytes changed: %s %v", base, err)
	}
	if !bytes.Contains(stack, []byte("pam_unix.so try_first_pass nullok shadow"+nativeTokenSuffix)) {
		t.Fatal("native password writer does not consume checked token")
	}
	state, err := nativePAMState(stack, nativeFile(target, 10).GetContent(), true, nativeFile(target, 2).GetContent())
	if err != nil || !slices.Equal(state.features, []agentv1.PasswordNativeFeature{1, 2, 3}) {
		t.Fatalf("native feature readback: %v %v", state, err)
	}
	ledger := ledgerFixture(before, target, 1, 3)
	repeat, err := targetSnapshot(d, target, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	if err := targetNativePAM(target, repeat, ledger); err != nil || !targetMatches(target, repeat) {
		t.Fatalf("repeat changed owned state: %v", err)
	}
	released, err := targetSnapshot(d, target, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if err := targetNativePAM(target, released, ledger); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nativeFile(released, 9).GetContent(), []byte(nativeStackFixture)) || nativeFile(released, 10).GetState().GetExists() {
		t.Fatal("release failed to restore only owned include/token wiring")
	}
}

func TestNativePAMRejectsForeignIncludesAndTokenBypass(t *testing.T) {
	owned, err := insertNativeInclude([]byte(nativeStackFixture), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, stack := range []string{
		strings.Replace(nativeStackFixture, "password required pam_unix.so", "password include foreign", 1),
		string(owned) + nativePasswordInclude,
		strings.Replace(string(owned), nativeTokenSuffix, "\n", 1),
		strings.Replace(string(owned), nativePasswordInclude, "password optional lindm-password\n", 1),
	} {
		if _, err := nativePAMState([]byte(stack), nativePolicy([]agentv1.PasswordNativeFeature{1}), true, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsafe stack accepted: %v\n%s", err, stack)
		}
	}
	before := archPolicyFixture()
	setFileContent(nativeFile(before, 10), nativePolicy([]agentv1.PasswordNativeFeature{1}))
	target := proto.CloneOf(before)
	target.PasswordPolicy.AcquiredFeatures = []agentv1.PasswordNativeFeature{1}
	if err := targetNativePAM(before, target, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign policy adopted without ledger: %v", err)
	}
}

func TestPamConfigDoesNotInventLocalHistoryOrLockout(t *testing.T) {
	before := policyFixture()
	before.PasswordPolicy.EnabledFeatures = nil
	for _, feature := range []agentv1.PasswordNativeFeature{2, 3} {
		target := proto.CloneOf(before)
		target.PasswordPolicy.EnabledFeatures = []agentv1.PasswordNativeFeature{feature}
		if _, err := pamConfigOperation(before, target); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsupported feature %d accepted: %v", feature, err)
		}
	}
}

func TestPamConfigPreviewRejectsUnrelatedAuthenticationChanges(t *testing.T) {
	stacks := make(map[string][]byte)
	for _, name := range pamConfigStacks {
		stacks[name] = []byte("# generated\n")
	}
	stacks["common-password"] = []byte("password required pam_unix.so nullok\n")
	stacks["common-auth"] = []byte("auth required pam_unix.so try_first_pass\n")
	for _, corrupt := range []bool{false, true} {
		run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
			dir := filepath.Join(args[1], "pam.d")
			if err := os.WriteFile(filepath.Join(dir, "common-password-pc"), []byte("password requisite pam_pwquality.so\npassword required pam_unix.so use_authtok nullok\n"), 0600); err != nil {
				return nil, err
			}
			if corrupt {
				if err := os.WriteFile(filepath.Join(dir, "common-auth-pc"), []byte("auth sufficient pam_permit.so\n"), 0600); err != nil {
					return nil, err
				}
			}
			return nil, nil
		}
		_, err := renderPamConfig(context.Background(), stacks, []string{"--add", "--pwquality"}, run)
		if corrupt && !errors.Is(err, ErrUnsupported) || !corrupt && err != nil {
			t.Fatalf("preview corrupt=%t: %v", corrupt, err)
		}
	}
}

func TestRollingPackageQueriesRetainFullRelease(t *testing.T) {
	for _, tc := range []struct {
		product            *resourcev1.PlatformProduct
		name, output, want string
	}{
		{&resourcev1.PlatformProduct{OsId: "arch"}, "pam", "pam 1.7.3-1\n", "1.7.3-1"},
		{&resourcev1.PlatformProduct{OsId: "opensuse-tumbleweed", Version: "20261007"}, "pam-config", "2.14+git.20260216-1.4\n", "2.14+git.20260216-1.4"},
	} {
		run := func(context.Context, string, ...string) ([]byte, error) { return []byte(tc.output), nil }
		got, err := packageVersion(context.Background(), tc.product, tc.name, run)
		if err != nil || got != tc.want {
			t.Fatalf("full package release %q: %q %v", tc.name, got, err)
		}
	}
	run := func(context.Context, string, ...string) ([]byte, error) { return []byte("foreign 1.7.3-1\n"), nil }
	if _, err := packageVersion(context.Background(), &resourcev1.PlatformProduct{OsId: "arch"}, "pam", run); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("foreign pacman package accepted: %v", err)
	}
}

func TestRollingVersionsRejectUnrecordedRebuilds(t *testing.T) {
	for _, tc := range []struct {
		product               *resourcev1.PlatformProduct
		quality, pam, manager string
	}{
		{&resourcev1.PlatformProduct{OsId: "arch"}, "1.4.5-7", "1.7.3-1", "20260616-1"},
		{&resourcev1.PlatformProduct{OsId: "opensuse-tumbleweed", Version: "20261007"}, "1.4.5-5.7", "1.7.3-1.1", "2.14+git.20260216-1.4"},
	} {
		for feature, version := range map[agentv1.PasswordNativeFeature]string{1: tc.quality, 2: tc.pam, 3: tc.pam} {
			if !moduleVersionSupported(tc.product, feature, version) || moduleVersionSupported(tc.product, feature, version+".1") || moduleVersionSupported(tc.product, feature, upstreamVersion(version)) {
				t.Fatalf("%s feature %d did not enforce full package release", tc.product.GetOsId(), feature)
			}
		}
		for _, version := range []string{tc.manager, tc.manager + ".1"} {
			output := version
			if tc.product.GetOsId() == "arch" {
				output = "pambase " + output
			}
			run := func(context.Context, string, ...string) ([]byte, error) { return []byte(output + "\n"), nil }
			_, err := managerVersion(context.Background(), tc.product, run)
			if version == tc.manager && err != nil || version != tc.manager && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("manager version %q: %v", version, err)
			}
		}
	}
}

func TestNativePAMHistoryZeroLeavesPasswordWriterAbleToPrompt(t *testing.T) {
	for _, initial := range []uint32{0, 5} {
		before := archPolicyFixture()
		desired := &resourcev1.PasswordPolicyDesired{HistoryCount: proto.Uint32(initial)}
		target, err := targetSnapshot(desired, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
		if err != nil {
			t.Fatal(err)
		}
		if err := targetNativePAM(before, target, nil); err != nil {
			t.Fatal(err)
		}
		if initial != 0 {
			ledger := ledgerFixture(before, target, 3)
			desired.HistoryCount = proto.Uint32(0)
			next, err := targetSnapshot(desired, target, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
			if err != nil {
				t.Fatal(err)
			}
			if err := targetNativePAM(target, next, ledger); err != nil {
				t.Fatal(err)
			}
			target = next
		}
		stack := nativeFile(target, 9).GetContent()
		if bytes.Contains(stack, []byte("use_authtok")) {
			t.Fatalf("initial=%d: remember=0 requires a nonexistent token", initial)
		}
		if _, err := nativePAMState(stack, nativeFile(target, 10).GetContent(), true, nativeFile(target, 2).GetContent()); err != nil {
			t.Fatalf("initial=%d: zero-history readback: %v", initial, err)
		}
	}
	for _, zero := range []string{"0", "00", "000"} {
		produces, err := nativeTokenProduced([]agentv1.PasswordNativeFeature{2}, []byte("remember = "+zero+"\n"))
		if err != nil || produces {
			t.Fatalf("zero remember %q produces a token: %t %v", zero, produces, err)
		}
	}
}

func TestNativePAMRefusesHistoryBeforeUnownedQuality(t *testing.T) {
	before := archPolicyFixture()
	stack := strings.Replace(nativeStackFixture, "-password [success=1", "password requisite pam_pwquality.so retry=3\n-password [success=1", 1)
	setFileContent(nativeFile(before, 9), []byte(stack))
	before.PasswordPolicy.EnabledFeatures = []agentv1.PasswordNativeFeature{1, 3}
	target, err := targetSnapshot(&resourcev1.PasswordPolicyDesired{HistoryCount: proto.Uint32(5)}, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	if err := targetNativePAM(before, target, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("history-before-quality retry bypass accepted: %v", err)
	}
	if !bytes.Equal(nativeFile(before, 9).GetContent(), []byte(stack)) {
		t.Fatal("refused composition modified the observed stack")
	}
}

func TestPamConfigRejectsInactiveHigherPriorityInput(t *testing.T) {
	const vendor = "/usr/lib/pam.d/common-auth-pc"
	const orphan = "/etc/pam.d/common-auth-pc"
	content := []byte("# autogenerated by pam-config\nauth required pam_unix.so\n")
	for _, higher := range [][]byte{nil, content, []byte("auth sufficient pam_permit.so\n")} {
		files := map[string][]byte{vendor: content}
		if higher != nil {
			files[orphan] = higher
		}
		read := func(path string, _ int64) ([]byte, error) {
			data, ok := files[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return data, nil
		}
		err := pamConfigInputMatches("common-auth", vendor, content, read)
		if higher == nil && err != nil || higher != nil && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("higher priority input %q: %v", higher, err)
		}
	}
}

func TestPamConfigPublicationPreservesConcurrentAuthenticationEdit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root filesystem custody and leases")
	}
	dir, err := os.MkdirTemp("/var/lib", "lindm-pam-config-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	passwordPath := filepath.Join(dir, "common-password-pc")
	authPath := filepath.Join(dir, "common-auth-pc")
	password := []byte("password required pam_unix.so\n")
	auth := []byte("auth required pam_unix.so\n")
	for path, content := range map[string][]byte{passwordPath: password, authPath: auth} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	template := &resourcev1.ResourceObservation{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: passwordPath}, Metadata: &resourcev1.ObservationMetadata{}}
	file, err := nativefile.Capture(passwordPath, template)
	if err != nil {
		t.Fatal(err)
	}
	target := proto.CloneOf(file)
	target.ManagedFileContent = []byte("password requisite pam_pwquality.so\npassword required pam_unix.so use_authtok\n")
	digest := sha256.Sum256(target.ManagedFileContent)
	target.Observation.GetManagedFile().File.Sha256 = digest[:]
	tx, err := nativefile.Prepare(file, target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	generation := sha256.Sum256(auth)
	before := policyFixture()
	before.PasswordPolicy.ManagerGenerationSha256 = generation[:]
	// Synchronization seam: an administrator changes authentication after
	// rendering/preparation, before the nativefile publication callback.
	changed := []byte("auth required pam_unix.so try_first_pass\n")
	if err := os.WriteFile(authPath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	inspect := func(context.Context) (*managerState, error) {
		content, err := os.ReadFile(authPath)
		current := sha256.Sum256(content)
		return &managerState{generation: current[:], profileDigest: before.PasswordPolicy.ManagerProfileSha256}, err
	}
	after, err := tx.Commit(t.Context(), func(ctx context.Context) error {
		return pamConfigUnchanged(ctx, before, inspect)
	})
	if !errors.Is(err, ErrConflict) || after != nil {
		t.Fatalf("concurrent authentication edit produced convergence: %v %v", after, err)
	}
	for path, want := range map[string][]byte{passwordPath: password, authPath: changed} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("publication overwrote %s: %q %v", path, got, err)
		}
	}
}

func TestPamConfigReadbackFencesUnpublishedStackBytes(t *testing.T) {
	before := policyFixture()
	before.PasswordPolicy.ManagerProfile = "pam-config"
	target := proto.CloneOf(before)
	if !targetMatches(before, target) {
		t.Fatal("identical manager generation did not converge")
	}
	// Even a comment-only change to an unpublished input leaves the normalized
	// profile equal but must invalidate the exact post-publication graph.
	target.PasswordPolicy.ManagerGenerationSha256[0]++
	if targetMatches(before, target) {
		t.Fatal("changed unpublished PAM input produced a convergence receipt")
	}
}
