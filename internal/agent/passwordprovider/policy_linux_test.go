//go:build linux

package passwordprovider

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func policyFixture() *agentv1.ResourceOwnershipSnapshot {
	s := &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Ref: passwordRef(), Observed: &resourcev1.ResourceObservation_PasswordPolicy{PasswordPolicy: &resourcev1.PasswordPolicyObservation{PamOwner: "pam-auth-update", Effective: &resourcev1.PasswordPolicyDesired{MaxAgeDays: proto.Uint32(99999)}}}}, PasswordPolicy: &agentv1.PasswordPolicyOwnership{ManagerProfile: "pam-auth-update", ManagerGenerationSha256: make([]byte, 32), ManagerProfileSha256: make([]byte, 32), EnabledFeatures: []agentv1.PasswordNativeFeature{1, 2, 3}}}
	s.PasswordPolicy.QualityDropinsSha256 = make([]byte, 32)
	for kind := agentv1.PasswordNativeFile(1); kind <= 8; kind++ {
		f := &agentv1.PasswordNativeFileSnapshot{Kind: kind, State: &resourcev1.ManagedFileObservation{Path: filePath(kind), AncestrySha256: make([]byte, 32), NativeIdentitySha256: make([]byte, 32), SecurityMetadataSha256: make([]byte, 32)}, NativeRevisionSha256: make([]byte, 32)}
		if kind <= 4 {
			setFileContent(f, []byte("# administrator configuration\n"))
		}
		s.PasswordPolicy.Files = append(s.PasswordPolicy.Files, f)
	}
	return s
}
func ledgerFixture(before, after *agentv1.ResourceOwnershipSnapshot, fields ...resourcev1.PasswordField) *agentv1.ResourceOwnershipLedger {
	l := &agentv1.ResourceOwnershipLedger{Baseline: proto.CloneOf(before), LastApplied: proto.CloneOf(after), Owner: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}}, State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED}
	for _, f := range fields {
		l.OwnedDimensions = append(l.OwnedDimensions, dimension(f))
	}
	l.OwnedDimensions = append(l.OwnedDimensions, 49)
	return l
}
func TestExactLengthDisablesScoringCredits(t *testing.T) {
	before := policyFixture()
	setFileContent(nativeFile(before, 1), []byte("minlen = 8\ndcredit = 2\n# keep me\nmaxrepeat = 4\n"))
	d := &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}
	target, err := targetSnapshot(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := effectivePolicy(target, map[string]string{"minlen": "24", "dcredit": "3"})
	if err != nil {
		t.Fatal(err)
	}
	if effective.GetMinLength() != 14 {
		t.Fatalf("character minimum = %d", effective.GetMinLength())
	}
	text := string(nativeFile(target, 1).GetContent())
	if !strings.Contains(text, "# keep me\nmaxrepeat = 4\n") {
		t.Fatal("unrelated configuration changed")
	}
	for _, key := range []string{"dcredit", "ucredit", "lcredit", "ocredit"} {
		if !strings.Contains(text, key+" = 0") {
			t.Fatalf("%s scoring remains", key)
		}
	}
}
func TestNativePrecedenceAndSetFlagSemantics(t *testing.T) {
	s := policyFixture()
	setFileContent(nativeFile(s, 1), []byte("minlen = 14\nenforce_for_root = 0\n"))
	setFileContent(nativeFile(s, 2), []byte("enforce_for_root = 0\n"))
	effective, err := effectivePolicy(s, map[string]string{"minlen": "22"})
	if err != nil {
		t.Fatal(err)
	}
	if effective.GetMinLength() != 14 || !effective.GetEnforceForRoot() {
		t.Fatal("main file or set-only flag interpreted unlike libpwquality")
	}
	setFileContent(nativeFile(s, 1), []byte("minlen = 14\ndcredit = 1\n"))
	effective, err = effectivePolicy(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if effective.MinLength != nil {
		t.Fatal("score-based length claimed as actual character count")
	}
	setFileContent(nativeFile(s, 1), []byte("minlen = 14\nminlen = 8\n"))
	if _, err := effectivePolicy(s, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("duplicate config = %v", err)
	}
}
func TestReleaseOnlyOwnedDimensions(t *testing.T) {
	before := policyFixture()
	setFileContent(nativeFile(before, 1), []byte("# native baseline\nminlen = 8\nmaxrepeat = 2\n"))
	setFileContent(nativeFile(before, 4), []byte("PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nMAIL_DIR /var/mail\n"))
	desired := &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14), MaxAgeDays: proto.Uint32(90)}
	applied, err := targetSnapshot(desired, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	ledger := ledgerFixture(before, applied, 1, 4)
	current := proto.CloneOf(applied)
	setFileContent(nativeFile(current, 1), []byte(strings.ReplaceAll(string(nativeFile(current, 1).GetContent()), "maxrepeat = 2", "maxrepeat = 5")))
	setFileContent(nativeFile(current, 4), []byte(strings.ReplaceAll(string(nativeFile(current, 4).GetContent()), "MAIL_DIR /var/mail", "MAIL_DIR /srv/mail")))
	restored, err := targetSnapshot(desired, current, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	quality := string(nativeFile(restored, 1).GetContent())
	if !strings.Contains(quality, "minlen = 8") || !strings.Contains(quality, "maxrepeat = 5") || strings.Contains(quality, "dcredit") {
		t.Fatalf("bad owned release %q", quality)
	}
	login := string(nativeFile(restored, 4).GetContent())
	if !strings.Contains(login, "PASS_MAX_DAYS 99999") || !strings.Contains(login, "MAIL_DIR /srv/mail") {
		t.Fatalf("bad login default release %q", login)
	}
	setFileContent(nativeFile(current, 1), []byte(strings.ReplaceAll(string(nativeFile(current, 1).GetContent()), "minlen = 14", "minlen = 16")))
	if _, err := targetSnapshot(desired, current, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrConflict) {
		t.Fatalf("external owned edit overwritten: %v", err)
	}
}
func TestReleaseRetainsOtherManagerFeatures(t *testing.T) {
	before := policyFixture()
	before.PasswordPolicy.EnabledFeatures = []agentv1.PasswordNativeFeature{1}
	desired := &resourcev1.PasswordPolicyDesired{HistoryCount: proto.Uint32(6)}
	applied, err := targetSnapshot(desired, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	ledger := ledgerFixture(before, applied, 3)
	current := proto.CloneOf(applied)
	current.PasswordPolicy.EnabledFeatures = append(current.PasswordPolicy.EnabledFeatures, 3)
	restored, err := targetSnapshot(desired, current, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if !slicesEqualFeatures(restored.PasswordPolicy.EnabledFeatures, []agentv1.PasswordNativeFeature{1, 3}) {
		t.Fatalf("unrelated lockout feature lost: %v", restored.PasswordPolicy.EnabledFeatures)
	}
	if nativeFile(restored, 6).GetState().GetExists() {
		t.Fatal("owned history profile not released")
	}
}
func slicesEqualFeatures(a, b []agentv1.PasswordNativeFeature) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func TestUnsupportedControlsFailClosed(t *testing.T) {
	ubuntu := &resourcev1.PlatformProduct{OsId: "ubuntu", Version: "24.04"}
	if err := policySupported(&resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(5)}, ubuntu); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	// shadow 4.20 removed PASS_MIN_DAYS and its tools fail while it is set.
	minAge := &resourcev1.PasswordPolicyDesired{MinAgeDays: proto.Uint32(1)}
	for _, product := range []*resourcev1.PlatformProduct{{OsId: "arch"}, {OsId: "opensuse-tumbleweed", Version: "20261009"}, {OsId: "omarchy", Version: "4.0.4"}} {
		if err := policySupported(minAge, product); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s minimum age accepted: %v", product.GetOsId(), err)
		}
	}
	if err := policySupported(minAge, ubuntu); err != nil {
		t.Fatalf("shadow before 4.20 refused minimum age: %v", err)
	}
	for _, body := range []string{"enforcing = 0\n", "minlen = invalid\n"} {
		s := policyFixture()
		setFileContent(nativeFile(s, 1), []byte(body))
		if _, err := effectivePolicy(s, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsafe config accepted: %q %v", body, err)
		}
	}
	s := policyFixture()
	setFileContent(nativeFile(s, 3), []byte("even_deny_root\n"))
	if _, err := effectivePolicy(s, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("root lockout accepted: %v", err)
	}
}

// shadow's getdef skips a name without a value, as Arch's shadow 4.20
// login.defs ships MOTD_FILE; two values remain refused.
func TestLoginDefsBareNameDefinesNothing(t *testing.T) {
	s := policyFixture()
	setFileContent(nativeFile(s, 4), []byte("MOTD_FILE\nPASS_MAX_DAYS\t90\n"))
	got, err := effectivePolicy(s, nil)
	if err != nil || got.GetMaxAgeDays() != 90 {
		t.Fatalf("bare login.defs name: %v %v", got, err)
	}
	setFileContent(nativeFile(s, 4), []byte("PASS_MAX_DAYS 90 30\n"))
	if _, err := effectivePolicy(s, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ambiguous login.defs value accepted: %v", err)
	}
}
func TestUnknownOwnershipNeverReplays(t *testing.T) {
	err := acquisitionAllowed(&agentv1.ResourceOwnershipBinding{}, &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN}, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
}
func TestNativeManagerControlFlow(t *testing.T) {
	valid := "auth required pam_faillock.so preauth silent\nauth sufficient pam_unix.so\nauth required pam_faillock.so authfail\naccount required pam_faillock.so\npassword requisite pam_pwquality.so retry=3\npassword [default=1 ignore=ignore success=ok] pam_localuser.so\npassword required pam_pwhistory.so use_authtok\npassword sufficient pam_unix.so use_authtok\n"
	got, err := inspectStacks(map[string][]byte{"system-auth": []byte(valid)})
	if err != nil {
		t.Fatal(err)
	}
	if !slicesEqualFeatures(got, []agentv1.PasswordNativeFeature{1, 2, 3}) {
		t.Fatal(got)
	}
	for _, bad := range []string{strings.Replace(valid, "retry=3", "minlen=2", 1), strings.Replace(valid, "auth required pam_faillock.so authfail\n", "", 1), "password sufficient pam_permit.so\n" + valid, strings.Replace(valid, "password requisite pam_pwquality.so", "password optional pam_pwquality.so", 1), "@include password-auth\n"} {
		if _, err := inspectStacks(map[string][]byte{"stack": []byte(bad)}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsafe PAM accepted: %q: %v", bad, err)
		}
	}
}
func TestPamAuthUpdateCacheUsesSymbolicJumps(t *testing.T) {
	cache := []byte("Module: unix\n[success=end default=ignore] pam_unix.so nullok\nModule: capability\noptional pam_cap.so\n")
	stack := []byte("# here are the per-package modules (the \"Primary\" block)\nauth [success=1 default=ignore] pam_unix.so nullok\n# here's the fallback if no module succeeds\nauth requisite pam_deny.so\n# and here are more per-package modules (the \"Additional\" block)\nauth optional pam_cap.so\n# end of pam-auth-update config\n")
	if !cacheMatches(cache, stack) {
		t.Fatal("native symbolic end cache rejected")
	}
	if cacheMatches(cache, bytes.ReplaceAll(stack, []byte("pam_unix.so"), []byte("pam_permit.so"))) {
		t.Fatal("external PAM edit accepted as manager owned")
	}
}
func TestAccessGuardRequiresLiveRootSession(t *testing.T) {
	config := &agentv1.NativePasswordProviderConfig{Enabled: true, RecoverySessionId: "42"}
	for _, body := range []string{"Active=yes\nState=active\nUser=1000\nLeader=42\n", "Active=no\nState=closing\nUser=0\nLeader=42\n", "Active=yes\nState=active\nUser=0\nLeader=1\n"} {
		run := func(context.Context, string, ...string) ([]byte, error) { return []byte(body), nil }
		if err := accessGuard(context.Background(), config, run); !errors.Is(err, ErrAccessGuard) {
			t.Fatal(err)
		}
	}
	run := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Active=yes\nState=active\nUser=0\nLeader=42\n"), nil
	}
	if err := accessGuard(context.Background(), config, run); err != nil {
		t.Fatal(err)
	}
}
func TestManagerEnablementDoesNotSelectOrForce(t *testing.T) {
	before := policyFixture()
	before.PasswordPolicy.EnabledFeatures = []agentv1.PasswordNativeFeature{1}
	target := proto.CloneOf(before)
	target.PasswordPolicy.EnabledFeatures = []agentv1.PasswordNativeFeature{1, 2, 3}
	var calls [][]string
	run := func(_ context.Context, path string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{path}, args...))
		return nil, nil
	}
	if err := changeManager(context.Background(), &resourcev1.PlatformProduct{OsId: "ubuntu", Version: "24.04"}, before, target, run); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || strings.Join(calls[1], " ") != "/usr/sbin/pam-auth-update --enable lindm-faillock lindm-faillock-pre" {
		t.Fatal(calls)
	}
	interrupted := errors.New("interrupted")
	run = func(context.Context, string, ...string) ([]byte, error) { return nil, interrupted }
	if err := changeManager(context.Background(), &resourcev1.PlatformProduct{OsId: "fedora", Version: "44"}, before, target, run); !errors.Is(err, interrupted) {
		t.Fatal(err)
	}
}

func TestRootPasswordEnforcementOwnsQualityAndHistory(t *testing.T) {
	before := policyFixture()
	d := &resourcev1.PasswordPolicyDesired{EnforceForRoot: proto.Bool(true)}
	applied, err := targetSnapshot(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []agentv1.PasswordNativeFile{1, 2} {
		if !bytes.Contains(nativeFile(applied, kind).GetContent(), []byte("enforce_for_root")) {
			t.Fatal("root password check omitted")
		}
	}
	restored, err := targetSnapshot(d, applied, ledgerFixture(before, applied, 9), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []agentv1.PasswordNativeFile{1, 2} {
		if bytes.Contains(nativeFile(restored, kind).GetContent(), []byte("enforce_for_root")) {
			t.Fatal("root enforcement not released")
		}
	}
}

func TestReleaseRestoresAbsentConfiguration(t *testing.T) {
	before := policyFixture()
	file := nativeFile(before, 1)
	file.Content = nil
	file.State.Exists = false
	file.State.File = nil
	d := &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}
	applied, err := targetSnapshot(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := targetSnapshot(d, applied, ledgerFixture(before, applied, 1), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if nativeFile(restored, 1).GetState().GetExists() {
		t.Fatal("still-owned new configuration not removed")
	}
}

func TestLaterObservedFeaturesAreNotAcquired(t *testing.T) {
	before := policyFixture()
	before.PasswordPolicy.EnabledFeatures = []agentv1.PasswordNativeFeature{1}
	d := &resourcev1.PasswordPolicyDesired{HistoryCount: proto.Uint32(6)}
	first, err := targetSnapshot(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	ledger := ledgerFixture(before, first, 3)
	current := proto.CloneOf(first)
	current.PasswordPolicy.EnabledFeatures = append(current.PasswordPolicy.EnabledFeatures, 3)
	next, err := targetSnapshot(d, current, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	ledger.LastApplied = next
	released, err := targetSnapshot(d, next, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if !slicesEqualFeatures(released.PasswordPolicy.EnabledFeatures, []agentv1.PasswordNativeFeature{1, 3}) {
		t.Fatal("later administrator feature was released")
	}
}

func TestAddingDimensionRetainsOriginalNativeBaseline(t *testing.T) {
	before := policyFixture()
	before.PasswordPolicy.EnabledFeatures = nil
	first, err := targetSnapshot(&resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	ledger := ledgerFixture(before, first, 1)
	next, err := targetSnapshot(&resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14), MinClasses: proto.Uint32(3)}, first, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := effectivePolicy(next, nil)
	if err != nil || effective.GetMinClasses() != 3 || effective.GetMinLength() != 14 {
		t.Fatalf("added dimension: %v %v", effective, err)
	}
	drift := proto.CloneOf(first)
	setFileContent(nativeFile(drift, 1), append(bytes.Clone(nativeFile(drift, 1).GetContent()), []byte("minclass = 2\n")...))
	if _, err := targetSnapshot(&resourcev1.PasswordPolicyDesired{MinClasses: proto.Uint32(3)}, drift, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrConflict) {
		t.Fatalf("newly acquired native key drift accepted: %v", err)
	}
}

func TestLocalPolicyCannotBecomeDirectoryHistory(t *testing.T) {
	unguarded := "password required pam_pwhistory.so use_authtok\n"
	if _, err := inspectStacks(map[string][]byte{"common-password": []byte(unguarded)}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unguarded history accepted: %v", err)
	}
	guarded := "password [default=1 ignore=ignore success=ok] pam_localuser.so\n" + unguarded
	if _, err := inspectStacks(map[string][]byte{"common-password": []byte(guarded)}); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectStacks(map[string][]byte{"common-password": []byte(strings.Replace(guarded, "pam_localuser.so", "pam_localuser.so file=/tmp/passwd", 1))}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("alternate local identity database accepted: %v", err)
	}
	before := policyFixture()
	target, err := targetSnapshot(&resourcev1.PasswordPolicyDesired{MinClasses: proto.Uint32(3)}, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(nativeFile(target, 1).GetContent(), []byte("local_users_only\n")) {
		t.Fatal("quality policy lacks local-user boundary")
	}
}

func TestReleasePreservesLaterUnrelatedNativeConfiguration(t *testing.T) {
	before := policyFixture()
	for _, kind := range []agentv1.PasswordNativeFile{1, 2} {
		file := nativeFile(before, kind)
		file.Content = nil
		file.State.Exists = false
		file.State.File = nil
	}
	d := &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}
	applied, err := targetSnapshot(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	current := proto.CloneOf(applied)
	setFileContent(nativeFile(current, 1), append(bytes.Clone(nativeFile(current, 1).GetContent()), []byte("# later administrator note\nmaxrepeat = 4\n")...))
	setFileContent(nativeFile(current, 2), []byte("# later unowned file\nremember = 8\n"))
	ledger := ledgerFixture(before, current, 1)
	released, err := targetSnapshot(d, current, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nativeFile(released, 1).GetContent(), []byte("# later administrator note\nmaxrepeat = 4\n")) || !nativeFile(released, 1).GetState().GetExists() {
		t.Fatal("release deleted unrelated content in an initially absent owned file")
	}
	if !proto.Equal(nativeFile(released, 2), nativeFile(current, 2)) {
		t.Fatal("release touched an unowned later-created file")
	}
}

func TestReleaseRestoresAbsentSecurityMetadata(t *testing.T) {
	before := policyFixture()
	file := nativeFile(before, 1)
	file.Content = nil
	file.State.Exists = false
	file.State.File = nil
	d := &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}
	applied, err := targetSnapshot(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	nativeFile(applied, 1).State.SecurityMetadataSha256 = bytes.Repeat([]byte{7}, 32)
	released, err := targetSnapshot(d, applied, ledgerFixture(before, applied, 1), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if nativeFile(released, 1).GetState().GetExists() || !bytes.Equal(nativeFile(released, 1).GetState().GetSecurityMetadataSha256(), file.GetState().GetSecurityMetadataSha256()) {
		t.Fatal("deleted file retained its former SELinux/security metadata")
	}
}

func TestOwnedProfileEditsCannotBeLaunderedByReconcile(t *testing.T) {
	before := policyFixture()
	before.PasswordPolicy.EnabledFeatures = nil
	d := &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}
	applied, err := targetSnapshot(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	current := proto.CloneOf(applied)
	setFileContent(nativeFile(current, 5), append(bytes.Clone(nativeFile(current, 5).GetContent()), []byte("# administrator note\n")...))
	for _, op := range []resourcev1.ResourceOperation{resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE} {
		if _, err := targetSnapshot(d, current, ledgerFixture(before, applied, 1), op); !errors.Is(err, ErrConflict) {
			t.Fatalf("edited owned profile accepted for %v: %v", op, err)
		}
	}
}

func TestUnsupportedNativeStorageAndLockoutControls(t *testing.T) {
	for _, tc := range []struct {
		kind    agentv1.PasswordNativeFile
		content string
	}{{2, "file = /tmp/history\n"}, {2, "retry = 0\n"}, {3, "dir = /tmp/tallies\n"}, {3, "fail_interval = 0\n"}, {3, "admin_group = wheel\n"}} {
		s := policyFixture()
		setFileContent(nativeFile(s, tc.kind), []byte(tc.content))
		if _, err := effectivePolicy(s, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsupported native control accepted: %q %v", tc.content, err)
		}
	}
}

func TestReleaseRefusesChangedOwnedLowerPrecedenceBeforeEffect(t *testing.T) {
	before := policyFixture()
	original := map[string]string{"minlen": "8"}
	effective, err := effectivePolicy(before, original)
	if err != nil {
		t.Fatal(err)
	}
	before.Observation.GetPasswordPolicy().Effective = effective
	d := &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}
	applied, err := targetSnapshot(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	current := proto.CloneOf(applied)
	current.PasswordPolicy.QualityDropinsSha256 = bytes.Repeat([]byte{9}, 32)
	p := &Provider{config: Config{Platform: &resourcev1.PlatformProduct{OsId: "ubuntu", Version: "24.04"}}, dropins: func() (map[string]string, []byte, error) {
		return map[string]string{"minlen": "9"}, bytes.Repeat([]byte{9}, 32), nil
	}}
	if _, err := p.target(context.Background(), d, current, ledgerFixture(before, applied, 1), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed owned lower-precedence default was restored after effect: %v", err)
	}
}
