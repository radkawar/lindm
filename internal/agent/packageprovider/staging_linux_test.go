//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/dnf"
)

// An installed package lindm adopts (installed by rpm -i or an image build)
// already satisfies its exact row. DNF5 must not stage it: libdnf5 resolved a
// "Reason Change", which the resolver refused as an unsafe action.
func TestDNF5SatisfiedRequestStagesNoTransaction(t *testing.T) {
	identity := &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, NativeName: "proof", Architecture: "x86_64"}
	v1 := &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Rpm{Rpm: &resourcev1.RPMVersion{Version: "1.0", Release: "1"}}}
	v2 := &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Rpm{Rpm: &resourcev1.RPMVersion{Version: "2.0", Release: "1"}}}
	exact := func(version *resourcev1.NativeVersion) *resourcev1.NativePackageDesired {
		return &resourcev1.NativePackageDesired{Package: identity, Presence: resourcev1.Presence_PRESENCE_PRESENT, Version: &resourcev1.NativePackageDesired_Exact{Exact: version}}
	}
	installed := &resourcev1.NativePackageRecord{Package: identity, Version: v1}
	absent := &resourcev1.NativePackageDesired{Package: identity, Presence: resourcev1.Presence_PRESENCE_ABSENT}
	for _, tc := range []struct {
		name      string
		manager   dnf.Kind
		desired   *resourcev1.NativePackageDesired
		installed *resourcev1.NativePackageRecord
		satisfied bool
	}{
		{"installed exact version", dnf.DNF5, exact(v1), installed, true},
		{"absent and not installed", dnf.DNF5, absent, nil, true},
		{"other installed version", dnf.DNF5, exact(v2), installed, false},
		{"not installed", dnf.DNF5, exact(v1), nil, false},
		{"installed but desired absent", dnf.DNF5, absent, installed, false},
		{"DNF4 stages its own satisfied request", dnf.DNF4, exact(v1), installed, false},
	} {
		p := &Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, manager: tc.manager}
		if got := p.dnfSatisfied(tc.desired, tc.installed); got != tc.satisfied {
			t.Errorf("%s: satisfied = %t, want %t", tc.name, got, tc.satisfied)
		}
	}
}

func TestDownloadDeclarationRequiresExactAuthenticatedSizes(t *testing.T) {
	digest := sha256.Sum256([]byte("native archive"))
	line := fmt.Sprintf("'https://repo.example/proof.deb' proof_1.0_amd64.deb 123 SHA256:%x\n", digest)
	declarations, total, err := parseAPTDownloadDeclarations([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if total != 123 || len(declarations) != 1 || !bytes.Equal(declarations["proof_1.0_amd64.deb"].sha256, digest[:]) {
		t.Fatal("native declaration lost exact digest or size")
	}
	for _, bad := range []string{
		"'https://repo.example/proof.deb' ../proof.deb 123 SHA256:" + hex.EncodeToString(digest[:]) + "\n",
		"'https://repo.example/proof.deb' proof.deb 0 SHA256:" + hex.EncodeToString(digest[:]) + "\n",
		"'https://repo.example/proof.deb' proof.deb 123 MD5Sum:abcdef\n",
		line + line,
	} {
		if _, _, err := parseAPTDownloadDeclarations([]byte(bad)); err == nil {
			t.Fatalf("accepted unsafe native declaration %q", bad)
		}
	}
}

// A provenance proof downloads into a scratch directory inside staging while the
// native manager rewrites its caches in staging. The file-size limit must
// follow those caches: below them, apt-get and dnf5 died of SIGXFSZ.
func TestBoundedDownloadLetsTheManagerRewriteItsStagingCaches(t *testing.T) {
	staging := t.TempDir()
	cache := filepath.Join(staging, "cache", "pkgcache.bin")
	downloads := filepath.Join(staging, "provenance")
	for _, directory := range []string{filepath.Dir(cache), downloads} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(cache, make([]byte, 64<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	declarations := map[string]downloadDeclaration{"proof_1.0-1_amd64.deb": {size: 1 << 10}}
	if err := boundedDownload(t.Context(), staging, downloads, declarations, func(ctx context.Context) error {
		if output, err := exec.CommandContext(ctx, "/usr/bin/dd", "if=/dev/zero", "of="+cache, "bs=1024", "count=64").CombinedOutput(); err != nil {
			return fmt.Errorf("rewrite native cache: %w: %s", err, output)
		}
		return os.WriteFile(filepath.Join(downloads, "proof_1.0-1_amd64.deb"), make([]byte, 1<<10), 0o600)
	}); err != nil {
		t.Fatalf("declared download with a native cache rewrite: %v", err)
	}
	if err := boundedDownload(t.Context(), staging, downloads, declarations, func(context.Context) error {
		return os.WriteFile(filepath.Join(downloads, "other_1.0-1_amd64.deb"), []byte("undeclared"), 0o600)
	}); err == nil {
		t.Fatal("undeclared download accepted")
	}
}

func TestDNFSolverCannotChangeAfterDownloadPrecheck(t *testing.T) {
	resolved := &dnfResolved{Version: 1, Entries: []dnfResolvedEntry{{NEVRA: "proof-0:1.0-1.fc44.x86_64", Action: "Install", RepoID: "approved", DownloadSize: 100, FileName: "proof-1.0-1.fc44.x86_64.rpm"}}}
	transaction := &dnfTransaction{Version: "1.0", RPMs: []dnfRPM{{NEVRA: "proof-1.0-1.fc44.x86_64", Action: "Install", RepoID: "@stored_transaction(approved)"}}}
	if err := matchDNFDeclaration(resolved, transaction); err != nil {
		t.Fatal(err)
	}
	transaction.RPMs[0].NEVRA = "proof-1.1-1.fc44.x86_64"
	if err := matchDNFDeclaration(resolved, transaction); err == nil {
		t.Fatal("metadata/solver drift accepted after declared-size precheck")
	}
}
func TestStagingAccountingCountsMetadataAndRejectsSymlinks(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "repomd.xml"), []byte("metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, "packages"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "packages", "proof.rpm"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	used, err := stagingUsage(directory)
	if err != nil {
		t.Fatal(err)
	}
	if used != uint64(len("metadata")+len("payload")) {
		t.Fatalf("observed staging bytes = %d", used)
	}
	if err := checkDownloadBudget(directory, 20, used+19); err == nil {
		t.Fatal("declared package sizes ignored existing metadata footprint")
	}
	if err := os.Symlink("repomd.xml", filepath.Join(directory, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := stagingUsage(directory); err == nil {
		t.Fatal("staging followed foreign link")
	}
}

// zypper refresh records repo_gpgcheck as raw/<alias>/.repo_gpgcheck -> ./true
// (observed). The guard tolerates exactly that marker; the planner requires
// ./true and removes it. Any other symlink, or a gpg-agent socket left in the
// staging keyring (observed on Tumbleweed), still fails the guard.
func TestStagingAllowsOnlyZyppSignatureMarker(t *testing.T) {
	directory := t.TempDir()
	raw := filepath.Join(directory, "cache", "raw", "approved")
	if err := os.MkdirAll(raw, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("./true", filepath.Join(raw, ".repo_gpgcheck")); err != nil {
		t.Fatal(err)
	}
	if _, err := stagingUsage(directory); err != nil {
		t.Fatalf("zypper's signature-mode marker failed the guard: %v", err)
	}
	if err := consumeZyppGPGCheckMarker(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(raw, ".repo_gpgcheck")); !os.IsNotExist(err) {
		t.Fatal("consumed marker remained in the committed cache")
	}
	if err := consumeZyppGPGCheckMarker(raw); err == nil {
		t.Fatal("refresh without a recorded signature check was accepted")
	}
	if err := os.Symlink("./false", filepath.Join(raw, ".repo_gpgcheck")); err != nil {
		t.Fatal(err)
	}
	if err := consumeZyppGPGCheckMarker(raw); err == nil {
		t.Fatal("unenforced repository signature mode was accepted")
	}
	if err := os.Remove(filepath.Join(raw, ".repo_gpgcheck")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../escape", filepath.Join(raw, ".repo_gpgcheck")); err != nil {
		t.Fatal(err)
	}
	if _, err := stagingUsage(directory); err == nil {
		t.Fatal("marker name with a foreign target passed the guard")
	}
}

func TestStagingRejectsSocketAndNamesIt(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "keyring"), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(directory, "keyring", "S.gpg-agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if _, err := stagingUsage(directory); err == nil || !strings.Contains(err.Error(), "keyring/S.gpg-agent") {
		t.Fatalf("socket in staging = %v", err)
	}
}
func TestAPTPredependencyConfigurationOrderIsRetained(t *testing.T) {
	data := []byte("Inst predep (1.0-1 approved [amd64])\nConf predep (1.0-1 approved [amd64])\nInst dependency (2.0-1 approved [amd64])\nInst proof (3.0-1 approved [amd64])\nConf dependency (2.0-1 approved [amd64])\nConf proof (3.0-1 approved [amd64])\n")
	steps, err := parseAPTSteps(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 6 || steps[0].operation != "--unpack" || steps[1].operation != "--configure" || steps[1].name != "predep" || steps[2].operation != "--unpack" {
		t.Fatalf("predependency barrier lost: %#v", steps)
	}
	if _, err := parseAPTSteps([]byte("Conf proof (unknown shape)\n")); err == nil {
		t.Fatal("unrecognized configure step accepted")
	}
}
func TestPreparationBaselineAllowsExecutorRestartButRejectsNativeDrift(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root preparation custody")
	}
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	digest := sha256.Sum256([]byte("complete absent database"))
	observation := &resourcev1.ResourceObservation{Ref: d.GetRef(), Metadata: &resourcev1.ObservationMetadata{BootId: "22222222-2222-4222-8222-222222222222", ExecutorIncarnation: "33333333-3333-4333-8333-333333333333", ObservedAt: timestamppb.Now(), Backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_APT, NativeVersion: "2.7.14", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "amd64"}}, NativeRevision: digest[:], ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}, Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{Package: d.GetNativePackage().GetPackage(), DatabaseRevisionSha256: digest[:]}}}
	directory := t.TempDir()
	if err := bindPreparationBaseline(directory, observation, nil); err != nil {
		t.Fatal(err)
	}
	restarted := proto.CloneOf(observation)
	restarted.Metadata.ExecutorIncarnation = "44444444-4444-4444-8444-444444444444"
	restarted.Metadata.ObservedAt = timestamppb.New(time.Now().Add(time.Second))
	if err := bindPreparationBaseline(directory, restarted, nil); err != nil {
		t.Fatalf("same native state after executor restart: %v", err)
	}
	restarted.GetNativePackage().PinContents = []byte("external change")
	if err := bindPreparationBaseline(directory, restarted, nil); err == nil {
		t.Fatal("preparation rebound native baseline after drift")
	}
	rebooted := proto.CloneOf(observation)
	rebooted.Metadata.BootId = "55555555-5555-4555-8555-555555555555"
	if err := bindPreparationBaseline(directory, rebooted, nil); err == nil {
		t.Fatal("preparation survived changed native boot")
	}
}
func TestCancellationNeedsNoNativePlatformOrSource(t *testing.T) {
	called := false
	config := Config{ActionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", NativeStageCancel: func(_ context.Context, id string) error {
		called = true
		if id != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
			t.Fatal("wrong action cleanup")
		}
		return nil
	}}
	if err := CancelPreparation(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expired staging not canceled")
	}
	config.ActionID = "../foreign"
	called = false
	if err := CancelPreparation(context.Background(), config); err == nil || called {
		t.Fatal("cleanup accepted noncanonical action path")
	}
}
func TestPendingOwnershipCannotAuthorizeRelease(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	ledger := &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN}
	if _, _, _, err := releaseTarget(d, nil, ledger); err == nil {
		t.Fatal("uncertain native installation produced release inverse")
	}
}
func TestProjectedVersionlockIsBoundToOriginalAndCandidate(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	pin := &resourcev1.FileIdentity{Path: "/etc/dnf/versionlock.toml", Inode: 123, Mode: 0600, Sha256: make([]byte, 32)}
	contents := []byte("version = \"1.0\"\n")
	digest := sha256.Sum256(contents)
	binding := sha256.Sum256([]byte("signed desired"))
	databaseDigest := sha256.Sum256([]byte("native database"))
	plan := &resourcev1.ResourcePlan{Ref: d.GetRef(), DesiredSha256: binding[:], Before: &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{PinFile: pin}}}, Plan: &resourcev1.ResourcePlan_NativePackage{NativePackage: &resourcev1.NativePackagePlan{NativeDatabaseRevision: databaseDigest[:], NativeLockIdentity: "rpm", PinContents: contents}}}
	manifest := &resourcev1.PackageTransactionManifest{NativeDatabaseRevision: databaseDigest[:], NativeLockIdentity: "rpm", AffectedResources: []*resourcev1.ResourceRef{d.GetRef()}, AffectedDesiredSha256: [][]byte{binding[:]}, OriginalPin: proto.CloneOf(pin), CandidatePinSha256: digest[:]}
	if err := ValidateNativePlan(plan, manifest); err != nil {
		t.Fatal(err)
	}
	manifest.OriginalPin.Inode++
	if err := ValidateNativePlan(plan, manifest); err == nil {
		t.Fatal("projected solver ignored original file identity")
	}
	manifest.OriginalPin = proto.CloneOf(pin)
	manifest.CandidatePinSha256 = make([]byte, 32)
	if err := ValidateNativePlan(plan, manifest); err == nil {
		t.Fatal("projected solver ignored exact candidate pin")
	}
	if err := ValidateStagingProjection(nil); err == nil {
		t.Fatal("nil projection request accepted")
	}
	if err := ValidateStagingProjection(&agentv1.NativePackageTransactionRequest{CandidatePinContents: contents}); err == nil {
		t.Fatal("candidate projection without original accepted")
	}
}
func TestNativePostdiffDetectsUnmanifestedRPMReinstallation(t *testing.T) {
	first := []byte("proof\t0\t1.0\t1.fc44\tx86_64\t100\t100\t1111111111111111111111111111111111111111\n")
	second := bytes.ReplaceAll(first, []byte("\t100"), []byte("\t101"))
	before, err := parseDatabase(first, resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseDatabase(second, resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	if err != nil {
		t.Fatal(err)
	}
	if err := transactionMatchesDatabase(&resourcev1.PackageTransactionManifest{}, before, after); err == nil {
		t.Fatal("same-version native reinstall hidden by version-only postdiff")
	}
}
func TestPackageEffectSummaryUsesCompleteNativeManifest(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	digest := sha256.Sum256([]byte("signed package plan"))
	plan := &resourcev1.ResourcePlan{Ref: d.GetRef(), DesiredSha256: digest[:], Plan: &resourcev1.ResourcePlan_NativePackage{NativePackage: &resourcev1.NativePackagePlan{NativeDatabaseRevision: digest[:], NativeLockIdentity: "dpkg"}}}
	manifest := &resourcev1.PackageTransactionManifest{NativeDatabaseRevision: digest[:], NativeLockIdentity: "dpkg", AffectedResources: []*resourcev1.ResourceRef{d.GetRef()}, AffectedDesiredSha256: [][]byte{digest[:]}}
	if err := ValidateNativePlan(plan, manifest); err != nil {
		t.Fatalf("idempotent empty transaction: %v", err)
	}
	plan.GetNativePackage().ChangePackages = true
	if err := ValidateNativePlan(plan, manifest); err == nil {
		t.Fatal("empty transaction claimed a package effect")
	}
	plan.GetNativePackage().ChangePackages = false
	plan.GetNativePackage().ChangePin = true
	if err := ValidateNativePlan(plan, manifest); err != nil {
		t.Fatalf("pin-only transaction incorrectly requires a package effect: %v", err)
	}
	for _, operation := range []resourcev1.PackageTransactionOperation{
		resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_INSTALL,
		resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_UPGRADE,
		resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_REMOVE_OWNED,
	} {
		// Even identical before/after versions can represent a native effect;
		// the complete solver operation, not a version comparison, is authority.
		manifest.Entries = []*resourcev1.PackageTransactionEntry{{Operation: operation, Before: debVersion("1.0-1"), After: debVersion("1.0-1")}}
		plan.GetNativePackage().ChangePackages = false
		if err := ValidateNativePlan(plan, manifest); err == nil {
			t.Fatalf("operation %s hidden by false effect flag", operation)
		}
		plan.GetNativePackage().ChangePackages = true
		if err := ValidateNativePlan(plan, manifest); err != nil {
			t.Fatalf("operation %s effect flag: %v", operation, err)
		}
	}
	manifest.Entries = append(manifest.Entries, &resourcev1.PackageTransactionEntry{Operation: resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_APPROVED_DOWNGRADE})
	if err := ValidateNativePlan(plan, manifest); err == nil {
		t.Fatal("operation scan stopped after first mutating entry")
	}
	manifest.Entries = []*resourcev1.PackageTransactionEntry{nil}
	if err := ValidateNativePlan(plan, manifest); err == nil {
		t.Fatal("missing native operation accepted")
	}
}

// zypper's --disable-repositories also disables the command-line RPM repository
// (exit 104 on Tumbleweed); commits must instead name an empty private
// repository directory, and refuse one that is not empty.
func TestZypperCommitKeepsCommandLineRPMRepository(t *testing.T) {
	directory := t.TempDir()
	desired := &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{NativeName: "fixture", Architecture: "x86_64"}, Presence: resourcev1.Presence_PRESENCE_PRESENT}
	for _, preview := range []bool{true, false} {
		args := zypperCommitArgs(directory, desired, desired.GetPackage(), nil, preview)
		if slices.Contains(args, "--disable-repositories") {
			t.Fatalf("commit disables the command-line repository: %q", args)
		}
		if i := slices.Index(args, "--reposd-dir"); i < 0 || args[i+1] != filepath.Join(directory, zypperCommitRepos) {
			t.Fatalf("commit does not hide configured repositories: %q", args)
		}
	}
	if err := emptyZypperCommitRepos(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, zypperCommitRepos, "staging.repo"), []byte("[staging]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := emptyZypperCommitRepos(directory); err == nil {
		t.Fatal("non-empty commit repository directory admitted")
	}
}
