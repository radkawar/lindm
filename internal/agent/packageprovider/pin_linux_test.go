//go:build linux

package packageprovider

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/dnf"
)

func desiredFixture(ecosystem resourcev1.PackageEcosystem) *resourcev1.ResourceDesiredState {
	name, arch, key := "proof", "amd64", "deb/proof/amd64"
	version := debVersion("1:2.0-1")
	repository := "apt/11111111-1111-4111-8111-111111111111"
	if ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		arch = "x86_64"
		key = "rpm/proof/x86_64"
		repository = "rpm/11111111-1111-4111-8111-111111111111"
		version = &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Rpm{Rpm: &resourcev1.RPMVersion{Epoch: 1, Version: "2.0", Release: "1.fc44"}}}
	}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: key}, State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{Ecosystem: ecosystem, NativeName: name, Architecture: arch}, Presence: resourcev1.Presence_PRESENCE_PRESENT, Version: &resourcev1.NativePackageDesired_Exact{Exact: version}, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: repository}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA}}}
}
func TestExactAPTNativePinIsPersistentAndNeverDowngradingPriority(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	pin := aptPin(d.GetNativePackage())
	if !bytes.Contains(pin, []byte("Package: proof:amd64\n")) || !bytes.Contains(pin, []byte("Pin: version 1:2.0-1\n")) || !bytes.Contains(pin, []byte("Pin-Priority: 1000\n")) {
		t.Fatalf("native pin = %s", pin)
	}
	if !pinMatches(resourcev1.Backend_BACKEND_APT, d.GetRef(), d.GetNativePackage(), pin) {
		t.Fatal("rendered exact pin does not converge")
	}
	if pinMatches(resourcev1.Backend_BACKEND_APT, d.GetRef(), d.GetNativePackage(), bytes.Replace(pin, []byte("2.0"), []byte("3.0"), 1)) {
		t.Fatal("pin drift hidden")
	}
	d.GetNativePackage().Version = &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}
	if len(aptPin(d.GetNativePackage())) != 0 {
		t.Fatal("any version installed an unintended pin")
	}
}
func TestDNFNativePinPreservesUnrelatedOwnershipAndIsIdempotent(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	baseline := []byte("version = '1.0'\n[[packages]]\nname = 'bash'\n[[packages.conditions]]\nkey = 'evr'\ncomparator = '='\nvalue = '0:5.3-1.fc44'\n")
	pin, err := renderDNFPin(d.GetRef(), d.GetNativePackage(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := dnf.ParseVersionlock(pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Packages) != 2 || parsed.Packages[0].Name != "bash" || parsed.Packages[0].Conditions[0].Value != "0:5.3-1.fc44" {
		t.Fatal("unrelated native versionlock lost")
	}
	if !pinMatches(resourcev1.Backend_BACKEND_DNF5, d.GetRef(), d.GetNativePackage(), pin) {
		t.Fatal("exact native versionlock not effective")
	}
	again, err := renderDNFPin(d.GetRef(), d.GetNativePackage(), pin)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pin, again) {
		t.Fatal("idempotent pin rewrite")
	}
	drift := bytes.Replace(pin, []byte("1:2.0-1.fc44"), []byte("1:2.1-1.fc44"), 1)
	if pinMatches(resourcev1.Backend_BACKEND_DNF5, d.GetRef(), d.GetNativePackage(), drift) {
		t.Fatal("external versionlock drift hidden")
	}
	for _, name := range []string{"proof", "*", "pro*"} {
		overlap := bytes.Replace(baseline, []byte("'bash'"), []byte("'"+name+"'"), 1)
		if _, err := renderDNFPin(d.GetRef(), d.GetNativePackage(), overlap); err == nil {
			t.Fatalf("acquired overlapping native pin %s", name)
		}
	}
}
func TestSharedDNFVersionlockOnlyClaimsMatchingPackage(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	file := &resourcev1.FileIdentity{Path: "/etc/dnf/versionlock.toml"}
	observe := func(contents string) *resourcev1.NativePackageObservation {
		return &resourcev1.NativePackageObservation{Package: d.GetNativePackage().GetPackage(), PinFile: file, PinContents: []byte(contents)}
	}
	other := "version = '1.0'\n[[packages]]\nname = 'bash'\ncomment = 'lindm:rpm/bash/x86_64'\n[[packages.conditions]]\nkey = 'evr'\ncomparator = '='\nvalue = '0:5.3-1.fc44'\n"
	if pinClaimsPackage(d.GetRef(), observe(other)) {
		t.Fatal("another package's versionlock entry required adoption")
	}
	for _, name := range []string{"proof", "pro*"} {
		if !pinClaimsPackage(d.GetRef(), observe(strings.Replace(other, "'bash'", "'"+name+"'", 1))) {
			t.Fatalf("existing %s versionlock entry acquired without adoption", name)
		}
	}
	if !pinClaimsPackage(d.GetRef(), observe("not toml")) {
		t.Fatal("unreadable versionlock acquired without adoption")
	}
	deb := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	if !pinClaimsPackage(deb.GetRef(), &resourcev1.NativePackageObservation{Package: deb.GetNativePackage().GetPackage(), PinFile: file}) {
		t.Fatal("per-package APT pin acquired without adoption")
	}
}

// The DNF4 plugin list is shared, line-oriented and partly operator-written:
// lindm's exact lock must be a marked NEVRA line the native plugin enforces,
// unrelated lines must survive byte for byte, and overlap must be refused.
func TestDNF4VersionlockListPreservesUnrelatedLinesAndRefusesOverlap(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	p := &Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, manager: dnf.DNF4, versionlock: true}
	baseline := []byte("\n# Added lock on Mon Oct  5 05:03:00 2026\nbash-0:5.1.8-9.el9.*\n!kernel-0:5.14.0-1.el9.x86_64\n")
	pin, err := p.renderPin(d.GetRef(), d.GetNativePackage(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	want := string(baseline) + "# lindm:rpm/proof/x86_64\nproof-1:2.0-1.fc44.x86_64\n"
	if string(pin) != want {
		t.Fatalf("native list = %q", pin)
	}
	if !pinMatches(resourcev1.Backend_BACKEND_DNF4, d.GetRef(), d.GetNativePackage(), pin) {
		t.Fatal("exact DNF4 lock not converged")
	}
	if again, err := p.renderPin(d.GetRef(), d.GetNativePackage(), pin); err != nil || !bytes.Equal(again, pin) {
		t.Fatal("DNF4 lock rewrite is not idempotent")
	}
	if pinMatches(resourcev1.Backend_BACKEND_DNF4, d.GetRef(), d.GetNativePackage(), bytes.Replace(pin, []byte("2.0-1"), []byte("2.1-1"), 1)) {
		t.Fatal("external DNF4 lock drift hidden")
	}
	// An operator's native delete drops comments; the remaining unmarked
	// entry is then an external pin, never silently adopted or overwritten.
	unmarked := []byte("bash-0:5.1.8-9.el9.*\nproof-1:2.0-1.fc44.x86_64\n")
	for _, overlap := range [][]byte{unmarked, []byte("proof\n"), []byte("pro*\n"), []byte("!proof-1:3.0-1.fc44.*\n"), []byte("*-1:2.0-1.fc44.x86_64\n")} {
		if _, err := p.renderPin(d.GetRef(), d.GetNativePackage(), overlap); err == nil {
			t.Fatalf("acquired overlapping DNF4 lock %q", overlap)
		}
		if !dnf.VersionlockClaims(dnf.VersionlockListPath, overlap, d.GetRef().GetCanonicalKey(), "proof") {
			t.Fatalf("overlapping DNF4 lock %q acquired without adoption", overlap)
		}
	}
	if dnf.VersionlockClaims(dnf.VersionlockListPath, []byte("proof-tools-0:1.0-1.el9.*\n# lindm:rpm/bash/x86_64\nbash-0:5.1.8-9.el9.x86_64\n"), d.GetRef().GetCanonicalKey(), "proof") {
		t.Fatal("another package's DNF4 lock required adoption")
	}
	// A marker whose entry was replaced is orphaned; the following foreign
	// line is preserved, not removed as lindm's.
	orphan := []byte("# lindm:rpm/proof/x86_64\nbash-0:5.1.8-9.el9.*\n")
	d.GetNativePackage().Version = &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}
	released, err := p.renderPin(d.GetRef(), d.GetNativePackage(), orphan)
	if err != nil || string(released) != "bash-0:5.1.8-9.el9.*\n" {
		t.Fatalf("orphaned marker release = %q, %v", released, err)
	}
	if pinMatches(resourcev1.Backend_BACKEND_DNF4, d.GetRef(), d.GetNativePackage(), orphan) {
		t.Fatal("orphaned DNF4 marker reported converged")
	}
	if !pinMatches(resourcev1.Backend_BACKEND_DNF4, d.GetRef(), d.GetNativePackage(), released) {
		t.Fatal("released DNF4 lock not converged")
	}
	if string(pinProjection(resourcev1.Backend_BACKEND_DNF4, nil)) != "\n" {
		t.Fatal("empty DNF4 projection is not a valid native list")
	}
}

// Without the enabled native plugin the list has no native effect, so an
// exact DNF4 version cannot be promised as a persistent pin.
func TestDNF4ExactVersionRequiresEffectiveVersionlock(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	p := &Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, manager: dnf.DNF4}
	if _, err := p.renderPin(d.GetRef(), d.GetNativePackage(), nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("exact pin without native versionlock = %v", err)
	}
	d.GetNativePackage().Version = &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}
	if pin, err := p.renderPin(d.GetRef(), d.GetNativePackage(), nil); err != nil || len(pin) != 0 {
		t.Fatalf("any-version DNF4 pin = %q, %v", pin, err)
	}
}
func TestPinObservationRefusesSymlinksAndAtomicReplacementPreservesBaseline(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root native pin custody")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "pin")
	if err := atomicFile(path, []byte("baseline\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, contents, err := readPin(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicFile(path, []byte("managed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	after, _, err := readPin(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.GetInode() == after.GetInode() || bytes.Equal(before.GetSha256(), after.GetSha256()) {
		t.Fatal("pin replacement did not produce a distinct native identity")
	}
	if err := atomicFile(path, contents, os.FileMode(before.GetMode())); err != nil {
		t.Fatal(err)
	}
	_, restored, err := readPin(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, restored) {
		t.Fatal("pin baseline not restored")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPin(link); err == nil {
		t.Fatal("symlink pin acquired")
	}
}
func TestReleaseOnlyRestoresRecordedDimensions(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	digest := sha256.Sum256([]byte("authenticated fixture installation"))
	record := &resourcev1.NativePackageRecord{Package: proto.CloneOf(d.GetNativePackage().GetPackage()), Version: proto.CloneOf(d.GetNativePackage().GetExact()), Source: proto.CloneOf(d.GetNativePackage().GetRepository()), SignerSha256: digest[:], MetadataRevisionSha256: digest[:], NativeIdentitySha256: digest[:], ProvenanceKnown: true}
	current := &resourcev1.NativePackageObservation{Package: record.Package, Installed: true, Record: record, DatabaseRevisionSha256: digest[:], PinContents: aptPin(d.GetNativePackage())}
	observation := &resourcev1.ResourceObservation{Ref: d.GetRef(), Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: current}}
	baseline := &resourcev1.ResourceObservation{Ref: d.GetRef(), Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{Package: record.Package, DatabaseRevisionSha256: digest[:]}}}
	ledger := &agentv1.ResourceOwnershipLedger{Revision: 2, State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, Owner: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}}, Baseline: &agentv1.ResourceOwnershipSnapshot{Observation: baseline}, LastApplied: &agentv1.ResourceOwnershipSnapshot{Observation: proto.CloneOf(observation)}, OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PRESENCE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_VERSION, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PIN}}
	effective, pin, inverse, err := releaseTarget(d, observation, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if effective.GetPresence() != resourcev1.Presence_PRESENCE_ABSENT || len(pin) != 0 || len(inverse.GetInverseSha256()) != 32 {
		t.Fatal("release did not bind original absence and pin removal")
	}
	d.GetNativePackage().Removal = resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_RETAIN_INSTALLATION
	effective, pin, _, err = releaseTarget(d, observation, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if effective.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT || len(pin) != 0 {
		t.Fatal("retain-installation release uninstalled package or retained owned pin")
	}
	changed := proto.CloneOf(observation)
	changed.GetNativePackage().Record.Version = debVersion("9.0-1")
	if _, _, _, err := releaseTarget(d, changed, ledger); !errors.Is(err, ErrConflict) {
		t.Fatalf("external native version overwrite: %v", err)
	}
	changed = proto.CloneOf(observation)
	changed.GetNativePackage().PinContents = []byte("external pin")
	if _, _, _, err := releaseTarget(d, changed, ledger); !errors.Is(err, ErrConflict) {
		t.Fatalf("external pin overwrite: %v", err)
	}
	ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN
	if _, _, _, err := releaseTarget(d, observation, ledger); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("uncertain install replayed by release: %v", err)
	}
}
func TestAcquisitionDoesNotGuessInstalledProvenance(t *testing.T) {
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	p := &Provider{config: Config{Ownership: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION}}}}
	before := &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{Package: d.GetNativePackage().GetPackage(), Installed: true, Record: &resourcev1.NativePackageRecord{Package: d.GetNativePackage().GetPackage(), Version: d.GetNativePackage().GetExact()}}}}
	if err := p.acquisitionAllowed(before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err == nil {
		t.Fatal("unknown source acquired from desired repository")
	}
	before.GetNativePackage().Installed = false
	before.GetNativePackage().Record = nil
	if err := p.acquisitionAllowed(before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err != nil {
		t.Fatal(err)
	}
	if err := p.acquisitionAllowed(before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); err == nil {
		t.Fatal("release invented baseline")
	}
}
