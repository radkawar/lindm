//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/dnf"
	"lindm/internal/resource"
)

// adoptionFixture is an installed package lindm did not install, its proof and
// the observation of it.
func adoptionFixture(t *testing.T) (*resourcev1.ResourceDesiredState, *resourcev1.ResourceObservation, *resourcev1.InstalledProvenanceProof) {
	t.Helper()
	d := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	identity := sha256.Sum256([]byte("installed dpkg control identity"))
	signer := sha256.Sum256([]byte("approved archive key"))
	metadata := sha256.Sum256([]byte("approved metadata revision"))
	artifact := sha256.Sum256([]byte("approved archive"))
	record := &resourcev1.NativePackageRecord{Package: proto.CloneOf(d.GetNativePackage().GetPackage()), Version: proto.CloneOf(d.GetNativePackage().GetExact()), NativeIdentitySha256: identity[:]}
	before := &resourcev1.ResourceObservation{
		Ref: proto.CloneOf(d.GetRef()),
		Metadata: &resourcev1.ObservationMetadata{BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), ObservedAt: timestamppb.Now(),
			Backend:        &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_APT, NativeVersion: "apt 2.7.14", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}},
			NativeRevision: identity[:], ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK},
		Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{Package: record.GetPackage(), Installed: true, Record: record, DatabaseRevisionSha256: identity[:]}},
	}
	proof := &resourcev1.InstalledProvenanceProof{Package: proto.CloneOf(record.GetPackage()), Version: proto.CloneOf(record.GetVersion()), Source: proto.CloneOf(d.GetNativePackage().GetRepository()), SignerSha256: signer[:], MetadataRevisionSha256: metadata[:],
		Artifact: &resourcev1.ArtifactRef{Sha256: artifact[:], SizeBytes: 4096, ArtifactId: uuid.NewSHA1(uuid.NameSpaceOID, artifact[:]).String()},
		Method:   resourcev1.InstalledProvenanceMethod_INSTALLED_PROVENANCE_METHOD_DPKG_CONTROL, NativeIdentitySha256: identity[:]}
	if err := validateMessage(proof); err != nil {
		t.Fatal(err)
	}
	return d, before, proof
}

func ownershipMode(mode resourcev1.OwnershipMode) *Provider {
	return &Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, config: Config{
		Platform:  &resourcev1.PlatformProduct{OsId: "ubuntu", Version: "24.04"},
		Ownership: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Mode: mode}},
	}}
}

func TestInstalledProvenanceProofBindsTheExactInstallation(t *testing.T) {
	d, before, proof := adoptionFixture(t)
	repository := d.GetNativePackage().GetRepository()
	for name, mutate := range map[string]func(*resourcev1.NativePackageRecord, *resourcev1.InstalledProvenanceProof, **resourcev1.ResourceRef){
		"reinstalled": func(r *resourcev1.NativePackageRecord, _ *resourcev1.InstalledProvenanceProof, _ **resourcev1.ResourceRef) {
			r.NativeIdentitySha256 = make([]byte, 32)
		},
		"other version": func(r *resourcev1.NativePackageRecord, _ *resourcev1.InstalledProvenanceProof, _ **resourcev1.ResourceRef) {
			r.Version = debVersion("1:2.0-2")
		},
		"other package": func(r *resourcev1.NativePackageRecord, _ *resourcev1.InstalledProvenanceProof, _ **resourcev1.ResourceRef) {
			r.Package.NativeName = "other"
		},
		"other repository": func(_ *resourcev1.NativePackageRecord, p *resourcev1.InstalledProvenanceProof, _ **resourcev1.ResourceRef) {
			p.Source.CanonicalKey = "apt/22222222-2222-4222-8222-222222222222"
		},
		"desired elsewhere": func(_ *resourcev1.NativePackageRecord, _ *resourcev1.InstalledProvenanceProof, r **resourcev1.ResourceRef) {
			*r = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "apt/33333333-3333-4333-8333-333333333333"}
		},
		"no proof": func(_ *resourcev1.NativePackageRecord, p *resourcev1.InstalledProvenanceProof, _ **resourcev1.ResourceRef) {
			proto.Reset(p)
		},
	} {
		record, other, desired := proto.CloneOf(before.GetNativePackage().GetRecord()), proto.CloneOf(proof), proto.CloneOf(repository)
		mutate(record, other, &desired)
		if name == "no proof" {
			other = nil
		}
		if applyInstalledProvenance(record, other, desired) || record.GetProvenanceKnown() || record.GetSource() != nil {
			t.Fatalf("%s: proof applied to another installation", name)
		}
	}
	record := proto.CloneOf(before.GetNativePackage().GetRecord())
	if !applyInstalledProvenance(record, proof, repository) || !provenFrom(record, proof) || !proto.Equal(record.GetSource(), repository) {
		t.Fatalf("proof not recorded: %v", record)
	}
	if err := validateMessage(record); err != nil {
		t.Fatalf("proven record: %v", err)
	}
	if applyInstalledProvenance(record, proof, repository) {
		t.Fatal("proof replaced known provenance")
	}
}

// Provenance decides the refusal: unproven stays a precondition no approval can
// lift, proven without approval links to approved adoption, proven with
// approval acquires.
func TestAcquisitionOfInstalledPackageFollowsItsProof(t *testing.T) {
	d, before, proof := adoptionFixture(t)
	for _, mode := range []resourcev1.OwnershipMode{resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION} {
		err := ownershipMode(mode).acquisitionAllowed(before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
		if !errors.Is(err, ErrConflict) || errors.Is(err, ErrAdoptionRequired) || admissiondetail.Of(err) != "existing_package_unverified" {
			t.Fatalf("%s: unproven installation = %v", mode, err)
		}
	}
	proven := proto.CloneOf(before)
	applyInstalledProvenance(proven.GetNativePackage().GetRecord(), proof, d.GetNativePackage().GetRepository())
	err := ownershipMode(resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY).acquisitionAllowed(proven, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if !errors.Is(err, ErrAdoptionRequired) || admissiondetail.Of(err) != "existing_package" {
		t.Fatalf("proven installation without approval = %v", err)
	}
	if err := ownershipMode(resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION).acquisitionAllowed(proven, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err != nil {
		t.Fatalf("approved adoption of a proven installation: %v", err)
	}
}

func TestOnlyUnownedPresenceOfAnUnknownInstallationIsProven(t *testing.T) {
	d, before, _ := adoptionFixture(t)
	p := ownershipMode(resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION)
	reconcile := resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE
	if !p.needsInstalledProvenance(d, before, nil, reconcile) {
		t.Fatal("unowned installation acquired without a proof")
	}
	released := &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED}
	if !p.needsInstalledProvenance(d, before, released, reconcile) {
		t.Fatal("released row reacquired without a proof")
	}
	if p.needsInstalledProvenance(d, before, &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED}, reconcile) {
		t.Fatal("owned row proven again")
	}
	if p.needsInstalledProvenance(d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE) {
		t.Fatal("release proved an installation")
	}
	absent := proto.CloneOf(d)
	absent.GetNativePackage().Presence = resourcev1.Presence_PRESENCE_ABSENT
	if p.needsInstalledProvenance(absent, before, nil, reconcile) {
		t.Fatal("removal of a package lindm did not install offered through adoption")
	}
	known := proto.CloneOf(before)
	known.GetNativePackage().GetRecord().ProvenanceKnown = true
	if p.needsInstalledProvenance(d, known, nil, reconcile) {
		t.Fatal("known provenance proven again")
	}
	for name, other := range map[string]*Provider{
		"dnf4":   {ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, manager: dnf.DNF4, config: Config{Platform: &resourcev1.PlatformProduct{OsId: "rocky", Version: "9.6"}}},
		"pacman": {ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM, config: Config{Platform: &resourcev1.PlatformProduct{OsId: "arch", Version: ""}}},
	} {
		if other.canProveInstalledProvenance() {
			t.Fatalf("%s claims an installed-provenance proof", name)
		}
	}
	if !(&Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, manager: dnf.DNF5, config: Config{Platform: &resourcev1.PlatformProduct{OsId: "fedora", Version: "44"}}}).canProveInstalledProvenance() {
		t.Fatal("DNF5 cannot prove installed provenance")
	}
}

func TestProofIsBoundToThePlanBaseline(t *testing.T) {
	d, before, proof := adoptionFixture(t)
	digest := sha256.Sum256([]byte("signed package plan"))
	proven := proto.CloneOf(before)
	applyInstalledProvenance(proven.GetNativePackage().GetRecord(), proof, d.GetNativePackage().GetRepository())
	plan := &resourcev1.ResourcePlan{Ref: d.GetRef(), Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, DesiredSha256: digest[:], Before: proven, Plan: &resourcev1.ResourcePlan_NativePackage{NativePackage: &resourcev1.NativePackagePlan{NativeDatabaseRevision: digest[:], NativeLockIdentity: "dpkg", ChangePin: true}}}
	manifest := &resourcev1.PackageTransactionManifest{NativeDatabaseRevision: digest[:], NativeLockIdentity: "dpkg", AffectedResources: []*resourcev1.ResourceRef{d.GetRef()}, AffectedDesiredSha256: [][]byte{digest[:]}, InstalledProvenance: proof}
	if err := ValidateNativePlan(plan, manifest); err != nil {
		t.Fatalf("proven adoption plan: %v", err)
	}
	plan.Before = before
	if err := ValidateNativePlan(plan, manifest); !errors.Is(err, ErrConflict) {
		t.Fatalf("proof without its proven baseline = %v", err)
	}
	plan.Before = proven
	plan.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
	if err := ValidateNativePlan(plan, manifest); !errors.Is(err, ErrConflict) {
		t.Fatalf("release carried an acquisition proof = %v", err)
	}
}

// adoptionPlan is a complete signed-plan shape for a pin-only adoption plan.
func adoptionPlan(t *testing.T, d *resourcev1.ResourceDesiredState, before *resourcev1.ResourceObservation, operation resourcev1.ResourceOperation, pin []byte, inverse *resourcev1.OwnershipInverseBinding) *resourcev1.ResourcePlan {
	t.Helper()
	desiredDigest, err := resource.DesiredDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	observationDigest, err := resource.ObservationDigest(before)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := resource.Claims(d)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("adoption plan fixture"))
	artifact := &resourcev1.ArtifactRef{Sha256: digest[:], SizeBytes: 1, ArtifactId: uuid.NewSHA1(uuid.NameSpaceOID, digest[:]).String()}
	plan := &resourcev1.ResourcePlan{
		Ref: proto.CloneOf(d.GetRef()), Operation: operation, DesiredSha256: desiredDigest[:], ObservationSha256: observationDigest[:],
		Backend: proto.CloneOf(before.GetMetadata().GetBackend()), Claims: claims, OwnershipRevisionSha256: digest[:], Before: proto.CloneOf(before),
		Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL,
			RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED, PrerequisiteManifests: []*resourcev1.ArtifactRef{artifact}},
		Plan: &resourcev1.ResourcePlan_NativePackage{NativePackage: &resourcev1.NativePackagePlan{Desired: proto.CloneOf(d.GetNativePackage()), TransactionManifest: artifact,
			NativeDatabaseRevision: digest[:], NativeLockIdentity: "dpkg:/var/lib/dpkg/lock-frontend:/var/lib/dpkg/lock", Inverse: inverse, PinContents: pin, PinMode: 0o644, ChangePin: true}},
	}
	if inverse != nil {
		plan.OwnershipRevisionSha256 = bytes.Clone(inverse.GetLedgerRevisionSha256())
	}
	if err := resource.ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func adoptedVerification(t *testing.T, plan *resourcev1.ResourcePlan, after *resourcev1.ResourceObservation, ledger *agentv1.ResourceOwnershipLedger) *resourcev1.NativePackageChecks {
	t.Helper()
	verification, err := packageVerification(plan, after, ledger, &resourcev1.PackageTransactionManifest{}, true)
	if err != nil {
		t.Fatal(err)
	}
	return verification.GetNativePackage()
}

func TestAdoptedPackageConvergesOnlyFromItsApprovedSource(t *testing.T) {
	d, before, proof := adoptionFixture(t)
	pin := aptPin(d.GetNativePackage())
	plan := adoptionPlan(t, d, before, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, pin, nil)
	after := proto.CloneOf(before)
	after.GetNativePackage().PinContents = pin
	if checks := adoptedVerification(t, plan, after, nil); checks.GetConverged() || checks.GetApprovedSourceMatches() {
		t.Fatal("unproven installation converged")
	}
	applyInstalledProvenance(after.GetNativePackage().GetRecord(), proof, d.GetNativePackage().GetRepository())
	if checks := adoptedVerification(t, plan, after, nil); !checks.GetConverged() || !checks.GetApprovedSourceMatches() {
		t.Fatalf("adopted package with its pin did not converge: %v", checks)
	}
	after.GetNativePackage().PinContents = nil
	if checks := adoptedVerification(t, plan, after, nil); checks.GetConverged() {
		t.Fatal("adoption converged without its persistent pin")
	}
}

// RESTORE_OWNED release of an adopted package restores the baseline pin and
// never removes or downgrades the package lindm did not install.
func TestReleaseOfAdoptedPackageRestoresOnlyItsPin(t *testing.T) {
	d, before, proof := adoptionFixture(t)
	baseline := proto.CloneOf(before)
	applyInstalledProvenance(baseline.GetNativePackage().GetRecord(), proof, d.GetNativePackage().GetRepository())
	adopted := proto.CloneOf(baseline)
	adopted.GetNativePackage().PinContents = aptPin(d.GetNativePackage())
	ledger := &agentv1.ResourceOwnershipLedger{Revision: 2, State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED,
		Owner:    &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}},
		Baseline: &agentv1.ResourceOwnershipSnapshot{Observation: baseline}, LastApplied: &agentv1.ResourceOwnershipSnapshot{Observation: proto.CloneOf(adopted)},
		OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PRESENCE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_VERSION, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PIN}}
	effective, pin, inverse, err := releaseTarget(d, adopted, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if effective.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT || !proto.Equal(effective.GetExact(), before.GetNativePackage().GetRecord().GetVersion()) || len(pin) != 0 || !proto.Equal(effective.GetRepository(), d.GetNativePackage().GetRepository()) {
		t.Fatalf("adopted release = %v, pin %q", effective, pin)
	}
	plan := adoptionPlan(t, d, adopted, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, pin, inverse)
	released := proto.CloneOf(adopted)
	released.GetNativePackage().PinContents = nil
	if checks := adoptedVerification(t, plan, released, ledger); !checks.GetConverged() {
		t.Fatalf("pin-only release of an adopted package did not converge: %v", checks)
	}
	removed := proto.CloneOf(released)
	removed.GetNativePackage().Installed, removed.GetNativePackage().Record = false, nil
	if checks := adoptedVerification(t, plan, removed, ledger); checks.GetConverged() {
		t.Fatal("release verified the removal of a package lindm did not install")
	}
	// lindm later upgraded the adopted package: release keeps the newer version
	// rather than downgrading to the baseline.
	upgraded := proto.CloneOf(adopted)
	upgraded.GetNativePackage().GetRecord().Version = debVersion("1:3.0-1")
	ledger.LastApplied.Observation = proto.CloneOf(upgraded)
	effective, _, _, err = releaseTarget(d, upgraded, ledger)
	if err != nil || !proto.Equal(effective.GetExact(), debVersion("1:3.0-1")) {
		t.Fatalf("adopted then upgraded release = %v, %v", effective, err)
	}
}

func TestAPTIndexDecidesWhetherAnInstalledVersionIsProvable(t *testing.T) {
	_, before, _ := adoptionFixture(t)
	record := before.GetNativePackage().GetRecord()
	indexed := []byte("Package: proof\nArchitecture: amd64\nVersion: 1:2.0-1\nPriority: optional\nFilename: pool/main/p/proof/proof_2.0-1_amd64.deb\nSize: 4096\nSHA256: " + "099bb129f543adc4c14203334b0fa0a909f8bf038c4d56bc9cc7c774ebf78f87" + "\nDescription: proof\n long text\n\n")
	declaration, err := aptIndexedArtifact(indexed, record)
	if err != nil || declaration.size != 4096 || len(declaration.sha256) != 32 {
		t.Fatalf("indexed version = %v, %v", declaration, err)
	}
	statusOnly := []byte("Package: proof\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:2.0-1\nDescription: proof\n")
	if _, err := aptIndexedArtifact(statusOnly, record); !errors.Is(err, errProvenanceUnproven) {
		t.Fatalf("locally installed version = %v", err)
	}
	other := bytes.Replace(indexed, []byte("Version: 1:2.0-1"), []byte("Version: 1:2.0-2"), 1)
	if _, err := aptIndexedArtifact(other, record); err == nil || errors.Is(err, errProvenanceUnproven) {
		t.Fatalf("record for another version = %v", err)
	}
	if _, err := aptIndexedArtifact(append(bytes.TrimRight(indexed, "\n"), []byte("\n\n"+string(indexed))...), record); err == nil {
		t.Fatal("ambiguous APT records accepted")
	}
}

func TestDNFMetadataDecidesWhetherAnInstalledNEVRAIsProvable(t *testing.T) {
	rpm := &resourcev1.RpmRepository{NativeId: "fedora", AdditionalRepositories: []*resourcev1.RpmAdditionalRepository{{NativeId: "updates"}}}
	nevra := "git-0:2.51.0-1.fc44.x86_64"
	line := nevra + "\tupdates\t53120\thttps://mirror.example/updates/Packages/g/git-2.51.0-1.fc44.x86_64.rpm\n"
	file, size, err := dnfIndexedArtifact([]byte(line+line), nevra, rpm)
	if err != nil || file != "git-2.51.0-1.fc44.x86_64.rpm" || size != 53120 {
		t.Fatalf("approved NEVRA = %q %d %v", file, size, err)
	}
	if _, _, err := dnfIndexedArtifact(nil, nevra, rpm); !errors.Is(err, errProvenanceUnproven) {
		t.Fatalf("NEVRA absent from approved metadata = %v", err)
	}
	for name, output := range map[string]string{
		"unapproved repository": nevra + "\tcopr\t53120\tgit.rpm\n",
		"another NEVRA":         "git-0:2.51.0-2.fc44.x86_64\tupdates\t53120\tgit.rpm\n",
		"disagreeing sizes":     line + nevra + "\tfedora\t1\tgit-2.51.0-1.fc44.x86_64.rpm\n",
	} {
		if _, _, err := dnfIndexedArtifact([]byte(output), nevra, rpm); err == nil || errors.Is(err, errProvenanceUnproven) {
			t.Fatalf("%s = %v", name, err)
		}
	}
}

func TestRPMHeaderDigestDecidesProvenance(t *testing.T) {
	record := &resourcev1.NativePackageRecord{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, NativeName: "git", Architecture: "x86_64"}}
	var err error
	if record.Version, err = rpmVersion("0", "2.51.0", "1.fc44"); err != nil {
		t.Fatal(err)
	}
	installed := []byte("git\t0\t2.51.0\t1.fc44\tx86_64\t" + "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" + "\n")
	if err := rpmHeaderMatches(installed, installed, record); err != nil {
		t.Fatalf("identical header: %v", err)
	}
	rebuilt := bytes.Replace(installed, []byte("9f86"), []byte("0000"), 1)
	if err := rpmHeaderMatches(installed, rebuilt, record); !errors.Is(err, errProvenanceUnproven) {
		t.Fatalf("different header = %v", err)
	}
	none := []byte("git\t0\t2.51.0\t1.fc44\tx86_64\t(none)\n")
	if err := rpmHeaderMatches(none, none, record); !errors.Is(err, errProvenanceUnproven) {
		t.Fatalf("header without SHA256HEADER = %v", err)
	}
	if err := rpmHeaderMatches(bytes.Replace(installed, []byte("1.fc44"), []byte("2.fc44"), 1), installed, record); err == nil || errors.Is(err, errProvenanceUnproven) {
		t.Fatalf("query of another version = %v", err)
	}
}

func TestNativeVerifyReportsOnlyChangedPackageContent(t *testing.T) {
	dpkg := []byte("??5?????? c /etc/bash_completion.d/git-prompt\n??5??????   /usr/bin/git\n")
	failures, err := nativeVerifyFailures(dpkg, false)
	if err != nil || !slices.Equal(failures, []string{"/usr/bin/git"}) {
		t.Fatalf("dpkg verify = %q, %v", failures, err)
	}
	rpm := []byte("S.5....T.  c /etc/gitconfig\n.M.......    /usr/bin/git\n......G..    /usr/libexec/git-core\nmissing   d /usr/share/doc/git/README\nmissing     /usr/share/git-core/templates/x\n..?......    /usr/bin/git-shell\n")
	failures, err = nativeVerifyFailures(rpm, true)
	if err != nil || !slices.Equal(failures, []string{"/usr/share/doc/git/README", "/usr/share/git-core/templates/x", "/usr/bin/git-shell"}) {
		t.Fatalf("rpm verify = %q, %v", failures, err)
	}
	for _, line := range []string{"Unsatisfied dependencies for git\n", "S.5....T.  cc /etc/x\n", "S.5..x.T.    /etc/x\n"} {
		if _, err := nativeVerifyFailures([]byte(line), true); err == nil {
			t.Fatalf("unrecognized verify record %q accepted", line)
		}
	}
}

func TestConffileListsCompareInstalledFiles(t *testing.T) {
	shipped := shippedConffiles([]byte("/etc/b.conf\nremove-on-upgrade /etc/old.conf\n/etc/a.conf\n"))
	installed := installedConffiles([]byte(" /etc/a.conf 7baac5c3ced94ebf2c0e1dde65c3b1a6\n /etc/gone.conf 0b1e3e2d0c0e3f2a1b4c5d6e7f809a1b obsolete\n /etc/b.conf newconffile\n"))
	if !slices.Equal(shipped, []string{"/etc/a.conf", "/etc/b.conf"}) || !slices.Equal(installed, shipped) {
		t.Fatalf("conffiles shipped %q, installed %q", shipped, installed)
	}
}

// The dpkg comparison runs against a real dpkg database: dpkg-deb builds the
// archives and dpkg itself installs one into a private root. Nothing native is
// mocked; only the database location differs from the device's own.
func TestDebProofAgainstARealDpkgDatabase(t *testing.T) {
	for _, tool := range []string{"/usr/bin/dpkg", "/usr/bin/dpkg-deb", "/usr/bin/dpkg-query"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skip("dpkg is not installed on this host")
		}
	}
	work := t.TempDir()
	root := filepath.Join(work, "root")
	admin := filepath.Join(root, "var", "lib", "dpkg")
	for _, directory := range []string{filepath.Join(admin, "updates"), filepath.Join(admin, "info")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(admin, "status"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	command := func(name string, args ...string) {
		t.Helper()
		if output, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %q: %v\n%s", name, args, err, output)
		}
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	build := func(name, extraControl string, md5sums bool) string {
		t.Helper()
		tree := filepath.Join(work, name)
		write(filepath.Join(tree, "usr", "share", "lindm-proof", "data"), "approved content\n")
		write(filepath.Join(tree, "etc", "lindm-proof.conf"), "setting = 1\n")
		write(filepath.Join(tree, "DEBIAN", "control"), "Package: lindm-proof\nVersion: 1.0-1\nArchitecture: all\nMaintainer: Lindm <lindm@example.org>\n"+extraControl+"Description: provenance proof fixture\n Installed by dpkg into a private root.\n")
		write(filepath.Join(tree, "DEBIAN", "conffiles"), "/etc/lindm-proof.conf\n")
		if md5sums {
			cmd := exec.Command("md5sum", "usr/share/lindm-proof/data")
			cmd.Dir = tree
			sum, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(tree, "DEBIAN", "md5sums"), string(sum))
		}
		archive := filepath.Join(work, name+".deb")
		command("/usr/bin/dpkg-deb", "--root-owner-group", "--build", tree, archive)
		return archive
	}
	approved := build("approved", "", true)
	command("/usr/bin/dpkg", "--force-not-root", "--root="+root, "--admindir="+admin, "--instdir="+root, "--install", approved)
	record := &resourcev1.NativePackageRecord{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "lindm-proof", Architecture: "all"}, Version: debVersion("1.0-1")}
	p := &Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, run: runNative}
	database := dpkgRoot{admin: admin, instdir: root}
	ctx := context.Background()
	if err := p.debMatchesInstalled(ctx, database, approved, record); err != nil {
		t.Fatalf("installed approved archive: %v", err)
	}
	write(filepath.Join(root, "etc", "lindm-proof.conf"), "setting = 2\n")
	if err := p.debMatchesInstalled(ctx, database, approved, record); err != nil {
		t.Fatalf("administrator configuration refused provenance: %v", err)
	}
	for name, archive := range map[string]string{
		"same version, other control": build("other", "Depends: base-files\n", true),
		"archive without md5sums":     build("unsummed", "", false),
	} {
		if err := p.debMatchesInstalled(ctx, database, archive, record); !errors.Is(err, errProvenanceUnproven) {
			t.Fatalf("%s = %v", name, err)
		}
	}
	sums := filepath.Join(admin, "info", "lindm-proof.md5sums")
	original, err := os.ReadFile(sums)
	if err != nil {
		t.Fatal(err)
	}
	write(sums, string(bytes.Replace(original, []byte("usr/share"), []byte("usr/local"), 1)))
	if err := p.debMatchesInstalled(ctx, database, approved, record); !errors.Is(err, errProvenanceUnproven) {
		t.Fatalf("rewritten installed md5sums = %v", err)
	}
	write(sums, string(original))
	write(filepath.Join(root, "usr", "share", "lindm-proof", "data"), "changed after installation\n")
	if err := p.debMatchesInstalled(ctx, database, approved, record); !errors.Is(err, errProvenanceUnproven) {
		t.Fatalf("changed installed file = %v", err)
	}
}
