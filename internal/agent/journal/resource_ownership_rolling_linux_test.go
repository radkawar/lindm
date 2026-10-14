// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/packagepin"
	"lindm/internal/resource"
)

func rollingOwnershipRecord(t *testing.T, f serviceJournalFixture, alpm bool, contents string) *agentv1.ResourceExecutionRecord {
	t.Helper()
	record := f.record(t, 1, "unused.service", true)
	ecosystem, backend, prefix, path := resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, resourcev1.Backend_BACKEND_ZYPPER, "rpm", packagepin.ZypperPath
	version := &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Rpm{Rpm: &resourcev1.RPMVersion{Version: "2.0", Release: "1"}}}
	product := &resourcev1.PlatformProduct{OsId: "opensuse-tumbleweed", Product: "openSUSE Tumbleweed", Version: "20261007", Architecture: "x86_64"}
	if alpm {
		ecosystem, backend, prefix, path = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM, resourcev1.Backend_BACKEND_ALPM, "alpm", packagepin.PacmanPath
		version = &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Alpm{Alpm: &resourcev1.ALPMVersion{Pkgver: "2.0", Pkgrel: "1"}}}
		product = &resourcev1.PlatformProduct{OsId: "arch", Product: "Arch Linux", Architecture: "x86_64"}
	}
	identity := &resourcev1.PackageIdentity{Ecosystem: ecosystem, NativeName: "proof", Architecture: "x86_64"}
	ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: prefix + "/proof/x86_64"}
	desired := &resourcev1.NativePackageDesired{Package: identity, Presence: resourcev1.Presence_PRESENCE_PRESENT, Version: &resourcev1.NativePackageDesired_Exact{Exact: version}, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: prefix + "/" + uuid.NewString()}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA}
	record.Intent.Desired = &resourcev1.ResourceDesiredState{Ref: ref, State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: desired}}
	record.Intent.Preparation = &agentv1.ResourceExecutionPreparation{Deadline: proto.CloneOf(record.GetIntent().GetExpiresAt()), MaxCacheBytes: 1 << 20}
	record.Intent.Ownership.Policy = &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}
	plan := record.NativePlan
	plan.Ref, plan.Before.Ref, record.Challenge.Ref = proto.CloneOf(ref), proto.CloneOf(ref), proto.CloneOf(ref)
	plan.Backend = &resourcev1.BackendSelection{Backend: backend, Product: product, NativeVersion: "1", ProviderVersion: "1"}
	plan.Before.Metadata.Backend = proto.CloneOf(plan.Backend)
	pinDigest := sha256.Sum256([]byte(contents))
	plan.Before.Observed = &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{Package: proto.CloneOf(identity), DatabaseRevisionSha256: bytes.Repeat([]byte{2}, 32), PinFile: &resourcev1.FileIdentity{Path: path, Device: 1, Inode: 2, Mode: 0644, Sha256: pinDigest[:]}, PinContents: []byte(contents)}}
	artifact := &resourcev1.ArtifactRef{ArtifactId: uuid.NewString(), Sha256: bytes.Repeat([]byte{4}, 32), SizeBytes: 100}
	plan.Plan = &resourcev1.ResourcePlan_NativePackage{NativePackage: &resourcev1.NativePackagePlan{Desired: proto.CloneOf(desired), TransactionManifest: artifact, NativeDatabaseRevision: bytes.Repeat([]byte{2}, 32), NativeLockIdentity: prefix + ":native-lock", ChangePackages: true}}
	plan.Safety = &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED, PrerequisiteManifests: []*resourcev1.ArtifactRef{artifact}}
	desiredDigest, err := resource.DesiredDigest(record.GetIntent().GetDesired())
	if err != nil {
		t.Fatal(err)
	}
	plan.DesiredSha256 = desiredDigest[:]
	observationDigest, err := resource.ObservationDigest(plan.GetBefore())
	if err != nil {
		t.Fatal(err)
	}
	plan.ObservationSha256 = observationDigest[:]
	planDigest, err := resource.PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	record.Challenge.NativePlanSha256 = planDigest[:]
	return record
}

func TestRollingPackageJournalAcquiresOnlyUnownedSharedPin(t *testing.T) {
	for _, alpm := range []bool{false, true} {
		prefix, ordinary := "rpm", "type: package\nmatch_type: exact\nsolvable_name: other\n\n"
		if alpm {
			prefix, ordinary = "alpm", "[options]\nIgnorePkg = other\n[core]\n"
		}
		marker := "# lindm:" + prefix + "/proof/x86_64"
		for _, test := range []struct {
			name, contents string
			conflict       bool
		}{
			{"ordinary", ordinary, false},
			{"owned", ordinary + marker + " begin\nowned\n" + marker + " end\n", true},
			{"damaged", ordinary + marker + " begin\nowned\n", true},
		} {
			t.Run(prefix+"/"+test.name, func(t *testing.T) {
				f := newServiceJournalFixture(t)
				prepared := rollingOwnershipRecord(t, f, alpm, test.contents)
				pending := proto.CloneOf(prepared)
				pending.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING
				pending.NativePlan, pending.Challenge = nil, nil
				pending.ChallengeProof, pending.ChallengeCertificatePem = nil, nil
				pending.ChallengeBoottimeNs = 0
				if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, pending); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.UpdateResourceAction(t.Context(), 1, 1, 2, prepared); err != nil {
					t.Fatal(err)
				}
				record := serviceQueued(prepared)
				if _, err := f.store.UpdateResourceAction(t.Context(), 2, 1, 2, record); err != nil {
					t.Fatal(err)
				}
				ledger, err := f.store.ClaimResourceOwnership(t.Context(), record.GetIntent().GetActionId(), 0, ownershipSnapshot(record))
				if test.conflict {
					if !errors.Is(err, ErrResourceOwnershipConflict) {
						t.Fatalf("unsafe shared-pin acquisition: %v", err)
					}
				} else if err != nil || ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED {
					t.Fatalf("ordinary shared document required adoption: %v", err)
				}
			})
		}
	}
}
