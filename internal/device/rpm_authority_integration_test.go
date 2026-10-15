// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory"
	"lindm/internal/rpmauthority"
)

func TestRHELNativeSignedRPMBeginPutCommitCoverage(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, release := range []string{"9", "10"} {
		t.Run(release, func(t *testing.T) {
			f := newEnrolled(t, 0)
			name := "dbus"
			if release == "10" {
				name = "dbus10"
			}
			raw, err := os.ReadFile("../rpmauthority/testdata/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var proof struct{ ImmutableHeader, Signature []byte }
			if err := json.Unmarshal(raw, &proof); err != nil {
				t.Fatal(err)
			}
			i, err := rpmauthority.Parse(proof.ImmutableHeader)
			if err != nil {
				t.Fatal(err)
			}
			native := &inventoryv1.Package{Name: i.Name, Version: i.Version, Architecture: i.Architecture, Manager: "rpm", SourceName: i.SourceName, SourceVersion: i.SourceVersion, SourceArchitecture: i.SourceArchitecture, Module: i.Module, RpmAuthority: &inventoryv1.RpmAuthority{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, ImmutableHeader: proof.ImmutableHeader, Signature: proof.Signature}}
			thirdParty := &inventoryv1.Package{Name: "epel-unassessed-addon", Version: "0:1-1.el" + release, Architecture: "x86_64", Manager: "rpm", Module: &inventoryv1.ModuleObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS}, RpmAuthority: &inventoryv1.RpmAuthority{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}}
			source := &advisoryv1.FeedSource{Id: "controlled-rhel-rpm-upload-" + release, Distro: "rhel", Release: release, PlatformStream: "standard", Architecture: "x86_64", Format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF, Url: "https://security.access.redhat.com/data/csaf/v2/", MaxAgeSeconds: 86400}
			store, err := advisory.New(f.ctx, f.svc.Pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
			if err != nil {
				t.Fatal(err)
			}
			f.svc.Advisories = store
			// Controlled normalized product claims isolate inventory admission and
			// matching. These are NOT represented as signed vendor advisories; real
			// closed-snapshot acquisition is covered by the feed integration suite.
			revision := uuid.New()
			digest := sha256.Sum256([]byte("controlled RHEL native RPM upload matching fixture " + release))
			if _, err := f.svc.Pool.Exec(f.ctx, `UPDATE advisory_feeds SET revision=$2,source_sha256=$3,checked_at=now(),expires_at=now()+interval '24 hours',complete_snapshot=true,advisory_count=1 WHERE id=$1`, source.Id, revision, digest[:]); err != nil {
				t.Fatal(err)
			}
			record := &advisoryv1.Advisory{Id: "SYNTHETIC-RHEL-RPM-UPLOAD", PackageName: native.Name, Architecture: native.Architecture, ComponentVersion: native.Version, FixedVersion: "99:99-1", PlatformRelease: release, PlatformStream: "standard", Severity: "high", Cves: []string{"CVE-2099-99032"}, SourceUrl: source.Url}
			recordBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.Pool.Exec(f.ctx, `INSERT INTO advisory_record_generations(generation,id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes) VALUES($1,$2,$3,$4,$5,false,$6,$7)`, revision, uuid.New(), source.Id, record.Id, record.PackageName, record.Architecture, recordBytes); err != nil {
				t.Fatal(err)
			}
			host := hostObservation(f.generation, 1, "signed-rhel-"+release)
			host.Observation.StartedAt = timestamppb.New(f.now)
			host.Observation.FinishedAt = timestamppb.New(f.now)
			host.Observation.OsId.Value = "rhel"
			host.Observation.OsVersion.Value = release
			host.Observation.Architecture.Value = "x86_64"
			host.Observation.Details = nativeDetailsFixture()
			host.Observation.Details.Platform = &inventoryv1.PlatformDetails{Cpe: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "cpe:/o:redhat:enterprise_linux:" + release + "::baseos"}, ReleaseverLock: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}, Repositories: &inventoryv1.RepositoryObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Backend: "dnf4", Ids: []string{"rhel-" + release + "-for-x86_64-baseos-rpms"}}}
			if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(host)); err != nil {
				t.Fatal(err)
			}
			batch := packageBatch(t, native, thirdParty)
			manifest := snapshotManifest(t, f.generation, 1, f.now, [][]byte{batch})
			manifest.Backend = "rpm"
			if _, err := f.begin(t, manifest, 1); err != nil {
				t.Fatal(err)
			}
			if _, err := f.put(t, manifest.SnapshotId, 0, batch, 1); err != nil {
				t.Fatal(err)
			}
			if _, err := f.commit(t, manifest, 1); err != nil {
				t.Fatal(err)
			}
			var retained []byte
			var signer, reason string
			if err := f.svc.Pool.QueryRow(f.ctx, `SELECT rpm_authority,rpm_signer,rpm_authority_reason FROM snapshot_packages WHERE snapshot_id=$1 AND position=0`, uuid.MustParse(manifest.SnapshotId)).Scan(&retained, &signer, &reason); err != nil {
				t.Fatal(err)
			}
			want, err := proto.MarshalOptions{Deterministic: true}.Marshal(native.RpmAuthority)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(retained, want) || signer != rpmauthority.Fingerprint || reason != "" {
				t.Fatalf("real admission lost cryptographic authority: signer=%q reason=%q", signer, reason)
			}
			if _, err := store.Evaluate(f.ctx, uuid.MustParse(f.deviceID)); err != nil {
				t.Fatal(err)
			}
			out, err := f.svc.ListDeviceFindings(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: f.deviceID}))
			if err != nil {
				t.Fatal(err)
			}
			if out.Msg.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || out.Msg.Freshness.UncoveredPackages != 1 || len(out.Msg.Findings) != 1 || out.Msg.Findings[0].PackageName != native.Name {
				t.Fatalf("signed upload did not yield bounded coverage: %v", out.Msg)
			}
			uncovered, err := f.svc.ListDeviceUncoveredPackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceUncoveredPackagesRequest{DeviceId: f.deviceID}))
			if err != nil {
				t.Fatal(err)
			}
			if len(uncovered.Msg.Packages) != 1 || uncovered.Msg.Packages[0].Name != thirdParty.Name || uncovered.Msg.Packages[0].Reason != "rpm_authority_unavailable" {
				t.Fatalf("unsigned third-party upload implicitly covered: %v", uncovered.Msg)
			}
		})
	}
}
