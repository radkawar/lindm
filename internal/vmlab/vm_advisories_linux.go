// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/platform"
)

// VMAdvisoryEvidence binds the vendor acquisition, independently checked native
// package multiset and persisted server evaluation. Partial-feed matching never
// asserts complete coverage or a clean device.
type VMAdvisoryEvidence struct {
	Scope           string                 `json:"scope"`
	Source          *advisoryv1.FeedSource `json:"source"`
	PartialCoverage string                 `json:"partial_coverage,omitempty"`
	// VerifiedOrigin is the partial reason a derivative's evaluation through
	// its base's feed must carry; Origin is that evaluation's oracle.
	VerifiedOrigin  string                       `json:"verified_origin,omitempty"`
	Origin          *VMAdvisoryOriginEvidence    `json:"origin,omitempty"`
	Refresh         *devlab.AcceptanceFeedResult `json:"refresh,omitempty"`
	Inventory       *vmInventoryEvidence         `json:"inventory,omitempty"`
	Packages        []*inventoryv1.Package       `json:"packages,omitempty"`
	InventorySHA256 string                       `json:"inventory_sha256,omitempty"`
	Feed            *adminv1.AdvisoryFeedStatus  `json:"feed,omitempty"`
	Freshness       *adminv1.AdvisoryFreshness   `json:"freshness,omitempty"`
	Findings        []*adminv1.AdvisoryFinding   `json:"findings,omitempty"`
	NativeMatches   int                          `json:"native_matches"`
	AffectedMatches int                          `json:"affected_matches"`
	Boundary        *VMAdvisoryBoundaryEvidence  `json:"boundary,omitempty"`
	Outcome         string                       `json:"outcome"`
}

// vmAdvisorySource deliberately permits registry-declared partial sources so
// the lane can record their actual UNKNOWN result rather than invent coverage.
// No URL, distribution identity or architecture support is guessed here. A
// snapshot row has no fixed registry version, so its feed release derives from
// the image's dated VERSION_ID (an empty Tumbleweed release failed validation).
func vmAdvisorySource(release *platform.Release, imageVersion, architecture string) (*advisoryv1.FeedSource, error) {
	if release == nil || !release.Known() || len(advisoryFeedRow(release).Advisory.Feeds) == 0 {
		return nil, errors.New("advisories: no maintained vendor source")
	}
	return vmAdvisoryFeedSource(release, imageVersion, architecture, advisoryFeedRow(release).Advisory.Feeds[0], "matrix-"+release.Key)
}

// advisoryFeedRow is the registry row whose vendor feeds apply to the release:
// a derivative's base (BaseCoverage), whose feed covers only the derivative's
// verified base-archive packages, or the release itself.
func advisoryFeedRow(release *platform.Release) *platform.Release {
	if base := release.BaseCoverage(); base != nil {
		return base
	}
	return release
}

// advisoryOriginReason is the partial evaluation reason the server must report
// for a derivative evaluated through its base's feed, "" for any other release.
func advisoryOriginReason(release *platform.Release) string {
	if release.BaseCoverage() == nil {
		return ""
	}
	return "vendor_feed_unavailable_" + release.ID
}

// AirgapAdvisories derives the connected station's bundle feeds from every
// registry feed with a maintained export, with the same partial-coverage
// policy as the advisories lane. Feeds the registry lists without an export
// (for example Tumbleweed's CSAF) cannot be acquired and are not invented. A
// derivative bundles its base's feeds: the derivative vendor publishes none.
func AirgapAdvisories(release *platform.Release, imageVersion, architecture string) (*configv1.AdvisoryConfig, error) {
	if release == nil || !release.Known() || len(advisoryFeedRow(release).Advisory.Feeds) == 0 {
		return nil, errors.New("advisories: no maintained vendor source")
	}
	feedRow := advisoryFeedRow(release)
	cfg := new(configv1.AdvisoryConfig)
	for _, feed := range feedRow.Advisory.Feeds {
		if _, exported := feedRow.Advisory.Exports[feed]; !exported {
			continue
		}
		source, err := vmAdvisoryFeedSource(release, imageVersion, architecture, feed, "airgap-"+release.Key+"-"+string(feed))
		if err != nil {
			return nil, err
		}
		cfg.Feeds = append(cfg.Feeds, source)
	}
	if len(cfg.Feeds) == 0 {
		return nil, fmt.Errorf("advisories: no maintained export for %s", release.Key)
	}
	return cfg, nil
}

// Stream-scoped (Red Hat) sources name the image's exact minor: from RHEL 10,
// standard-stream errata carry minor CPEs (enterprise_linux:10.1), so a major
// source admits only the major-wide VEX claims and never a fix. A derivative's
// source is its base's feed identity and export (advisoryFeedRow), bounded by
// the derivative's own architectures.
func vmAdvisoryFeedSource(release *platform.Release, imageVersion, architecture string, feed platform.Feed, prefix string) (*advisoryv1.FeedSource, error) {
	feedRow := advisoryFeedRow(release)
	versionID := feedRow.Version.Value
	switch {
	case feedRow.Version.Rule == platform.VersionSnapshot:
		versionID = imageVersion
	case feedRow.Advisory.PlatformStreams:
		if platform.Identify(platform.OSRelease{ID: feedRow.ID, VersionID: imageVersion}).Key != feedRow.Key {
			return nil, fmt.Errorf("advisories: image version %q is not %s", imageVersion, feedRow.Name)
		}
		versionID = imageVersion
	}
	switch architecture {
	case "amd64":
		architecture = "x86_64"
	case "arm64":
		architecture = "aarch64"
	}
	if !slices.Contains(release.Architectures, architecture) {
		return nil, fmt.Errorf("advisories: unsupported architecture %q", architecture)
	}
	export, ok := feedRow.Advisory.Exports[feed]
	url := export.URL
	if len(export.ArchitectureURLs) != 0 {
		url = export.ArchitectureURLs[architecture]
	}
	format, supported := advisoryv1.FeedFormat_value["FEED_FORMAT_"+strings.ToUpper(strings.ReplaceAll(export.Format, "-", "_"))]
	if !ok || url == "" || export.MaxAgeSeconds == 0 || !supported || format == 0 {
		return nil, fmt.Errorf("advisories: no maintained %s export for %s/%s", feed, release.Key, architecture)
	}
	if release.Native().Packages.Backend == platform.BackendAPT {
		switch architecture {
		case "x86_64":
			architecture = "amd64"
		case "aarch64":
			architecture = "arm64"
		}
	}
	source := &advisoryv1.FeedSource{
		Id:     prefix + "-" + architecture,
		Distro: feedRow.ID, Release: feedRow.FeedRelease(versionID), Architecture: architecture,
		Url: url, Format: advisoryv1.FeedFormat(format), MaxAgeSeconds: export.MaxAgeSeconds,
		PlatformStream: export.PlatformStream,
	}
	if export.MaxArchiveBytes != 0 {
		source.MaxArchiveBytes = proto.Uint64(export.MaxArchiveBytes)
	}
	return source, nil
}

// vmAdvisoryRefreshBounds bounds the lab's vendor acquisition and publication.
// The default fits the paired RHEL CSAF archives: 480,655,133 bytes on
// 2026-10-11, with a measured 7.5-minute full publication. Exports declaring a
// larger registry archive allowance (Ubuntu's OSV all.zip, over 700 MB and
// 500,000 claims) get it with a longer window: on a 0.6 MB/s controller link
// the first fetch alone takes over 20 minutes. Revalidated cache hits are fast.
func vmAdvisoryRefreshBounds(source *advisoryv1.FeedSource) (int64, time.Duration) {
	byteBudget, duration := int64(1<<30), 30*time.Minute
	if allowance := int64(source.GetMaxArchiveBytes()); allowance > byteBudget {
		byteBudget, duration = allowance, 45*time.Minute
	}
	return byteBudget, duration
}

func exerciseVMAdvisories(ctx context.Context, vm *guestVM, control *vmControlPlane, fixture *devlab.AuthorityFixture, manifest *labv1.ImageManifest, cacheDir, deviceID string) (evidence *VMAdvisoryEvidence, err error) {
	release := manifestRelease(manifest)
	source, err := vmAdvisorySource(release, manifest.GetVersion(), manifest.GetArchitecture())
	if err != nil {
		return nil, err
	}
	evidence = &VMAdvisoryEvidence{Source: source, PartialCoverage: release.Advisory.Partial, VerifiedOrigin: advisoryOriginReason(release), Outcome: "incomplete"}
	before, err := collectVMTruth(ctx, vm, release)
	if err != nil {
		return evidence, err
	}
	evidence.Inventory, err = control.WaitSnapshot(ctx, deviceID, before, nil, 5*time.Minute)
	if err != nil {
		return evidence, err
	}
	// Cursor tokens are session authority, not durable evidence. Retain snapshot
	// identity and complete package rows, but do not publish the cursor.
	evidence.Inventory.FirstPageToken = ""
	after, err := collectVMTruth(ctx, vm, release)
	if err != nil {
		return evidence, err
	}
	if err := stableVMTruth(before, after); err != nil {
		return evidence, err
	}
	evidence.Packages, evidence.InventorySHA256, err = vmAdvisoryInventory(evidence.Inventory.packages)
	if err != nil {
		return evidence, err
	}
	byteBudget, duration := vmAdvisoryRefreshBounds(source)
	evidence.Refresh, err = fixture.RefreshVendorFeeds(ctx, filepath.Join(cacheDir, "advisories"), byteBudget, duration, []*advisoryv1.FeedSource{source})
	if err != nil {
		evidence.Outcome = "feed_refresh_failed"
		return evidence, err
	}
	feeds, err := control.session.Admin.ListAdvisoryFeeds(ctx, connect.NewRequest(&adminv1.ListAdvisoryFeedsRequest{}))
	if err != nil {
		return evidence, vmControlPlaneError("read published advisory feeds", err)
	}
	for _, candidate := range feeds.Msg.GetFeeds() {
		if candidate.GetId() == source.GetId() {
			evidence.Feed = candidate
			break
		}
	}
	if err := vmAdvisoryAcquisition(evidence); err != nil {
		evidence.Outcome = "feed_publication_unqualified"
		return evidence, err
	}
	if err := waitVMAdvisoryEvaluation(ctx, control, deviceID, evidence); err != nil {
		return evidence, err
	}
	if evidence.VerifiedOrigin != "" {
		if evidence.Origin, err = exerciseVMAdvisoryOrigin(ctx, vm, control, release, deviceID, evidence); err != nil {
			evidence.Outcome = "verified_origin_partial_unqualified"
			return evidence, err
		}
	}
	evidence.Boundary, err = exerciseVMAdvisoryBoundary(ctx, vm, fixture, evidence, before.manager)
	if err != nil {
		evidence.Outcome = "vendor_boundary_unqualified"
		return evidence, err
	}
	err = qualifyVMAdvisoryMatches(evidence)
	return evidence, err
}

// The digest covers compact encoding/json of the complete sorted Package list,
// with multiplicity and native source/module identity retained. The same list is
// embedded in the immutable lane record so its digest can be reproduced.
func vmAdvisoryInventory(packages map[nativePackage]int) ([]*inventoryv1.Package, string, error) {
	var rows []*inventoryv1.Package
	for p, count := range packages {
		if count <= 0 || count > 100000-len(rows) {
			return nil, "", errors.New("advisories: invalid native package multiplicity")
		}
		for range count {
			rows = append(rows, &inventoryv1.Package{Name: p.name, Version: p.version, Architecture: p.architecture, Manager: p.manager, SourceName: p.sourceName, SourceVersion: p.sourceVersion, Module: &inventoryv1.ModuleObservation{Status: p.module.status, Modular: p.module.modular, Name: p.module.name, Stream: p.module.stream, Version: p.module.version, Context: p.module.context}})
		}
	}
	if len(rows) == 0 {
		return nil, "", errors.New("advisories: empty native inventory")
	}
	// Package JSON has fixed struct-field ordering. Sort the complete row, not
	// only name/version, to preserve reproducibility with duplicate identities.
	encoded := make(map[*inventoryv1.Package]string, len(rows))
	for _, row := range rows {
		data, err := json.Marshal(row)
		if err != nil {
			return nil, "", err
		}
		encoded[row] = string(data)
	}
	slices.SortFunc(rows, func(a, b *inventoryv1.Package) int { return strings.Compare(encoded[a], encoded[b]) })
	data, err := json.Marshal(rows)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(data)
	return rows, hex.EncodeToString(digest[:]), nil
}

func vmAdvisoryAcquisition(e *VMAdvisoryEvidence) error {
	f := e.Feed
	if f == nil || f.GetId() != e.Source.GetId() || f.GetSourceUrl() != e.Source.GetUrl() || !vmValidTime(f.GetCheckedAt()) || f.GetAdvisoryCount() == 0 || f.GetError() != "" {
		return errors.New("advisories: missing, failed or empty vendor publication")
	}
	digest, err := hex.DecodeString(f.GetSourceSha256())
	if err != nil || len(digest) != sha256.Size || e.Refresh == nil || len(e.Refresh.Artifacts) == 0 || len(f.GetArtifacts()) == 0 {
		return errors.New("advisories: vendor publication lacks acquisition hashes")
	}
	for _, artifact := range f.GetArtifacts() {
		found := false
		for _, fetched := range e.Refresh.Artifacts {
			if fetched.URL == artifact.GetUrl() && fetched.SHA256 == hex.EncodeToString(artifact.GetSha256()) && fetched.Bytes > 0 {
				found = true
				break
			}
		}
		if !found {
			return errors.New("advisories: published artifact was not fetched and hashed by this run")
		}
	}
	return nil
}

func waitVMAdvisoryEvaluation(ctx context.Context, control *vmControlPlane, deviceID string, e *VMAdvisoryEvidence) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		response, err := control.session.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: deviceID, PageSize: 200}))
		if err != nil {
			return vmControlPlaneError("read server advisory evaluation", err)
		}
		e.Freshness = response.Msg.GetFreshness()
		if e.Freshness.GetReason() != "evaluation_pending" && e.Freshness.GetSnapshotId() == e.Inventory.SnapshotID && e.Freshness.GetFeedId() == e.Source.GetId() && e.Freshness.GetSourceSha256() == e.Feed.GetSourceSha256() {
			e.Findings = response.Msg.GetFindings()
			cursor := response.Msg.GetNextPageToken()
			seen := make(map[string]bool)
			for cursor != "" {
				if seen[cursor] || len(e.Findings) >= 100000 {
					return errors.New("advisories: findings pagination exceeded bound or repeated cursor")
				}
				seen[cursor] = true
				page, err := control.session.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: deviceID, PageSize: 200, PageToken: cursor}))
				if err != nil {
					return vmControlPlaneError("read server advisory findings page", err)
				}
				if !proto.Equal(page.Msg.GetFreshness(), e.Freshness) || len(page.Msg.GetFindings()) == 0 {
					return errors.New("advisories: evaluation changed during pagination")
				}
				e.Findings = append(e.Findings, page.Msg.GetFindings()...)
				cursor = page.Msg.GetNextPageToken()
			}
			return nil
		}
		select {
		case <-ctx.Done():
			e.Outcome = "evaluation_not_bound_to_native_snapshot"
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func qualifyVMAdvisoryMatches(e *VMAdvisoryEvidence) error {
	e.NativeMatches, e.AffectedMatches = 0, 0
	if len(e.Packages) == 0 {
		return errors.New("advisories: native inventory is empty")
	}
	for _, finding := range e.Findings {
		if finding.GetFeedId() != e.Source.GetId() || finding.GetAdvisoryId() == "" || finding.GetSourceUrl() == "" {
			return errors.New("advisories: finding lacks vendor identity")
		}
		matched := slices.ContainsFunc(e.Packages, func(p *inventoryv1.Package) bool {
			return p.GetName() == finding.GetPackageName() && p.GetVersion() == finding.GetInstalledVersion() && p.GetArchitecture() == finding.GetArchitecture()
		})
		if !matched {
			return errors.New("advisories: finding does not identify an actually installed native package")
		}
		e.NativeMatches++
		if finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
			e.AffectedMatches++
		}
	}
	partial := e.Freshness.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN && e.Freshness.GetReason() == "feed_partial_coverage"
	if e.VerifiedOrigin != "" {
		// A derivative is partial only through its verified-origin oracle.
		partial = e.Origin != nil && e.Origin.Reason == e.VerifiedOrigin && validateVMAdvisoryOrigin(e.Origin, e) == nil
	}
	if !vmValidTime(e.Feed.GetExpiresAt()) || !time.Now().Before(e.Feed.GetExpiresAt().AsTime()) || (e.Freshness.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN && !partial) || (!e.Feed.GetFresh() && !partial) || (e.PartialCoverage != "" && !partial) {
		e.Outcome = "unsupported_coverage"
		return fmt.Errorf("advisories: native evaluation remains unqualified: %s", e.Freshness.GetReason())
	}
	if e.AffectedMatches == 0 && !validVMAdvisoryBoundary(e.Boundary) {
		e.Outcome = "no_positive_matching_oracle"
		return errors.New("advisories: no affected native package or real vendor boundary oracle; an empty match alone is not a pass")
	}
	e.Scope, e.Outcome = "native feed matching; not complete device coverage", "qualified_native_match"
	if e.VerifiedOrigin != "" {
		e.Scope, e.Outcome = "partial-feed matching", "qualified_verified_origin_partial_matching"
	} else if partial || e.PartialCoverage != "" {
		e.Scope, e.Outcome = "partial-feed matching", "qualified_partial_feed_matching"
	}
	return nil
}
