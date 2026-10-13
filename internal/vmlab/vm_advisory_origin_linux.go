//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/platform"
)

// maxAdvisoryOriginQueries bounds the guest APT policy queries of one side
// (vendor-reason uncovered packages, finding packages) of the origin oracle.
const maxAdvisoryOriginQueries = 200

var aptPackageName = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]*$`)

// VMAdvisoryOriginEvidence qualifies a derivative's verified-origin partial
// evaluation: the base release's feed applied only to packages whose APT
// listings are the base archive's, and the derivative vendor's own packages
// listed UNKNOWN rather than cleared. Origins are the guest's own APT policy
// (Release Origin and Archive of the installed version's package indexes),
// observed independently of the agent's inventory.
type VMAdvisoryOriginEvidence struct {
	Reason        string                      `json:"reason"`
	BaseOrigin    string                      `json:"base_origin"`
	BaseSuites    []string                    `json:"base_suites"`
	VendorOrigins []string                    `json:"vendor_origins"`
	Uncovered     []*adminv1.UncoveredPackage `json:"uncovered"`
	// UncoveredReasons counts uncovered packages per server reason code.
	UncoveredReasons map[string]int `json:"uncovered_reasons"`
	// VendorPackages and FindingPackages map each checked package to the
	// "origin/archive" pairs of its installed version's APT indexes.
	VendorPackages  map[string][]string `json:"vendor_packages"`
	FindingPackages map[string][]string `json:"finding_packages"`
}

// exerciseVMAdvisoryOrigin reads every uncovered package of the evaluation
// bound in e and checks origins in the guest: a vendor-reason package must be
// listed by a vendor origin, and every finding's package only by the base
// archive in a suite its feed assesses.
func exerciseVMAdvisoryOrigin(ctx context.Context, vm *guestVM, control *vmControlPlane, release *platform.Release, deviceID string, e *VMAdvisoryEvidence) (*VMAdvisoryOriginEvidence, error) {
	base := release.BaseCoverage()
	if base == nil {
		return nil, fmt.Errorf("advisories: %s has no verified-origin base coverage", release.Name)
	}
	o := &VMAdvisoryOriginEvidence{
		Reason: advisoryOriginReason(release), BaseOrigin: base.Advisory.ArchiveOrigin, BaseSuites: base.Advisory.ArchiveSuites,
		VendorOrigins: release.Advisory.VendorOrigins, UncoveredReasons: map[string]int{},
	}
	token, seen := "", map[string]bool{}
	for {
		page, err := control.session.Admin.ListDeviceUncoveredPackages(ctx, connect.NewRequest(&adminv1.ListDeviceUncoveredPackagesRequest{DeviceId: deviceID, PageSize: 200, PageToken: token}))
		if err != nil {
			return o, vmControlPlaneError("read uncovered packages", err)
		}
		if f := page.Msg.GetFreshness(); f.GetSnapshotId() != e.Freshness.GetSnapshotId() || f.GetFeedId() != e.Freshness.GetFeedId() || f.GetSourceSha256() != e.Freshness.GetSourceSha256() ||
			f.GetState() != e.Freshness.GetState() || f.GetReason() != e.Freshness.GetReason() || f.GetUncoveredPackages() != e.Freshness.GetUncoveredPackages() {
			return o, errors.New("advisories: evaluation changed while listing uncovered packages")
		}
		o.Uncovered = append(o.Uncovered, page.Msg.GetPackages()...)
		if token = page.Msg.GetNextPageToken(); token == "" {
			break
		}
		if seen[token] || len(o.Uncovered) >= 100000 {
			return o, errors.New("advisories: uncovered pagination exceeded bound or repeated cursor")
		}
		seen[token] = true
	}
	var vendor, findings []string
	for _, p := range o.Uncovered {
		o.UncoveredReasons[p.GetReason()]++
		if p.GetReason() == "vendor_feed_unavailable" && len(vendor) < maxAdvisoryOriginQueries && !slices.Contains(vendor, p.GetName()) {
			vendor = append(vendor, p.GetName())
		}
	}
	for _, f := range e.Findings {
		if len(findings) < maxAdvisoryOriginQueries && !slices.Contains(findings, f.GetPackageName()) {
			findings = append(findings, f.GetPackageName())
		}
	}
	origins, err := guestAPTInstalledOrigins(ctx, vm, slices.Concat(vendor, findings))
	if err != nil {
		return o, err
	}
	o.VendorPackages, o.FindingPackages = make(map[string][]string, len(vendor)), make(map[string][]string, len(findings))
	for _, name := range vendor {
		o.VendorPackages[name] = origins[name]
	}
	for _, name := range findings {
		o.FindingPackages[name] = origins[name]
	}
	return o, validateVMAdvisoryOrigin(o, e)
}

// validateVMAdvisoryOrigin is the derivative partial oracle over recorded
// evidence: the server's PARTIAL state with the derivative's reason and an
// exact uncovered count, uncovered rows naming installed native packages,
// at least one vendor package the guest lists from a vendor origin, and
// findings only for packages the guest lists solely from assessed base
// suites, never for an uncovered one.
func validateVMAdvisoryOrigin(o *VMAdvisoryOriginEvidence, e *VMAdvisoryEvidence) error {
	if o == nil || o.Reason == "" || e.Freshness.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || e.Freshness.GetReason() != o.Reason {
		return fmt.Errorf("advisories: derivative evaluation is %s/%s, not verified-origin partial", e.Freshness.GetState(), e.Freshness.GetReason())
	}
	if len(o.Uncovered) == 0 || uint64(len(o.Uncovered)) != e.Freshness.GetUncoveredPackages() {
		return fmt.Errorf("advisories: %d uncovered packages listed, evaluation reports %d", len(o.Uncovered), e.Freshness.GetUncoveredPackages())
	}
	uncovered := make(map[[2]string]bool, len(o.Uncovered))
	for _, p := range o.Uncovered {
		if !slices.ContainsFunc(e.Packages, func(installed *inventoryv1.Package) bool {
			return installed.GetName() == p.GetName() && installed.GetVersion() == p.GetVersion() && installed.GetArchitecture() == p.GetArchitecture()
		}) {
			return fmt.Errorf("advisories: uncovered package %s %s is not an installed native package", p.GetName(), p.GetVersion())
		}
		uncovered[[2]string{p.GetName(), p.GetArchitecture()}] = true
	}
	if o.UncoveredReasons["vendor_feed_unavailable"] == 0 || len(o.VendorPackages) == 0 {
		return errors.New("advisories: no derivative vendor package is uncovered")
	}
	for name, origins := range o.VendorPackages {
		if !slices.ContainsFunc(origins, func(origin string) bool {
			return slices.Contains(o.VendorOrigins, strings.SplitN(origin, "/", 2)[0])
		}) {
			return fmt.Errorf("advisories: uncovered vendor package %s has no vendor APT origin (%v)", name, origins)
		}
	}
	for _, f := range e.Findings {
		if uncovered[[2]string{f.GetPackageName(), f.GetArchitecture()}] {
			return fmt.Errorf("advisories: base feed finding for uncovered package %s", f.GetPackageName())
		}
	}
	for name, origins := range o.FindingPackages {
		if len(origins) == 0 || slices.ContainsFunc(origins, func(origin string) bool {
			source, archive, _ := strings.Cut(origin, "/")
			return source != o.BaseOrigin || !slices.Contains(o.BaseSuites, archive)
		}) {
			return fmt.Errorf("advisories: finding package %s is not listed solely by the assessed %s archive (%v)", name, o.BaseOrigin, origins)
		}
	}
	return nil
}

// guestAPTInstalledOrigins returns, per package, the "origin/archive" pairs of
// the package indexes listing its installed version (dpkg's status file has
// none), from the guest's apt-cache policy.
func guestAPTInstalledOrigins(ctx context.Context, vm *guestVM, names []string) (map[string][]string, error) {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		if !aptPackageName.MatchString(name) {
			return nil, fmt.Errorf("advisories: invalid APT package name %q", name)
		}
		quoted = append(quoted, nativeQuote(name))
	}
	script := "export LC_ALL=C; apt-cache policy; for p in " + strings.Join(quoted, " ") + "; do printf '@@package %s\\n' \"$p\"; apt-cache policy \"$p\"; done"
	output, err := vm.run(ctx, "sh -c "+nativeQuote(script), nil, 8<<20, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("guest APT policy: %w", err)
	}
	return parseAPTInstalledOrigins(string(output))
}

// parseAPTInstalledOrigins joins the global "Package files:" listing (each
// index line followed by its "release" fields) with each "@@package NAME"
// block's version table, keeping the installed (***) version's indexes.
func parseAPTInstalledOrigins(output string) (map[string][]string, error) {
	global, packages, _ := strings.Cut(output, "\n@@package ")
	indexes := map[string]string{}
	current := ""
	for _, line := range strings.Split(global, "\n") {
		trimmed := strings.TrimSpace(line)
		if release, ok := strings.CutPrefix(trimmed, "release "); ok && current != "" {
			var origin, archive string
			for _, field := range strings.Split(release, ",") {
				if value, ok := strings.CutPrefix(field, "o="); ok {
					origin = value
				} else if value, ok := strings.CutPrefix(field, "a="); ok {
					archive = value
				}
			}
			indexes[current] = origin + "/" + archive
			current = ""
			continue
		}
		if strings.HasSuffix(trimmed, " Packages") {
			current = aptIndexKey(trimmed)
		}
	}
	if len(indexes) == 0 {
		return nil, errors.New("advisories: guest APT policy lists no package index")
	}
	result := map[string][]string{}
	if packages == "" {
		return result, nil
	}
	for _, block := range strings.Split("@@package "+packages, "\n@@package ") {
		header, body, _ := strings.Cut(strings.TrimPrefix(block, "@@package "), "\n")
		name := strings.TrimSpace(header)
		installed, inTable := false, false
		origins := []string{}
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trimmed, "Version table:"):
				inTable = true
			case !inTable:
			case strings.HasPrefix(line, " *** "):
				installed = true
			case strings.HasPrefix(line, "     ") && !strings.HasPrefix(line, "        "):
				installed = false // the next version of the table
			case installed && strings.HasSuffix(trimmed, " Packages"):
				index, ok := indexes[aptIndexKey(trimmed)]
				if !ok {
					return nil, fmt.Errorf("advisories: %s lists an index absent from APT policy: %s", name, trimmed)
				}
				origins = append(origins, index)
			}
		}
		result[name] = origins
	}
	return result, nil
}

// aptIndexKey drops an index line's leading pin priority, which a
// package-specific pin changes in the version table but not the index.
func aptIndexKey(line string) string {
	_, index, _ := strings.Cut(line, " ")
	return index
}
