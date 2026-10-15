// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/google/uuid"

	"lindm/internal/advisory/advisorydb"
	"lindm/internal/platform"
	"lindm/internal/rpmauthority"
)

var errSnapshotPosition = errors.New("advisory: snapshot position out of range")

const (
	// maxSnapshotPositions mirrors snapshot_packages_position_check.
	maxSnapshotPositions = 100000
	// uncoveredPage bounds one uncovered-package page while matching.
	uncoveredPage = 5000
)

// originCoverage restricts matching to independently proved package authority.
// Derivatives require every APT listing to be a verified covered base-archive
// index, and always remain PARTIAL because their own vendor has no feed.
// Native RHEL requires a verified immutable RPM identity plus an exact product
// declaration; it is PARTIAL only when some installed packages are uncovered.
// Neither policy infers authority from names, display vendors or ID_LIKE.
type originCoverage struct {
	base   *platform.Release
	reason string
	vendor []string
	rpm    bool
}

// derivativeCoverage retains the existing derivative policy selector and also
// selects the bounded native-RHEL policy for exact supported registry rows.
func derivativeCoverage(host *platform.Release) *originCoverage {
	if host != nil && host.Advisory.RPMHeaderAuthority {
		return &originCoverage{base: host, reason: "rhel_package_coverage_incomplete", rpm: true}
	}
	base := host.BaseCoverage()
	if base == nil {
		return nil
	}
	return &originCoverage{base: base, reason: "vendor_feed_unavailable_" + host.ID, vendor: host.Advisory.VendorOrigins}
}

// feedIdentity is the os-release identity feeds are selected and their
// architectures checked against: the base release for a derivative.
func feedIdentity(coverage *originCoverage, osID, version string) (string, string) {
	if coverage == nil || coverage.rpm {
		return osID, version
	}
	return coverage.base.ID, coverage.base.Version.Value
}

func (c *originCoverage) uncoveredParams(snapshot uuid.UUID, after, limit int32) advisorydb.ListAdvisoryUncoveredPackagesParams {
	a := c.base.Advisory
	return advisorydb.ListAdvisoryUncoveredPackagesParams{
		Origin: a.ArchiveOrigin, Codename: c.base.Codename, Suites: a.ArchiveSuites, Signers: a.ArchiveSigners, VendorOrigins: c.vendor,
		SnapshotID: snapshot, AfterPosition: after, RowLimit: limit,
	}
}

// setDigest keys a finding set matched under this coverage: the policy, the
// package rows and their origin evidence. It never equals a complete match's
// package digest, so base and derivative devices never share a set.
func (c *originCoverage) setDigest(packageDigest, originDigest []byte) []byte {
	if c.rpm {
		h := sha256.New()
		_, _ = h.Write([]byte("lindm-rhel-immutable-rpm-exact-product-v1\x00" + c.base.Key + "\x00"))
		root, valid := rpmauthority.PolicyIdentity()
		_, _ = h.Write(root[:])
		if valid {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write(packageDigest)
		return h.Sum(nil)
	}
	a := c.base.Advisory
	h := sha256.New()
	for _, part := range []string{"lindm-origin-coverage", a.ArchiveOrigin, c.base.Codename, strings.Join(a.ArchiveSuites, ","), strings.Join(a.ArchiveSigners, ","), strings.Join(c.vendor, ",")} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	_, _ = h.Write(packageDigest)
	_, _ = h.Write(originDigest)
	return h.Sum(nil)
}

// uncovered pages the snapshot's uncovered positions into a bitmap. The
// policy argument is the registry's; reasons are recomputed by the read path.
func (c *originCoverage) uncovered(ctx context.Context, q *advisorydb.Queries, snapshot uuid.UUID) ([]bool, int32, error) {
	positions := make([]bool, maxSnapshotPositions)
	var count int32
	after := int32(-1)
	for {
		rows, err := q.ListAdvisoryUncoveredPackages(ctx, c.uncoveredParams(snapshot, after, uncoveredPage))
		if err != nil {
			return nil, 0, err
		}
		for _, row := range rows {
			if row.Position < 0 || row.Position >= maxSnapshotPositions {
				return nil, 0, errSnapshotPosition
			}
			positions[row.Position] = true
			count++
		}
		if len(rows) < uncoveredPage {
			return positions, count, nil
		}
		after = rows[len(rows)-1].Position
	}
}
