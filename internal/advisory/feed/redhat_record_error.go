// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// A sink failure is never a vendor-record rejection, even when the sink's own
// error chain happens to contain a redHatRejectedRecordError. Acquisition must
// test this marker before considering any vendor error in its unwrap chain.
type redHatSinkError struct {
	cause error
}

func (e *redHatSinkError) Error() string { return e.cause.Error() }
func (e *redHatSinkError) Unwrap() error { return e.cause }

func redHatBoundedDiagnostic(value string, bound int) string {
	if len(value) <= bound {
		return value
	}
	value = value[:bound]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func redHatMetadataRejection(notice *suseCSAF, cause error) *redHatRejectedRecordError {
	return &redHatRejectedRecordError{
		record: &advisoryv1.RejectedRecord{
			Id:       redHatBoundedDiagnostic(notice.Document.Tracking.ID, 256),
			Reason:   redHatBoundedDiagnostic(cause.Error(), 512),
			Unscoped: true,
		},
		cause: cause,
	}
}

// Retain a deterministic bounded set, even if a large document exceeds the
// scoped-name allowance. Unscoped then preserves uncertainty for omitted names.
func redHatRejectedPackageName(record *advisoryv1.RejectedRecord, name string) {
	index, exists := slices.BinarySearch(record.PackageNames, name)
	if exists {
		return
	}
	if len(record.PackageNames) == 64 {
		record.Unscoped = true
		if index == len(record.PackageNames) {
			return
		}
	} else {
		record.PackageNames = append(record.PackageNames, "")
	}
	copy(record.PackageNames[index+1:], record.PackageNames[index:len(record.PackageNames)-1])
	record.PackageNames[index] = name
}

// Continue inspecting the remaining statuses after a semantic failure, retaining
// only offending literal native PURL names that were parsed before a later
// constraint failed. Never recover a name from a slash namespace, label or ID.
// Unscoped remains true: the entire document, including its valid prefix and
// unnamed failures, is removed. A partial name list cannot imply clean coverage.
func (e *redHatRejectedRecordError) includeRejectedPackages(ctx context.Context, config *advisoryv1.FeedSource, vulnerability redHatVulnerability, products map[string]redHatProduct, relations map[string]redHatRelationship) error {
	for _, ids := range vulnerability.Status {
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			relation, declared := relations[id]
			if !declared {
				continue
			}
			platform, _, err := redHatPlatformProduct(relation.Platform, products, relations, 0)
			if err != nil {
				continue
			}
			if applies, _ := redHatPlatform(config, platform, "under_investigation"); !applies {
				continue
			}
			component, exists := products[relation.Component]
			if !exists || component.unsupported || component.ambiguous || products[platform.ID].unsupported || relation.Category != "default_component_of" {
				continue
			}
			pkg, err := redHatPackage(component)
			if err == nil || pkg.name == "" || len(pkg.name) > 512 || strings.ContainsAny(pkg.name, " \t\r\n\v\f/") {
				continue
			}
			redHatRejectedPackageName(e.record, pkg.name)
		}
	}
	return nil
}
