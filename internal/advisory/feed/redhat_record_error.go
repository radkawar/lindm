// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"errors"
	"net/url"
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
	if len(record.PackageNames) == 4096 {
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

// Inspect every status, including the valid prefix of a subsequently rejected
// document. Package names here are quarantine scope, never recovered RPM claims.
// A single unresolved relevant reference makes the whole rejection unscoped.
func (e *redHatRejectedRecordError) includeRejectedPackages(ctx context.Context, config *advisoryv1.FeedSource, vulnerability redHatVulnerability, products map[string]redHatProduct, relations map[string]redHatRelationship) error {
	var memo map[string]redHatScopeProof
	for _, ids := range vulnerability.Status {
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			if redHatReferenceOffScope(config, id, products, relations, 0, &memo) {
				continue
			}
			relation, declared := relations[id]
			if !declared || relation.ambiguous {
				e.record.Unscoped = true
				continue
			}
			platform, module, err := redHatPlatformProduct(relation.Platform, products, relations, 0)
			if err != nil {
				e.record.Unscoped = true
				continue
			}
			if applies, _ := redHatPlatform(config, platform, "under_investigation"); !applies {
				e.record.Unscoped = true
				continue
			}
			component, exists := products[relation.Component]
			if !exists || component.unsupported || component.ambiguous || products[platform.ID].unsupported || relation.Category != "default_component_of" {
				e.record.Unscoped = true
				continue
			}
			pkg, err := redHatPackage(component)
			if errors.Is(err, errRedHatNonNativeRPM) {
				continue
			}
			if !redHatRejectedName(pkg.name) {
				bounded, err := e.includeRejectedModuleFamily(ctx, config, component, module, products, relations)
				if err != nil {
					return err
				}
				if !bounded {
					e.record.Unscoped = true
				}
				continue
			}
			redHatRejectedPackageName(e.record, pkg.name)
			// A broken EVR/architecture cannot change an already established
			// native name. Module ambiguity, however, is not a scope proof.
			if err != nil {
				_, query, _ := strings.Cut(component.product.Helper.PURL, "?")
				qualifiers, queryErr := url.ParseQuery(query)
				if value := qualifiers.Get("rpmmod"); value != "" {
					name, stream, moduleErr := redHatModule(value)
					if moduleErr != nil {
						e.record.Unscoped = true
					} else {
						pkg.module, pkg.stream = name, stream
					}
				}
				if queryErr != nil {
					e.record.Unscoped = true
				}
			}
			if module != "" {
				name, stream, moduleErr := redHatModule(module)
				if moduleErr != nil || (pkg.module != "" && (pkg.module != name || pkg.stream != stream)) {
					e.record.Unscoped = true
				}
			}
		}
	}
	return nil
}

func redHatRejectedName(name string) bool {
	if name == "" || len(name) > 512 {
		return false
	}
	for _, char := range name {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '+' && char != '-' && char != '_' && char != '.' {
			return false
		}
	}
	return true
}

// This recognizes quarantine module scope, never an RPM identity. Each marker's
// own NS and source qualifier must be valid and agree with its enclosing edge.
func redHatRejectedModuleMarker(component redHatProduct, enclosingModule string) (string, bool) {
	raw, native := strings.CutPrefix(component.product.Helper.PURL, "pkg:rpm/redhat/")
	identity, query, _ := strings.Cut(raw, "?")
	marker, err := url.PathUnescape(identity)
	if !native || err != nil || strings.ContainsAny(marker, "/@%") {
		return "", false
	}
	name, markerStream, err := redHatModule(marker)
	q, queryErr := url.ParseQuery(query)
	if err != nil || !redHatRejectedName(name) || queryErr != nil || len(q) != 1 || len(q["arch"]) != 1 || q.Get("arch") != "src" || (component.arch != "" && component.arch != "src") {
		return "", false
	}
	if enclosingModule != "" {
		moduleName, stream, err := redHatModule(enclosingModule)
		if err != nil || moduleName != name || stream != markerStream {
			return "", false
		}
	}
	return name, true
}

// Some vendor source components contain a module NS in the RPM-name position.
// This is NOT a valid RPM identity. Only independently declared native source
// RPMs and module relationships can bound its quarantine to a component family.
// Use every declared stream of that family, not a guessed name prefix or a
// manufactured RPM obtained by stripping the colon.
func (e *redHatRejectedRecordError) includeRejectedModuleFamily(ctx context.Context, config *advisoryv1.FeedSource, component redHatProduct, enclosingModule string, products map[string]redHatProduct, relations map[string]redHatRelationship) (bool, error) {
	name, bounded := redHatRejectedModuleMarker(component, enclosingModule)
	if !bounded {
		return false, nil
	}
	// The independent source RPM must establish both the component name and
	// its module family. A display label or an unrelated package's rpmmod
	// qualifier does not prove that this malformed marker denotes a source.
	proved := false
	var memo map[string]redHatScopeProof
	for id, relation := range relations {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if redHatReferenceOffScope(config, id, products, relations, 0, &memo) {
			continue
		}
		// Ambiguity is checked before selecting a family. The index retains
		// only the first component/edge, so a hidden alternative could belong
		// to this family even when the retained declaration does not.
		if relation.ambiguous || relation.Category != "default_component_of" {
			e.record.Unscoped = true
			continue
		}
		platform, module, err := redHatPlatformProduct(relation.Platform, products, relations, 0)
		if err != nil || products[platform.ID].unsupported {
			e.record.Unscoped = true
			continue
		}
		if applies, _ := redHatPlatform(config, platform, "under_investigation"); !applies {
			e.record.Unscoped = true
			continue
		}
		other, exists := products[relation.Component]
		if !exists || other.unsupported || other.ambiguous {
			e.record.Unscoped = true
			continue
		}
		pkg, packageErr := redHatPackage(other)
		if errors.Is(packageErr, errRedHatNonNativeRPM) {
			continue
		}
		if !redHatRejectedName(pkg.name) {
			// Other well-shaped markers cannot hide members of this family:
			// its independent source proof covers all of its streams. A
			// different family is proved separately if a status names it.
			if _, bounded := redHatRejectedModuleMarker(other, module); !bounded {
				e.record.Unscoped = true
			}
			continue
		}
		if packageErr != nil && pkg.module == "" {
			// EVR/architecture failures may occur before rpmmod is parsed.
			// Preserve the authoritative native name without repairing a
			// package claim; malformed module authority stays unscoped.
			_, query, _ := strings.Cut(other.product.Helper.PURL, "?")
			qualifiers, queryErr := url.ParseQuery(query)
			if queryErr != nil {
				e.record.Unscoped = true
				continue
			}
			if value := qualifiers.Get("rpmmod"); value != "" {
				var moduleErr error
				pkg.module, pkg.stream, moduleErr = redHatModule(value)
				if moduleErr != nil {
					e.record.Unscoped = true
					continue
				}
			}
		}
		if module != "" {
			moduleName, stream, err := redHatModule(module)
			if err != nil || (pkg.module != "" && (pkg.module != moduleName || pkg.stream != stream)) {
				e.record.Unscoped = true
				continue
			}
			pkg.module = moduleName
		}
		if pkg.module == name || (pkg.source && pkg.name == name) {
			redHatRejectedPackageName(e.record, pkg.name)
			if packageErr == nil && pkg.module == name && pkg.source && pkg.name == name {
				proved = true
			}
		}
	}
	return proved, nil
}
