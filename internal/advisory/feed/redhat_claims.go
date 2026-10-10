package feed

import (
	"errors"
	"fmt"
	"strings"

	"buf.build/go/protovalidate"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// redHatVulnerabilityClaims preserves vendor applicability and status policy;
// only the acquisition and retention of CSAF wire data are incremental.
func redHatVulnerabilityClaims(config *advisoryv1.FeedSource, notice *suseCSAF, vulnerability redHatVulnerability, products map[string]redHatProduct, relations map[string]redHatRelationship, validator protovalidate.Validator, emit func(*advisoryv1.Advisory) error) error {
	if !validCVE(vulnerability.CVE) {
		return errors.New("feed: Red Hat vulnerability lacks valid CVE")
	}
	d := &notice.Document
	published, err := timestamp(d.Tracking.Published)
	if err != nil {
		return err
	}
	var scopeMemo map[string]redHatScopeProof
	// Fixed statuses precede bare affected claims. The disk stager reconciles
	// the complete source, including fixes in another advisory or archive.
	for _, status := range []string{"fixed", "known_affected", "known_not_affected", "under_investigation"} {
		for _, id := range vulnerability.Status[status] {
			relation, exists := relations[id]
			if !exists {
				if redHatOffScopeProduct(config, id, products) {
					continue
				}
				return errors.New("feed: unresolved Red Hat vulnerability relationship")
			}
			if relation.ambiguous {
				if redHatReferenceOffScope(config, id, products, relations, 0, &scopeMemo) {
					continue
				}
				return errRedHatAmbiguousIdentity
			}
			platform, module, err := redHatPlatformProduct(relation.Platform, products, relations, 0)
			if err != nil {
				if errors.Is(err, errRedHatAmbiguousIdentity) && redHatReferenceOffScope(config, id, products, relations, 0, &scopeMemo) {
					continue
				}
				return err
			}
			applies, uncertain := redHatPlatform(config, platform, status)
			if !applies {
				continue
			}
			if relation.Category != "default_component_of" || products[platform.ID].unsupported {
				return errors.New("feed: unsupported relevant Red Hat product relationship")
			}
			component, exists := products[relation.Component]
			if !exists {
				return errors.New("feed: unresolved Red Hat RPM component")
			}
			if component.ambiguous {
				return errRedHatAmbiguousIdentity
			}
			if component.unsupported {
				return errors.New("feed: unsupported relevant Red Hat component constraint")
			}
			// The PURL namespace, not a product label or path suffix,
			// distinguishes native RPMs from layered content.
			pkg, err := redHatPackage(component)
			if errors.Is(err, errRedHatNonNativeRPM) {
				continue
			}
			if err != nil {
				return err
			}
			if module != "" {
				name, stream, err := redHatModule(module)
				if err != nil || (pkg.module != "" && (pkg.module != name || pkg.stream != stream)) {
					return errors.New("feed: conflicting Red Hat module relationship")
				}
				pkg.module, pkg.stream = name, stream
			}
			if pkg.arch != "" && pkg.arch != "noarch" && !pkg.source && pkg.arch != canonicalArch(config.GetArchitecture()) {
				continue
			}
			record := &advisoryv1.Advisory{Id: d.Tracking.ID, Cves: []string{vulnerability.CVE}, PackageName: pkg.name, SourcePackage: pkg.source, Architecture: pkg.arch, Severity: d.Severity.Text, PublishedAt: published, SourceUrl: config.GetUrl(), PlatformRelease: config.GetRelease(), PlatformStream: config.GetPlatformStream(), ModuleName: pkg.module, ModuleStream: pkg.stream}
			if pkg.source {
				record.Architecture = ""
			}
			switch status {
			case "fixed":
				if pkg.version == "" {
					return errors.New("feed: Red Hat fixed RPM lacks exact EVR")
				}
				record.FixedVersion = pkg.version
			case "known_affected":
				// Vendor unfixed status applies to the package/source in this
				// platform, even when its component PURL includes a version.
				// Source-wide reconciliation still gives exact fixes priority.
			case "known_not_affected":
				record.NotAffected = !uncertain
				if pkg.version != "" {
					record.IntroducedVersion, record.LastAffectedVersion = pkg.version, pkg.version
				}
			}
			record.AssessmentUnknown = uncertain || status == "under_investigation"
			// Reuse the shared normalized-record validation without retaining
			// an advisory-sized document or bypassing native RPM bounds.
			var storage [1]*advisoryv1.Advisory
			one := advisoryv1.FeedDocument{Advisories: storage[:0]}
			if err := addRecord(&one, record, "rpm", validator); err != nil {
				return err
			}
			if err := emit(record); err != nil {
				return err
			}
		}
	}
	for status, ids := range vulnerability.Status {
		if status == "fixed" || status == "known_affected" || status == "known_not_affected" || status == "under_investigation" {
			continue
		}
		for _, id := range ids {
			relation, ok := relations[id]
			if !ok {
				if redHatOffScopeProduct(config, id, products) {
					continue
				}
				return errors.New("feed: unresolved Red Hat status product")
			}
			if relation.ambiguous {
				if redHatReferenceOffScope(config, id, products, relations, 0, &scopeMemo) {
					continue
				}
				return errRedHatAmbiguousIdentity
			}
			platform, _, err := redHatPlatformProduct(relation.Platform, products, relations, 0)
			if err != nil {
				if errors.Is(err, errRedHatAmbiguousIdentity) && redHatReferenceOffScope(config, id, products, relations, 0, &scopeMemo) {
					continue
				}
				return err
			}
			if applies, _ := redHatPlatform(config, platform, "under_investigation"); applies {
				return fmt.Errorf("feed: unsupported relevant Red Hat status %q", status)
			}
		}
	}
	return nil
}

type redHatScopeProof struct {
	offScope bool
	distance uint8
}

// An ambiguous dependency is irrelevant only when every declared alternative
// reaches a well-formed off-scope platform. Unknown identifiers and cycles do
// not prove that a competing native interpretation is absent.
func redHatReferenceOffScope(config *advisoryv1.FeedSource, id string, products map[string]redHatProduct, relations map[string]redHatRelationship, depth int, memo *map[string]redHatScopeProof) bool {
	if depth > 8 {
		return false
	}
	if known, exists := (*memo)[id]; exists {
		return known.offScope && depth+int(known.distance) <= 8
	}
	if *memo == nil {
		*memo = make(map[string]redHatScopeProof)
	}
	// A pending/failed proof is false, so cycles cannot prove scope. The
	// vulnerability-local cache visits each indexed identifier at most once,
	// rather than expanding shared alternative paths exponentially.
	(*memo)[id] = redHatScopeProof{}
	var distance uint8
	found := false
	if _, exists := products[id]; exists {
		found = true
		if !redHatOffScopeProduct(config, id, products) {
			return false
		}
	}
	if relation, exists := relations[id]; exists {
		found = true
		if !redHatReferenceOffScope(config, relation.Platform, products, relations, depth+1, memo) {
			return false
		}
		distance = (*memo)[relation.Platform].distance + 1
		for platform := range relation.platforms {
			if !redHatReferenceOffScope(config, platform, products, relations, depth+1, memo) {
				return false
			}
			distance = max(distance, (*memo)[platform].distance+1)
		}
	}
	(*memo)[id] = redHatScopeProof{offScope: found, distance: distance}
	return found
}

// A VEX status can name a declared platform directly, not just a package
// relationship. Only an explicit, well-formed off-scope CPE makes that reference
// irrelevant. Missing declarations, RPM-only products, malformed/unsupported CPE
// syntax and relevant broad-platform claims still fail: none identifies a host
// package for which we can safely synthesize an affected or clean assertion.
func redHatOffScopeProduct(config *advisoryv1.FeedSource, id string, products map[string]redHatProduct) bool {
	product, exists := products[id]
	if !exists {
		return false
	}
	if !redHatOffScopePlatform(config, product.product) {
		return false
	}
	for cpe := range product.cpes {
		alternative := product.product
		alternative.Helper.CPE = cpe
		if !redHatOffScopePlatform(config, alternative) {
			return false
		}
	}
	return true
}

func redHatOffScopePlatform(config *advisoryv1.FeedSource, product suseProduct) bool {
	cpe := strings.Split(product.Helper.CPE, ":")
	if len(cpe) < 4 || len(cpe) > 7 || cpe[0] != "cpe" || (cpe[1] != "/o" && cpe[1] != "/a") || cpe[2] != "redhat" || cpe[3] == "" {
		return false
	}
	// The supported unescaped URI binding is intentionally conservative:
	// an escaped, wildcard or malformed CPE is uncertainty, not proof that the
	// claimed platform is unrelated to the configured host.
	for index, part := range cpe[2:] {
		for _, char := range part {
			// Version/update/edition strings may contain uppercase letters
			// (the vendor publishes AMQ 2026.Q3). Never case-fold identity.
			if index >= 2 && char >= 'A' && char <= 'Z' {
				continue
			}
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' && char != '-' && char != '.' {
				return false
			}
		}
	}
	switch cpe[3] {
	case "enterprise_linux", "rhel_eus", "enterprise_linux_eus", "rhel_e4s", "enterprise_linux_e4s":
		if len(cpe) < 5 || cpe[4] == "" {
			return false
		}
		release := strings.Split(cpe[4], ".")
		if len(release) > 2 || !suseDigits(release[0]) || (len(release) == 2 && !suseDigits(release[1])) {
			return false
		}
	default:
		// A different product remains off-scope when its URI binding omits
		// version (ANY). Native RHEL's absent version cannot prove scope.
		return true
	}
	// Unknown update/edition qualifiers must not turn an otherwise relevant
	// native platform into an off-scope assertion.
	baseBytes := 4
	for _, part := range cpe[:5] {
		baseBytes += len(part)
	}
	product.Helper.CPE = product.Helper.CPE[:baseBytes]
	applies, _ := redHatPlatform(config, product, "under_investigation")
	return !applies
}
