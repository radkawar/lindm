// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"buf.build/go/protovalidate"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/platform"
)

// These wire types belong to Debian's security-tracker export, not lindm's
// normalized contract. repositories contains current archive source versions,
// not a binary map or the first fixed version. The export has no timestamps.
type debianTrackerIssue struct {
	Description string                          `json:"description"`
	DebianBug   int64                           `json:"debianbug"`
	Scope       string                          `json:"scope"`
	Releases    map[string]debianTrackerRelease `json:"releases"`
}

type debianTrackerRelease struct {
	Status          string            `json:"status"`
	Repositories    map[string]string `json:"repositories"`
	FixedVersion    *string           `json:"fixed_version"`
	Urgency         string            `json:"urgency"`
	NoDSA           string            `json:"nodsa"`
	NoDSAReason     string            `json:"nodsa_reason"`
	NextPointUpdate bool              `json:"next_point_update"`
}

func parseDebianTracker(config *advisoryv1.FeedSource, raw []byte, validator protovalidate.Validator) (*advisoryv1.FeedDocument, error) {
	product, err := vendorProduct(config, platform.FeedDebianTracker)
	if err != nil {
		return nil, err
	}
	release := product.Codename
	if len(raw) > maxBytes {
		return nil, errors.New("feed: Debian tracker document byte limit exceeded")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// An unknown field could carry a native applicability constraint. Do not
	// silently drop it and widen the vendor's assessment.
	decoder.DisallowUnknownFields()
	if err := debianTrackerDelimiter(decoder, '{'); err != nil {
		return nil, err
	}
	// Even the full export is not a package-universe coverage assertion: it
	// contains tracked source-package issues, not untracked/removed packages.
	doc := &advisoryv1.FeedDocument{}
	packages := make(map[string]bool)
	entries := 0
	for decoder.More() {
		name, err := debianTrackerKey(decoder)
		if err != nil {
			return nil, err
		}
		if packages[name] || len(packages) >= maxEntries {
			return nil, errors.New("feed: duplicate Debian source package or package limit exceeded")
		}
		packages[name] = true
		if err := debianTrackerDelimiter(decoder, '{'); err != nil {
			return nil, err
		}
		issues := make(map[string]bool)
		for decoder.More() {
			id, err := debianTrackerKey(decoder)
			if err != nil {
				return nil, err
			}
			if issues[id] || entries >= maxEntries {
				return nil, errors.New("feed: duplicate Debian tracker issue or issue limit exceeded")
			}
			issues[id] = true
			entries++
			if !validCVE(id) && !strings.HasPrefix(id, "TEMP-") {
				return nil, errors.New("feed: unsupported Debian tracker issue identifier")
			}
			// Decode one issue at a time: large packages such as linux can
			// exceed the per-record bound without any individual issue doing so.
			start := decoder.InputOffset()
			var issue debianTrackerIssue
			if err := decoder.Decode(&issue); err != nil {
				return nil, fmt.Errorf("feed: decode Debian tracker %s/%s: %w", name, id, err)
			}
			if decoder.InputOffset()-start > maxRecordBytes {
				return nil, errors.New("feed: Debian tracker issue byte limit exceeded")
			}
			if len(issue.Releases) == 0 {
				return nil, errors.New("feed: Debian tracker issue lacks releases")
			}
			assessment, ok := issue.Releases[release]
			if !ok {
				continue
			}
			if err := appendDebianTracker(doc, name, id, assessment, validator); err != nil {
				return nil, fmt.Errorf("feed: Debian tracker %s/%s: %w", name, id, err)
			}
		}
		if err := debianTrackerDelimiter(decoder, '}'); err != nil {
			return nil, err
		}
	}
	if err := debianTrackerDelimiter(decoder, '}'); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("feed: trailing Debian tracker data")
	}
	if len(doc.GetAdvisories()) == 0 {
		return nil, errors.New("feed: Debian tracker contains no matching supported release")
	}
	return doc, nil
}

func appendDebianTracker(doc *advisoryv1.FeedDocument, name, id string, release debianTrackerRelease, validator protovalidate.Validator) error {
	if len(release.Repositories) == 0 {
		return errors.New("release lacks source repositories")
	}
	record := &advisoryv1.Advisory{
		Id:            id,
		PackageName:   name,
		SourcePackage: true,
		Severity:      release.Urgency,
		SourceUrl:     "https://security-tracker.debian.org/tracker/" + url.PathEscape(id),
	}
	if validCVE(id) {
		record.Cves = []string{id}
	}
	switch release.Status {
	case "resolved":
		if release.FixedVersion == nil || *release.FixedVersion == "" {
			return errors.New("resolved issue lacks fixed version")
		}
		if *release.FixedVersion == "0" {
			record.NotAffected = true
		} else {
			record.FixedVersion = *release.FixedVersion
		}
	case "open", "undetermined":
		if release.FixedVersion != nil {
			return errors.New("unresolved issue contains contradictory fixed version")
		}
		record.AssessmentUnknown = release.Status == "undetermined"
	default:
		return errors.New("unsupported release status")
	}
	// No-DSA/ignored/postponed are update policies, not fixes. Likewise,
	// unimportant is not a package-wide clean claim (it can denote packages
	// outside security support). Preserve severity via the shared normalizer.
	// Architecture and publication date remain absent: the vendor supplies none.
	return addRecord(doc, record, "dpkg", validator)
}

func debianTrackerDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("feed: decode Debian tracker object: %w", err)
	}
	if token != want {
		return errors.New("feed: invalid Debian tracker object shape")
	}
	return nil
}

func debianTrackerKey(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", fmt.Errorf("feed: decode Debian tracker key: %w", err)
	}
	key, ok := token.(string)
	if !ok || key == "" {
		return "", errors.New("feed: invalid Debian tracker object key")
	}
	return key, nil
}
