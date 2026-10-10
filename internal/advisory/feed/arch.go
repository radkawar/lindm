package feed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// These are the vendor's two JSON exports, not lindm serialization contracts.
// all.json omits publication dates, repository identity and package architecture.
// advisories.json supplies dates only for published ASA records.
type archIssue struct {
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	Type       string   `json:"type"`
	Affected   string   `json:"affected"`
	Fixed      string   `json:"fixed"`
	Ticket     string   `json:"ticket"`
	Issues     []string `json:"issues"`
	Advisories []string `json:"advisories"`
}

type archPublishedAdvisory struct {
	Name      string `json:"name"`
	Date      string `json:"date"`
	Group     string `json:"group"`
	Package   string `json:"package"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	Reference string `json:"reference"`
}

func parseArch(config *advisoryv1.FeedSource, raw []byte, validator protovalidate.Validator) (*advisoryv1.FeedDocument, error) {
	if config.GetDistro() != "arch" || config.GetRelease() != "rolling" || canonicalArch(config.GetArchitecture()) != "x86_64" {
		return nil, errors.New("feed: Arch tracker requires arch/rolling/x86_64; derivatives and Arch Linux ARM are not covered")
	}
	// The tracker export filters out packages absent from its current repository
	// cache. It cannot assert coverage of historical, AUR or third-party packages,
	// even when fetched at the canonical all.json URL over authenticated HTTPS.
	doc := &advisoryv1.FeedDocument{}
	seen := make(map[string]bool)
	err := archJSONArray(raw, func(decoder *json.Decoder) error {
		var issue archIssue
		if err := decoder.Decode(&issue); err != nil {
			return fmt.Errorf("feed: decode Arch issue: %w", err)
		}
		if !archID(issue.Name, "AVG-") || seen[issue.Name] || len(issue.Packages) == 0 || len(issue.Issues) == 0 || issue.Affected == "" {
			return errors.New("feed: unsupported or duplicate Arch issue")
		}
		seen[issue.Name] = true
		for _, id := range issue.Advisories {
			if !archAdvisoryID(id) {
				return errors.New("feed: invalid Arch advisory reference")
			}
		}
		if _, err := compareArch(issue.Affected, issue.Affected); err != nil {
			return err
		}
		if issue.Fixed != "" {
			if _, err := compareArch(issue.Fixed, issue.Fixed); err != nil {
				return err
			}
		}
		var fixed, lower, last string
		var unknown, notAffected bool
		switch issue.Status {
		case "Fixed":
			if issue.Fixed == "" {
				return errors.New("feed: fixed Arch issue lacks fixed version")
			}
			n, err := compareArch(issue.Affected, issue.Fixed)
			if err != nil || n >= 0 {
				return errors.New("feed: invalid Arch fixed version boundary")
			}
			// Affected is a known vulnerable build, not an introduction version.
			// Published ASAs describe packages before the fixed build as affected.
			fixed = issue.Fixed
		case "Vulnerable", "Testing":
			// Both statuses affirm the affected build is vulnerable. A fixed
			// field may describe an unreleased or testing-only build, not an
			// available stable fix. Only the known affected build is asserted;
			// other versions remain uncovered by this partial feed.
			lower, last = issue.Affected, issue.Affected
		case "Unknown":
			// A populated fixed field cannot override an undetermined status.
			unknown = true
		case "Not affected":
			notAffected = true
		default:
			return errors.New("feed: unsupported Arch issue status")
		}
		slices.Sort(issue.Issues)
		packages := make(map[string]bool, len(issue.Packages))
		for _, name := range issue.Packages {
			if packages[name] {
				return errors.New("feed: duplicate Arch issue package")
			}
			packages[name] = true
			record := &advisoryv1.Advisory{
				Id: issue.Name, Cves: issue.Issues, PackageName: name,
				FixedVersion: fixed, IntroducedVersion: lower, LastAffectedVersion: last,
				Severity: issue.Severity, SourceUrl: "https://security.archlinux.org/" + issue.Name,
				AssessmentUnknown: unknown, NotAffected: notAffected,
			}
			// No inferred source/binary mapping, per-package architecture, date,
			// repository or acquisition timestamp is added to the vendor record.
			if err := addRecord(doc, record, "pacman", validator); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// applyArchAdvisoryDates joins the independently fetched published-ASA export on
// both AVG and package. The caller retains the supplementary bytes' provenance.
// The vendor supplies a calendar date (also its Atom publication-date source),
// represented at UTC midnight, not an invented time of day. No match leaves nil.
func applyArchAdvisoryDates(doc *advisoryv1.FeedDocument, raw []byte, validator protovalidate.Validator) error {
	if doc == nil {
		return errors.New("feed: Arch document required")
	}
	type key struct{ group, name string }
	records := make(map[key]*advisoryv1.Advisory, len(doc.GetAdvisories()))
	for _, record := range doc.GetAdvisories() {
		records[key{record.GetId(), record.GetPackageName()}] = record
	}
	seen := make(map[string]bool)
	return archJSONArray(raw, func(decoder *json.Decoder) error {
		var published archPublishedAdvisory
		if err := decoder.Decode(&published); err != nil {
			return fmt.Errorf("feed: decode Arch published advisory: %w", err)
		}
		if !archAdvisoryID(published.Name) || !archID(published.Group, "AVG-") || published.Package == "" || seen[published.Name] {
			return errors.New("feed: unsupported or duplicate Arch published advisory")
		}
		seen[published.Name] = true
		date, err := time.Parse("2006-01-02", published.Date)
		if err != nil {
			return fmt.Errorf("feed: invalid Arch advisory date: %w", err)
		}
		record := records[key{published.Group, published.Package}]
		if record == nil {
			return nil
		}
		if record.GetPublishedAt() != nil && !date.Before(record.GetPublishedAt().AsTime()) {
			return nil
		}
		record.PublishedAt = timestamppb.New(date)
		record.SourceUrl = "https://security.archlinux.org/" + published.Name
		if err := validator.Validate(record); err != nil {
			return fmt.Errorf("feed: validate dated Arch advisory: %w", err)
		}
		return nil
	})
}

// archJSONArray bounds both vendor exports and rejects concatenated JSON, empty
// snapshots, unknown fields (which might introduce applicability constraints),
// and oversized entries. The caller's raw input is already globally bounded;
// decode one entry at a time rather than allocating an entire record array.
func archJSONArray(raw []byte, consume func(*json.Decoder) error) error {
	if len(raw) > maxBytes {
		return errors.New("feed: Arch document byte limit exceeded")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return errors.New("feed: Arch JSON array required")
	}
	count := 0
	for decoder.More() {
		if count >= maxEntries {
			return errors.New("feed: Arch entry limit exceeded")
		}
		start := decoder.InputOffset()
		if err := consume(decoder); err != nil {
			return err
		}
		if decoder.InputOffset()-start > maxRecordBytes {
			return errors.New("feed: Arch record byte limit exceeded")
		}
		count++
	}
	if count == 0 {
		return errors.New("feed: empty Arch export cannot establish coverage")
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
		return errors.New("feed: unterminated Arch JSON array")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("feed: trailing Arch JSON content")
	}
	return nil
}

func archID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return false
	}
	for i := len(prefix); i < len(value); i++ {
		if !digit(value[i]) {
			return false
		}
	}
	return true
}

func archAdvisoryID(value string) bool {
	if !strings.HasPrefix(value, "ASA-") {
		return false
	}
	month, number, ok := strings.Cut(value[4:], "-")
	return ok && len(month) == 6 && archID(month, "") && archID(number, "")
}
