// SPDX-License-Identifier: Apache-2.0

// Package feed imports distro-authoritative advisory documents and compares native
// package versions. It does not infer binary-to-source mappings, infer module
// streams, authenticate air-gap custody, or decide whether an inventory is clean.
package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/platform"
)

const (
	maxBytes         = 128 << 20
	maxExpandedBytes = 512 << 20
	maxEntries       = 250000
	maxAdvisories    = 500000
	maxRecordBytes   = 2 << 20
)

// Client preserves caller TLS roots and permits at most four HTTPS redirects per
// request. Ordinary acquisition has a two-minute deadline; streaming Red Hat and
// OSV archive refreshes are bounded by the publisher's progress watchdog.
type Client struct {
	http *http.Client
	// archive has no whole-request timeout: large exports (the complete Ubuntu
	// OSV archive is ~780 MB) are bounded by the caller's refresh context and
	// its idle-progress watchdog instead of a fixed two-minute transfer cap.
	archive     *http.Client
	validator   protovalidate.Validator
	signedTrust *vendorTrust
}

func New(client *http.Client) (*Client, error) {
	if client == nil {
		return nil, errors.New("feed: HTTP client required")
	}
	if tr, ok := client.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("feed: insecure TLS configuration")
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&advisoryv1.FeedSource{}, &advisoryv1.Advisory{}))
	if err != nil {
		return nil, fmt.Errorf("feed: compile source validation: %w", err)
	}
	copyClient := *client
	copyClient.Jar = nil
	copyClient.Timeout = 2 * time.Minute
	copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("feed: redirect limit exceeded")
		}
		if err := httpsURL(req.URL); err != nil {
			return err
		}
		return nil
	}
	signedTrust, err := newVendorTrust()
	if err != nil {
		return nil, err
	}
	archiveClient := copyClient
	archiveClient.Timeout = 0
	return &Client{http: &copyClient, archive: &archiveClient, validator: validator, signedTrust: signedTrust}, nil
}

// Fetch materializes a bounded document. Publication of complete OSV ecosystems
// uses FetchStream instead so normalized memory does not grow with the export.
func (c *Client) Fetch(ctx context.Context, config *advisoryv1.FeedSource) (*advisoryv1.FeedDocument, error) {
	if config == nil {
		return nil, errors.New("feed: source required")
	}
	if err := c.validator.Validate(config); err != nil {
		return nil, fmt.Errorf("feed: validate source: %w", err)
	}
	deadline := 2 * time.Minute
	if config.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES || config.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP {
		deadline = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	switch config.GetFormat() {
	case advisoryv1.FeedFormat_FEED_FORMAT_SUSE_OVAL:
		return collectBoundedClaims(func(emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
			return c.fetchSUSEOVAL(ctx, config, emit, nil)
		})
	case advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP:
		return c.fetchOSVArchive(ctx, config, nil, nil)
	case advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES, advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF:
		return collectBoundedClaims(func(emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
			return c.fetchRedHatStream(ctx, config, emit, nil)
		})
	case advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF:
		raw, artifact, signedAt, err := c.fetchSignedCSAF(ctx, config)
		if err != nil {
			return nil, err
		}
		doc, err := parse(config, raw, c.validator)
		if err != nil {
			return nil, err
		}
		if err := bindArtifacts(doc, []*advisoryv1.FeedArtifact{artifact}); err != nil {
			return nil, err
		}
		doc.SnapshotAt = timestamppb.New(signedAt)
		return doc, nil
	}
	bound := int64(maxBytes)
	if config.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD {
		bound = maxRecordBytes
	}
	artifactURL := config.GetUrl()
	raw, err := c.get(ctx, config.GetUrl(), bound)
	if err != nil {
		return nil, err
	}
	if config.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD {
		location, checksum, err := updateLocation(config.GetUrl(), raw)
		if err != nil {
			return nil, err
		}
		artifactURL = location
		raw, err = c.get(ctx, location, maxBytes)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(raw)
		if !bytes.Equal(digest[:], checksum) {
			return nil, errors.New("feed: repomd updateinfo checksum mismatch")
		}
	}
	doc, err := parse(config, raw, c.validator)
	if err != nil {
		return nil, err
	}
	artifacts := []*advisoryv1.FeedArtifact{{Url: artifactURL, Sha256: doc.GetSourceSha256()}}
	if config.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_ARCH_JSON {
		const datesURL = "https://security.archlinux.org/advisories.json"
		dates, err := c.get(ctx, datesURL, maxBytes)
		if err != nil {
			return nil, err
		}
		if err := applyArchAdvisoryDates(doc, dates, c.validator); err != nil {
			return nil, err
		}
		digest := sha256.Sum256(dates)
		artifacts = append(artifacts, &advisoryv1.FeedArtifact{Url: datesURL, Sha256: digest[:]})
	}
	if err := bindArtifacts(doc, artifacts); err != nil {
		return nil, err
	}
	return doc, nil
}

func (c *Client) get(ctx context.Context, location string, bound int64) (raw []byte, err error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("feed: parse URL: %w", err)
	}
	if err := httpsURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("feed: create request: %w", err)
	}
	// Compression is decoded explicitly so the digest always covers vendor bytes.
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed: fetch: %w", err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if resp.TLS == nil || !resp.TLS.HandshakeComplete || len(resp.TLS.VerifiedChains) == 0 {
		return nil, errors.New("feed: response lacks verified TLS")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed: HTTP status %d", resp.StatusCode)
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, errors.New("feed: unsupported HTTP content encoding")
	}
	return boundedRead(resp.Body, bound)
}

func httpsURL(u *url.URL) error {
	if u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("feed: HTTPS URL without credentials or fragment required")
	}
	return nil
}

// Parse is the common online and air-gap parser. RPM_REPOMD imports contain the
// referenced updateinfo bytes, not a repomd document without its companion data.
// Custody/authenticity of offline input remains the importing administrator's job.
// Large OSV publication uses ParseStream; this materialized API retains the
// bounded document limit for callers that need an in-memory normalized snapshot.
func Parse(config *advisoryv1.FeedSource, raw io.Reader) (*advisoryv1.FeedDocument, error) {
	if config == nil || raw == nil {
		return nil, errors.New("feed: source and reader required")
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(config, &advisoryv1.Advisory{}))
	if err != nil {
		return nil, fmt.Errorf("feed: compile source validation: %w", err)
	}
	if err := validator.Validate(config); err != nil {
		return nil, fmt.Errorf("feed: validate source: %w", err)
	}
	if config.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_SUSE_OVAL {
		return collectBoundedClaims(func(emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
			return stageSUSEOVAL(context.Background(), config, validator, raw, emit, nil)
		})
	}
	if config.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP {
		return stageOSVArchive(context.Background(), config, validator, raw, nil, nil)
	}
	data, err := boundedRead(raw, maxBytes)
	if err != nil {
		return nil, err
	}
	return parse(config, data, validator)
}

func parse(config *advisoryv1.FeedSource, raw []byte, validator protovalidate.Validator) (*advisoryv1.FeedDocument, error) {
	digest := sha256.Sum256(raw)
	if pin := config.GetExpectedSha256(); len(pin) != 0 && !bytes.Equal(pin, digest[:]) {
		return nil, errors.New("feed: source checksum mismatch")
	}
	var doc *advisoryv1.FeedDocument
	var err error
	switch config.GetFormat() {
	case advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP:
		doc, err = parseOSV(config, raw, validator)
	case advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO, advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD:
		doc, err = parseUpdateinfo(config, raw, validator)
	case advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF:
		doc, err = parseRedHat(config, raw, validator)
	case advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF:
		doc, err = parseSUSE(config, raw, validator)
	case advisoryv1.FeedFormat_FEED_FORMAT_ARCH_JSON:
		doc, err = parseArch(config, raw, validator)
	case advisoryv1.FeedFormat_FEED_FORMAT_DEBIAN_TRACKER_JSON:
		doc, err = parseDebianTracker(config, raw, validator)
	default:
		err = errors.New("feed: unsupported format")
	}
	if err != nil {
		return nil, err
	}
	doc.SourceSha256 = digest[:]
	return doc, nil
}

func boundedRead(r io.Reader, bound int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, bound+1))
	if err != nil {
		return nil, fmt.Errorf("feed: read document: %w", err)
	}
	if int64(len(data)) > bound {
		return nil, errors.New("feed: document byte limit exceeded")
	}
	return data, nil
}

// Applies binds inventories to configured products. It deliberately does not
// equate a Red Hat minor/EUS release with its major stream or another vendor's build.
// A major-version row's feed configured by that major (the AlmaLinux:N and
// Rocky Linux:N OSV ecosystems) covers each minor VERSION_ID of the row.
func Applies(source *advisoryv1.FeedSource, distro, release, architecture string) bool {
	if source == nil || source.GetDistro() != distro {
		return false
	}
	product := platform.ForFeed(distro, source.GetRelease())
	if !product.Supported(platform.Advisories) {
		return false
	}
	configured, release := product.FeedRelease(source.GetRelease()), product.FeedRelease(release)
	if product.Advisory.PlatformStreams && source.GetPlatformStream() == "standard" && !strings.Contains(configured, ".") {
		release, _, _ = strings.Cut(release, ".")
	}
	if !product.Advisory.PlatformStreams && product.Version.Rule == platform.VersionMajor && configured == product.Version.Value {
		release, _, _ = strings.Cut(release, ".")
	}
	if configured != release {
		return false
	}
	return source.GetArchitecture() == "" || canonicalArch(source.GetArchitecture()) == canonicalArch(architecture)
}

// vendorProduct resolves a feed source to its registry release, which must
// support advisories through the given vendor adapter. No cross-vendor
// inference: a compatible rebuild never borrows another vendor's feed.
func vendorProduct(config *advisoryv1.FeedSource, adapter platform.Feed) (*platform.Release, error) {
	product := platform.ForFeed(config.GetDistro(), config.GetRelease())
	if err := product.Gate(platform.Advisories); err != nil {
		return nil, fmt.Errorf("feed: %w", err)
	}
	if !slices.Contains(product.Advisory.Feeds, adapter) {
		return nil, fmt.Errorf("feed: %s advisories do not cover %s", adapter, product.Name)
	}
	return product, nil
}

// manager is the native version-comparison scheme of the product's packages.
func manager(product *platform.Release) string {
	return string(product.Native().Packages.Backend.PackageDB())
}

func canonicalArch(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return arch
}

func addRecord(doc *advisoryv1.FeedDocument, record *advisoryv1.Advisory, manager string, validator protovalidate.Validator) error {
	if len(doc.Advisories) >= maxAdvisories {
		return errors.New("feed: advisory limit exceeded")
	}
	if err := validator.Validate(record); err != nil {
		return fmt.Errorf("feed: validate normalized advisory: %w", err)
	}
	record.Severity = normalizeSeverity(record.GetSeverity())
	if proto.Size(record) > 64<<10 {
		return errors.New("feed: normalized advisory exceeds storage byte limit")
	}
	for _, version := range []string{record.GetFixedVersion(), record.GetIntroducedVersion(), record.GetLastAffectedVersion()} {
		if version != "" {
			if _, err := Compare(manager, version, version); err != nil {
				return err
			}
		}
	}
	if record.GetFixedVersion() != "" && record.GetLastAffectedVersion() != "" {
		return errors.New("feed: overlapping upper bounds")
	}
	upper := record.GetFixedVersion()
	if upper == "" {
		upper = record.GetLastAffectedVersion()
	}
	if lower := record.GetIntroducedVersion(); lower != "" && upper != "" {
		n, err := Compare(manager, lower, upper)
		if err != nil {
			return err
		}
		if n > 0 || n == 0 && record.GetFixedVersion() != "" {
			return errors.New("feed: inverted advisory range")
		}
	}
	doc.Advisories = append(doc.Advisories, record)
	return nil
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(value) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "negligible", "unimportant":
		return "negligible"
	default:
		return "unknown"
	}
}

// SeverityRank applies the common normalized vendor severity ordering.
func SeverityRank(value string) int {
	switch normalizeSeverity(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "negligible":
		return 1
	default:
		return 0
	}
}

func bindArtifacts(doc *advisoryv1.FeedDocument, artifacts []*advisoryv1.FeedArtifact) error {
	doc.Artifacts = artifacts
	if len(artifacts) == 1 {
		doc.SourceSha256 = artifacts[0].GetSha256()
		return nil
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&advisoryv1.FeedManifest{Artifacts: artifacts})
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	doc.SourceSha256 = digest[:]
	return nil
}
