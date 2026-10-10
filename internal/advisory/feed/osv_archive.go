package feed

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

const (
	defaultOSVArchiveBytes = 1 << 30
	maxOSVRecordBytes      = 4 << 20
	maxOSVExpandedBytes    = 16 << 30
	maxOSVCompressionRatio = 1000
)

func osvArchiveBound(config *advisoryv1.FeedSource) int64 {
	if config.MaxArchiveBytes != nil {
		return int64(config.GetMaxArchiveBytes())
	}
	return defaultOSVArchiveBytes
}

func (c *Client) fetchOSVArchive(ctx context.Context, config *advisoryv1.FeedSource, emit func(*advisoryv1.Advisory) error) (doc *advisoryv1.FeedDocument, err error) {
	file, err := os.CreateTemp("", "lindm-feed-osv-*")
	if err != nil {
		return nil, fmt.Errorf("feed: stage OSV archive: %w", err)
	}
	defer func() {
		err = errors.Join(err, file.Close(), os.Remove(file.Name()))
		if err != nil {
			doc = nil
		}
	}()
	digest, err := c.downloadArchive(ctx, config.GetUrl(), file, osvArchiveBound(config))
	if err != nil {
		return nil, err
	}
	return finishOSVArchive(ctx, config, c.validator, file, digest, emit)
}

func stageOSVArchive(ctx context.Context, config *advisoryv1.FeedSource, validator protovalidate.Validator, input io.Reader, emit func(*advisoryv1.Advisory) error) (doc *advisoryv1.FeedDocument, err error) {
	file, err := os.CreateTemp("", "lindm-feed-osv-*")
	if err != nil {
		return nil, fmt.Errorf("feed: stage OSV archive: %w", err)
	}
	defer func() {
		err = errors.Join(err, file.Close(), os.Remove(file.Name()))
		if err != nil {
			doc = nil
		}
	}()
	hash := sha256.New()
	if err := copyArchive(ctx, io.MultiWriter(file, hash), input, osvArchiveBound(config)); err != nil {
		return nil, err
	}
	return finishOSVArchive(ctx, config, validator, file, hash.Sum(nil), emit)
}

func finishOSVArchive(ctx context.Context, config *advisoryv1.FeedSource, validator protovalidate.Validator, file *os.File, digest []byte, emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
	if pin := config.GetExpectedSha256(); len(pin) != 0 && !bytes.Equal(pin, digest) {
		return nil, errors.New("feed: source checksum mismatch")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	doc, err := parseOSVArchive(ctx, config, file, info.Size(), validator, emit)
	if err != nil {
		return nil, err
	}
	doc.SourceSha256 = digest
	doc.Artifacts = []*advisoryv1.FeedArtifact{{Url: config.GetUrl(), Sha256: digest}}
	return doc, nil
}

func parseOSVArchive(ctx context.Context, config *advisoryv1.FeedSource, input io.ReaderAt, size int64, validator protovalidate.Validator, emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
	ecosystem, err := osvEcosystem(config)
	if err != nil {
		return nil, err
	}
	archive, err := zip.NewReader(input, size)
	if err != nil {
		return nil, fmt.Errorf("feed: open OSV ZIP: %w", err)
	}
	if len(archive.File) == 0 || len(archive.File) > maxEntries {
		return nil, errors.New("feed: OSV ZIP entry limit")
	}
	names := make(map[string]bool, len(archive.File))
	var expanded uint64
	for _, file := range archive.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if !strings.HasSuffix(file.Name, ".json") || path.Base(file.Name) != file.Name || strings.Contains(file.Name, "\\") || names[file.Name] || file.UncompressedSize64 > maxOSVRecordBytes {
			return nil, errors.New("feed: unsupported or duplicate OSV ZIP entry")
		}
		names[file.Name] = true
		if file.UncompressedSize64 > maxOSVExpandedBytes-expanded {
			return nil, errors.New("feed: OSV ZIP expansion limit")
		}
		expanded += file.UncompressedSize64
		if file.UncompressedSize64 > 0 && (file.CompressedSize64 == 0 || file.UncompressedSize64/file.CompressedSize64 > maxOSVCompressionRatio) {
			return nil, errors.New("feed: OSV ZIP compression ratio limit")
		}
	}
	doc := &advisoryv1.FeedDocument{}
	matched := false
	normalized := 0
	rejectedBytes := 0
	var pending advisoryv1.FeedDocument
	var seen map[[sha256.Size]byte]struct{}
	if emit == nil {
		seen = make(map[[sha256.Size]byte]struct{})
	}
	var claims uint64
	claimLimit := totalClaimsLimit(config)
	var encoded []byte
	for _, file := range archive.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if file.FileInfo().IsDir() {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("feed: open OSV ZIP entry: %w", err)
		}
		raw, readErr := boundedRead(contextFeedReader{ctx, reader}, maxOSVRecordBytes)
		if err := errors.Join(readErr, reader.Close()); err != nil {
			return nil, fmt.Errorf("feed: read OSV ZIP entry %s: %w", file.Name, err)
		}
		var scope osvRecordScope
		clear(pending.Advisories)
		pending.Advisories = pending.Advisories[:0]
		ok, recordErr := appendScopedOSV(&pending, config, ecosystem, raw, &scope, validator)
		if recordErr != nil {
			// A source record is atomic: retain none of its partially decoded claims.
			clear(pending.Advisories)
			pending.Advisories = pending.Advisories[:0]
			if err := rejectOSVRecord(doc, &pending, config, ecosystem, file.Name, &scope, recordErr, validator, &rejectedBytes); err != nil {
				return nil, err
			}
		}
		matched = matched || ok
		for _, advisory := range pending.Advisories {
			claims++
			if claims > claimLimit {
				return nil, errors.New("feed: total claims limit exceeded")
			}
			if emit != nil {
				if err := emit(advisory); err != nil {
					return nil, fmt.Errorf("feed: publish OSV claim: %w", err)
				}
				continue
			}
			encoded, err = proto.MarshalOptions{Deterministic: true}.MarshalAppend(encoded[:0], advisory)
			if err != nil {
				return nil, err
			}
			digest := sha256.Sum256(encoded)
			if _, duplicate := seen[digest]; duplicate {
				continue
			}
			if len(doc.Advisories) >= maxAdvisories {
				return nil, errors.New("feed: unique OSV advisory limit exceeded")
			}
			normalized += len(encoded)
			if normalized > maxBytes {
				return nil, errors.New("feed: OSV normalized byte limit")
			}
			seen[digest] = struct{}{}
			doc.Advisories = append(doc.Advisories, advisory)
		}
	}
	if !matched {
		return nil, errors.New("feed: OSV contains no matching supported product")
	}
	u, err := url.Parse(config.GetUrl())
	if err != nil {
		return nil, err
	}
	vendor, _, _ := strings.Cut(ecosystem, ":")
	doc.CompleteSnapshot = u.Host == "osv-vulnerabilities.storage.googleapis.com" && u.Path == "/"+vendor+"/all.zip" && u.RawQuery == "" && config.GetDistro() != "rocky"
	for _, rejected := range doc.RejectedRecords {
		if rejected.Unscoped {
			doc.CompleteSnapshot = false
		}
	}
	return doc, nil
}

// Scope parsing avoids allocating irrelevant native ranges and binary maps.
// A filename is diagnostic context only, never package or release authority.
type osvRecordScope struct {
	ID            string `json:"id"`
	SchemaVersion string `json:"schema_version"`
	Withdrawn     string `json:"withdrawn"`
	Affected      []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	} `json:"affected"`
}

func appendScopedOSV(doc *advisoryv1.FeedDocument, config *advisoryv1.FeedSource, ecosystem string, raw []byte, scope *osvRecordScope, validator protovalidate.Validator) (bool, error) {
	if err := json.Unmarshal(raw, scope); err != nil {
		return false, errors.New("feed: invalid OSV JSON")
	}
	if scope.ID == "" || !strings.HasPrefix(scope.SchemaVersion, "1.") {
		return false, errors.New("feed: unsupported OSV document shape")
	}
	if scope.Withdrawn != "" {
		if _, err := timestamp(scope.Withdrawn); err != nil {
			return false, err
		}
		return false, nil
	}
	if len(scope.Affected) == 0 {
		return false, errors.New("feed: active OSV record lacks affected products")
	}
	relevant := false
	for _, affected := range scope.Affected {
		if affected.Package.Ecosystem == "" {
			return false, errors.New("feed: OSV missing ecosystem")
		}
		if affected.Package.Ecosystem == ecosystem {
			relevant = true
		}
	}
	if !relevant {
		return false, nil
	}
	var record osvRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return true, errors.New("feed: invalid OSV record")
	}
	_, err := appendOSV(doc, config, ecosystem, &record, validator)
	return true, err
}

func rejectOSVRecord(doc, pending *advisoryv1.FeedDocument, config *advisoryv1.FeedSource, ecosystem, filename string, scope *osvRecordScope, recordErr error, validator protovalidate.Validator, rejectedBytes *int) error {
	limit := uint32(1000)
	if config.MaxRejectedRecords != nil {
		limit = config.GetMaxRejectedRecords()
	}
	if uint32(len(doc.RejectedRecords)) >= limit {
		return errors.New("feed: rejected record limit exceeded")
	}
	id := scope.ID
	if id == "" || len(id) > 256 {
		id = strings.TrimSuffix(filename, ".json")
	}
	if len(id) > 256 {
		id = id[:256]
	}
	id = strings.ToValidUTF8(id, "?")
	rejected := &advisoryv1.RejectedRecord{Id: id, Reason: recordErr.Error()}
	if len(rejected.Reason) > 512 {
		rejected.Reason = rejected.Reason[:512]
	}
	for _, affected := range scope.Affected {
		if affected.Package.Ecosystem != "" && affected.Package.Ecosystem != ecosystem {
			continue
		}
		name := affected.Package.Name
		if name == "" || len(name) > 512 || strings.ContainsAny(name, " \t\r\n\v\f/") {
			rejected.Unscoped = true
			continue
		}
		duplicate := false
		for _, present := range rejected.PackageNames {
			if present == name {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(rejected.PackageNames) == 64 {
			rejected.Unscoped = true
			continue
		}
		rejected.PackageNames = append(rejected.PackageNames, name)
	}
	if len(rejected.PackageNames) == 0 {
		rejected.Unscoped = true
	}
	size := proto.Size(rejected) + 8
	if *rejectedBytes+size > 48<<10 {
		return errors.New("feed: rejected record metadata byte limit exceeded")
	}
	*rejectedBytes += size
	doc.RejectedRecords = append(doc.RejectedRecords, rejected)
	// Names alone are enough to withhold a clean assessment, never enough to
	// manufacture a source identity. Match either observed native name dimension.
	for _, name := range rejected.PackageNames {
		for _, source := range []bool{false, true} {
			record := &advisoryv1.Advisory{Id: id, PackageName: name, SourcePackage: source, AssessmentUnknown: true, SourceRecordRejected: true, SourceUrl: config.GetUrl()}
			if err := addRecord(pending, record, managerFor(config.GetDistro()), validator); err != nil {
				return err
			}
		}
	}
	return nil
}
