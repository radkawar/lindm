package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// ErrOfflineUnsupported reports a feed format that cannot be carried in an
// offline bundle as one primary byte stream.
var ErrOfflineUnsupported = errors.New("feed: offline_snapshot_unsupported")

// Acquisition describes authenticated online acquisition of one feed snapshot.
type Acquisition struct {
	// Artifacts lists every vendor artifact fetched (URL, SHA-256, signer
	// fingerprint when verified); Artifacts[0] is the primary bytes written to
	// output.
	Artifacts []*advisoryv1.FeedArtifact
	// SnapshotAt is the vendor-signed snapshot time when the format has one.
	SnapshotAt *time.Time
}

// Acquire fetches exactly the primary bytes that ParseStream accepts for source
// and streams them to output without parsing claims into memory beyond the
// bounds Fetch already applies. Nothing is written to output unless every
// online check (TLS, vendor checksum or signature, configured pin) passed.
func (c *Client) Acquire(ctx context.Context, source *advisoryv1.FeedSource, output io.Writer) (*Acquisition, error) {
	if source == nil || output == nil {
		return nil, errors.New("feed: source and output required")
	}
	if err := c.validator.Validate(source); err != nil {
		return nil, fmt.Errorf("feed: validate source: %w", err)
	}
	deadline := 2 * time.Minute
	if source.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP {
		// Station acquisition of complete ecosystem exports (hundreds of MiB)
		// is bounded by bytes and this deadline, not by link speed.
		deadline = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	switch source.GetFormat() {
	case advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF, advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES:
		return nil, ErrOfflineUnsupported
	case advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP:
		return c.acquireArchive(ctx, source, output, osvArchiveBound(source))
	case advisoryv1.FeedFormat_FEED_FORMAT_SUSE_OVAL:
		return c.acquireArchive(ctx, source, output, ovalArchiveBound(source))
	case advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF:
		raw, artifact, signedAt, err := c.fetchSignedCSAF(ctx, source)
		if err != nil {
			return nil, err
		}
		if err := writeAcquired(output, raw, artifact.GetSha256()); err != nil {
			return nil, err
		}
		return &Acquisition{Artifacts: []*advisoryv1.FeedArtifact{artifact}, SnapshotAt: &signedAt}, nil
	case advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD:
		repomd, err := c.get(ctx, source.GetUrl(), maxRecordBytes)
		if err != nil {
			return nil, err
		}
		location, checksum, err := updateLocation(source.GetUrl(), repomd)
		if err != nil {
			return nil, err
		}
		raw, err := c.get(ctx, location, maxBytes)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(raw)
		if !bytes.Equal(digest[:], checksum) {
			return nil, errors.New("feed: repomd updateinfo checksum mismatch")
		}
		if err := checkPin(source, digest[:]); err != nil {
			return nil, err
		}
		if err := writeAcquired(output, raw, digest[:]); err != nil {
			return nil, err
		}
		repomdDigest := sha256.Sum256(repomd)
		return &Acquisition{Artifacts: []*advisoryv1.FeedArtifact{
			{Url: location, Sha256: digest[:]},
			{Url: source.GetUrl(), Sha256: repomdDigest[:]},
		}}, nil
	case advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO,
		advisoryv1.FeedFormat_FEED_FORMAT_DEBIAN_TRACKER_JSON, advisoryv1.FeedFormat_FEED_FORMAT_ARCH_JSON:
		// ARCH_JSON carries only all.json: the advisories.json date companion is
		// not part of ParseStream's input, so offline Arch publications lack
		// advisory dates.
		raw, err := c.get(ctx, source.GetUrl(), maxBytes)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(raw)
		if err := checkPin(source, digest[:]); err != nil {
			return nil, err
		}
		if err := writeAcquired(output, raw, digest[:]); err != nil {
			return nil, err
		}
		return &Acquisition{Artifacts: []*advisoryv1.FeedArtifact{{Url: source.GetUrl(), Sha256: digest[:]}}}, nil
	default:
		return nil, errors.New("feed: unsupported format")
	}
}

// acquireArchive stages the archive with the online download checks, then
// streams the authenticated file to output while re-hashing it.
func (c *Client) acquireArchive(ctx context.Context, source *advisoryv1.FeedSource, output io.Writer, bound int64) (acquisition *Acquisition, err error) {
	file, err := os.CreateTemp("", "lindm-feed-osv-*")
	if err != nil {
		return nil, fmt.Errorf("feed: stage OSV archive: %w", err)
	}
	defer func() {
		err = errors.Join(err, file.Close(), os.Remove(file.Name()))
		if err != nil {
			acquisition = nil
		}
	}()
	// Archive transfers use the client without a whole-request timeout; the
	// caller's context deadline bounds this request.
	digest, err := c.downloadArchive(ctx, source.GetUrl(), file, bound, nil)
	if err != nil {
		return nil, err
	}
	if err := checkPin(source, digest); err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("feed: rewind OSV archive: %w", err)
	}
	hash := sha256.New()
	if err := copyArchive(ctx, io.MultiWriter(output, hash), file, bound); err != nil {
		return nil, err
	}
	if !bytes.Equal(hash.Sum(nil), digest) {
		return nil, errors.New("feed: acquired archive digest mismatch")
	}
	return &Acquisition{Artifacts: []*advisoryv1.FeedArtifact{{Url: source.GetUrl(), Sha256: digest}}}, nil
}

func checkPin(source *advisoryv1.FeedSource, digest []byte) error {
	if pin := source.GetExpectedSha256(); len(pin) != 0 && !bytes.Equal(pin, digest) {
		return errors.New("feed: source checksum mismatch")
	}
	return nil
}

// writeAcquired writes raw while hashing so the primary artifact digest is
// proven to cover exactly the bytes delivered to output.
func writeAcquired(output io.Writer, raw, digest []byte) error {
	hash := sha256.New()
	if _, err := io.MultiWriter(output, hash).Write(raw); err != nil {
		return fmt.Errorf("feed: write acquired snapshot: %w", err)
	}
	if !bytes.Equal(hash.Sum(nil), digest) {
		return errors.New("feed: acquired snapshot digest mismatch")
	}
	return nil
}
