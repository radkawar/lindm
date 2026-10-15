// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// fetchRedHatStream authenticates originals before parsing, then reconciles the
// entire source on disk. No partial document or archive escapes to consumers.
// Consumers still must discard generation staging if emission itself fails.
// A complete VEX snapshot expands to over 21 GB, so there is no size-derived
// deadline: progress (nil allowed) is marked after every accepted document.
func (c *Client) fetchRedHatStream(ctx context.Context, source *advisoryv1.FeedSource, emit func(*advisoryv1.Advisory) error, progress func() error) (doc *advisoryv1.FeedDocument, err error) {
	if err := redHatConfig(source); err != nil {
		return nil, err
	}
	stager, err := newRedHatStager(ctx, source)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, stager.close())
		if err != nil {
			doc = nil
		}
	}()
	doc = new(advisoryv1.FeedDocument)
	var signedAt time.Time
	switch source.GetFormat() {
	case advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF:
		artifact, at, err := c.consumeSignedCSAF(ctx, source, func(file *os.File) error {
			if err := acceptRedHatDocument(source, c.validator, stager, doc, func() error {
				return parseRedHatFile(ctx, source, file, c.validator, stager.add)
			}); err != nil {
				return err
			}
			return markProgress(progress)
		})
		if err != nil {
			return nil, err
		}
		if err := bindArtifacts(doc, []*advisoryv1.FeedArtifact{artifact}); err != nil {
			return nil, err
		}
		signedAt = at
	case advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES:
		at, err := c.fetchIndexedRedHatSnapshot(ctx, source, stager, doc, progress)
		if err != nil {
			return nil, err
		}
		if pin := source.GetExpectedSha256(); len(pin) != 0 && !bytes.Equal(pin, doc.GetSourceSha256()) {
			return nil, errors.New("feed: Red Hat snapshot manifest checksum mismatch")
		}
		signedAt = at
	default:
		return nil, errors.New("feed: Red Hat streaming source required")
	}
	doc.SnapshotAt = timestamppb.New(signedAt)
	if err := stager.emit(ctx, emit); err != nil {
		return nil, err
	}
	return doc, nil
}

// stageRedHatStream preserves offline import custody: a single CSAF JSON can be
// pinned but gains no signature time or complete coverage. A compressed archive
// is not an offline substitute for both independently authenticated distributions.
func stageRedHatStream(ctx context.Context, source *advisoryv1.FeedSource, validator protovalidate.Validator, input io.Reader, emit func(*advisoryv1.Advisory) error) (doc *advisoryv1.FeedDocument, err error) {
	if source.GetFormat() != advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF {
		return nil, errors.New("feed: offline Red Hat imports require an individual CSAF document")
	}
	if err := redHatConfig(source); err != nil {
		return nil, err
	}
	stager, err := newRedHatStager(ctx, source)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, stager.close())
		if err != nil {
			doc = nil
		}
	}()
	doc = new(advisoryv1.FeedDocument)
	digest := sha256.New()
	if err := acceptRedHatDocument(source, validator, stager, doc, func() error {
		return parseRedHatClaims(ctx, source, io.TeeReader(input, digest), validator, stager.add)
	}); err != nil {
		return nil, err
	}
	sum := digest.Sum(nil)
	if pin := source.GetExpectedSha256(); len(pin) != 0 && !bytes.Equal(pin, sum) {
		return nil, errors.New("feed: source checksum mismatch")
	}
	if err := stager.emit(ctx, emit); err != nil {
		return nil, err
	}
	doc.SourceSha256 = sum
	return doc, nil
}
