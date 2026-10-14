// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"

	"buf.build/go/protovalidate"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

const ovalCompressedLimit = 64 << 20

func ovalArchiveBound(source *advisoryv1.FeedSource) int64 {
	if source.MaxArchiveBytes != nil {
		return min(int64(source.GetMaxArchiveBytes()), ovalCompressedLimit)
	}
	return ovalCompressedLimit
}

func (c *Client) fetchSUSEOVAL(ctx context.Context, source *advisoryv1.FeedSource, emit func(*advisoryv1.Advisory) error, progress func() error) (doc *advisoryv1.FeedDocument, err error) {
	file, err := os.CreateTemp("", "lindm-feed-oval-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, file.Close(), os.Remove(file.Name()))
		if err != nil {
			doc = nil
		}
	}()
	digest, err := c.downloadArchive(ctx, source.GetUrl(), file, ovalArchiveBound(source), progress)
	if err != nil {
		return nil, err
	}
	return finishSUSEOVAL(ctx, source, c.validator, file, digest, emit, progress)
}

func stageSUSEOVAL(ctx context.Context, source *advisoryv1.FeedSource, validator protovalidate.Validator, input io.Reader, emit func(*advisoryv1.Advisory) error, progress func() error) (doc *advisoryv1.FeedDocument, err error) {
	file, err := os.CreateTemp("", "lindm-feed-oval-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, file.Close(), os.Remove(file.Name()))
		if err != nil {
			doc = nil
		}
	}()
	hash := sha256.New()
	if err := copyArchive(ctx, io.MultiWriter(file, hash), input, ovalArchiveBound(source)); err != nil {
		return nil, err
	}
	return finishSUSEOVAL(ctx, source, validator, file, hash.Sum(nil), emit, progress)
}

func finishSUSEOVAL(ctx context.Context, source *advisoryv1.FeedSource, validator protovalidate.Validator, file *os.File, digest []byte, emit func(*advisoryv1.Advisory) error, progress func() error) (*advisoryv1.FeedDocument, error) {
	if pin := source.GetExpectedSha256(); len(pin) != 0 && !bytes.Equal(pin, digest) {
		return nil, errors.New("feed: source checksum mismatch")
	}
	doc, err := parseSUSEOVAL(ctx, source, file, validator, emit, progress)
	if err != nil {
		return nil, err
	}
	doc.SourceSha256 = digest
	doc.Artifacts = []*advisoryv1.FeedArtifact{{Url: source.GetUrl(), Sha256: digest}}
	return doc, nil
}
