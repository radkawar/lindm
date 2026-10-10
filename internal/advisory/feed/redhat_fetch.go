package feed

import (
	"bytes"
	"context"
	"errors"
	"io"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func (c *Client) fetchRedHatSnapshot(ctx context.Context, source *advisoryv1.FeedSource) (*advisoryv1.FeedDocument, error) {
	doc := new(advisoryv1.FeedDocument)
	normalizedBytes := 0
	manifest, signedAt, err := c.fetchRedHatArchives(ctx, source, func(input io.Reader, _ string) error {
		part, err := parseRedHatArchive(ctx, source, input, c.validator)
		if err != nil {
			return err
		}
		normalizedBytes += proto.Size(part)
		if normalizedBytes > maxBytes || len(part.GetAdvisories()) > maxAdvisories-len(doc.Advisories) {
			return errors.New("feed: combined Red Hat snapshot exceeds normalized bounds")
		}
		doc.Advisories = append(doc.Advisories, part.GetAdvisories()...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	redHatReconcile(doc)
	if err := bindArtifacts(doc, manifest.GetArtifacts()); err != nil {
		return nil, err
	}
	if pin := source.GetExpectedSha256(); len(pin) != 0 && !bytes.Equal(pin, doc.GetSourceSha256()) {
		return nil, errors.New("feed: Red Hat snapshot manifest checksum mismatch")
	}
	doc.SnapshotAt = timestamppb.New(signedAt)
	return doc, nil
}
