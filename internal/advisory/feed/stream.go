package feed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func totalClaimsLimit(source *advisoryv1.FeedSource) uint64 {
	if source.TotalClaimsLimit != nil {
		return source.GetTotalClaimsLimit()
	}
	return 5000000
}

// FetchStream authenticates source bytes and emits normalized claims for an
// unpublished generation. A returned error invalidates the entire generation;
// consumers must not expose partial claims. OSV memory is bounded by one entry,
// not the complete export. Other formats retain their existing bounded decoders.
// Returned metadata contains no claims; callbacks may serialize but not mutate them.
func (c *Client) FetchStream(ctx context.Context, source *advisoryv1.FeedSource, emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
	if source == nil || emit == nil {
		return nil, errors.New("feed: source and claim consumer required")
	}
	if err := c.validator.Validate(source); err != nil {
		return nil, fmt.Errorf("feed: validate source: %w", err)
	}
	if source.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF || source.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		return c.fetchRedHatStream(ctx, source, emit)
	}
	if source.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		return c.fetchOSVArchive(ctx, source, emit)
	}
	doc, err := c.Fetch(ctx, source)
	if err != nil {
		return nil, err
	}
	return emitDocument(ctx, source, doc, emit)
}

// ParseStream imports original bytes with the same parser and configured digest
// checks as online acquisition. It never grants online freshness to imported data;
// the service applies the offline coverage policy after parsing completes.
func ParseStream(ctx context.Context, source *advisoryv1.FeedSource, input io.Reader, emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
	if source == nil || input == nil || emit == nil {
		return nil, errors.New("feed: source, reader and claim consumer required")
	}
	if source.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP || source.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF || source.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES {
		validator, err := protovalidate.New(protovalidate.WithMessages(source, &advisoryv1.Advisory{}))
		if err != nil {
			return nil, fmt.Errorf("feed: compile source validation: %w", err)
		}
		if err := validator.Validate(source); err != nil {
			return nil, fmt.Errorf("feed: validate source: %w", err)
		}
		if source.GetFormat() != advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP {
			return stageRedHatStream(ctx, source, validator, input, emit)
		}
		return stageOSVArchive(ctx, source, validator, input, emit)
	}
	doc, err := Parse(source, contextFeedReader{ctx, input})
	if err != nil {
		return nil, err
	}
	return emitDocument(ctx, source, doc, emit)
}

func emitDocument(ctx context.Context, source *advisoryv1.FeedSource, doc *advisoryv1.FeedDocument, emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
	if uint64(len(doc.Advisories)) > totalClaimsLimit(source) {
		return nil, errors.New("feed: total claims limit exceeded")
	}
	for _, claim := range doc.Advisories {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := emit(claim); err != nil {
			return nil, fmt.Errorf("feed: publish claim: %w", err)
		}
	}
	doc.Advisories = nil
	return doc, nil
}

func collectBoundedClaims(producer func(func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error)) (*advisoryv1.FeedDocument, error) {
	var claims []*advisoryv1.Advisory
	size := 0
	doc, err := producer(func(claim *advisoryv1.Advisory) error {
		size += proto.Size(claim)
		if len(claims) >= maxAdvisories || size > maxBytes {
			return errors.New("feed: materialized document limit exceeded")
		}
		claims = append(claims, claim)
		return nil
	})
	if err != nil {
		return nil, err
	}
	doc.Advisories = claims
	return doc, nil
}
