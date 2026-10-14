// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"context"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// publish adapts controlled test documents to the production streaming publisher.
func (s *Service) publish(ctx context.Context, source *advisoryv1.FeedSource, doc *advisoryv1.FeedDocument, started time.Time) error {
	return s.publishStream(ctx, source, started, func(_ context.Context, emit func(*advisoryv1.Advisory) error, _ func() error) (*advisoryv1.FeedDocument, error) {
		if doc == nil {
			return nil, ErrInvalid
		}
		for _, record := range doc.GetAdvisories() {
			if err := emit(record); err != nil {
				return nil, err
			}
		}
		return doc, nil
	})
}
