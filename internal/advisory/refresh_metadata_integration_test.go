// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"context"
	"errors"
	"testing"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/testdb"
)

func TestPublicationExposesActualStartAndClearsFailedLiveLease(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, _ := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	started := time.Now().UTC().Truncate(time.Microsecond)
	failure := errors.New("controlled producer failure")
	go func() {
		done <- s.publishStream(ctx, source, started, func(producer context.Context, _ func(*advisoryv1.Advisory) error, _ func() error) (*advisoryv1.FeedDocument, error) {
			close(entered)
			select {
			case <-release:
				return nil, failure
			case <-producer.Done():
				return nil, producer.Err()
			}
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("publication did not enter its producer")
	}
	feeds, err := s.Feeds(ctx)
	if err != nil || len(feeds.Feeds) != 1 || !feeds.Feeds[0].GetRefreshing() || !feeds.Feeds[0].GetRefreshStartedAt().AsTime().Equal(started) || feeds.Feeds[0].GetCheckedAt() != nil || feeds.Feeds[0].GetFresh() {
		t.Fatalf("running unpublished producer metadata: %v %v", feeds, err)
	}
	close(release)
	if err := <-done; !errors.Is(err, failure) {
		t.Fatalf("producer failure: %v", err)
	}
	feeds, err = s.Feeds(ctx)
	if err != nil || feeds.Feeds[0].GetRefreshing() || feeds.Feeds[0].GetRefreshStartedAt() != nil || feeds.Feeds[0].GetFresh() {
		t.Fatalf("failed producer retained live or published authority: %v %v", feeds, err)
	}
}
