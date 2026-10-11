package main

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// Publication uses unsigned emitted counts and signed persisted unique counts.
// Evidence collection must not panic after a real database publication commits.
func TestFeedTimingHandlerAcceptsPublicationCounterKinds(t *testing.T) {
	collector := new(feedTimingCollector)
	handler := &feedTimingHandler{base: slog.NewJSONHandler(io.Discard, nil), collector: collector}
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "advisory feed published", 0)
	record.Add("feed_id", "example", "elapsed", 2*time.Second, "emitted_count", uint64(15), "unique_count", int64(12), "rejected_count", int(3))
	if err := handler.Handle(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	results := collector.results()
	if len(results) != 1 {
		t.Fatalf("results=%d", len(results))
	}
	want := feedSourceTiming{FeedID: "example", Seconds: 2, Emitted: 15, Unique: 12, Rejected: 3}
	if results[0] != want {
		t.Fatalf("timing=%+v want=%+v", results[0], want)
	}
}
