package vmlab

import (
	"testing"
	"time"
)

func TestImageDownloadTimeoutCoversPinnedInstallerDVDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		size uint64
		min  time.Duration
	}{
		{"cloud image keeps the historical floor", 645988352, 30 * time.Minute},
		{"Rocky 10.2 DVD at 2 MiB/s", 10226171904, 81 * time.Minute},
		{"Rocky 9.8 DVD at 2 MiB/s", 15194259456, 120 * time.Minute},
	} {
		got := ImageDownloadTimeout(tc.size)
		if got < tc.min {
			t.Errorf("%s: %v, want at least %v", tc.name, got, tc.min)
		}
		if tc.size/imageDownloadFloor > uint64(30*time.Minute/time.Second) && got > time.Duration(tc.size/imageDownloadFloor+1)*time.Second {
			t.Errorf("%s: %v exceeds the size-derived bound", tc.name, got)
		}
	}
	if (Fetcher{}).client().Timeout != 0 {
		t.Fatal("client-wide timeout would cap pinned image transfers below their size-derived deadline")
	}
}
