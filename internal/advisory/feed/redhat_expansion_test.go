package feed

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRedHatArchiveExpansionIncludesTrailingBytes(t *testing.T) {
	// The LimitedReader has already charged all decompressed tar entries to
	// the 32 GiB budget. Exercise the remaining sentinel at EOF, not a 32 GiB
	// synthetic payload: trailing decompressed bytes still spend that budget.
	for _, test := range []struct {
		name      string
		remaining int64
		trailer   string
		valid     bool
	}{
		{"exact-bound", 1, "", true},
		{"last-permitted-byte", 2, "x", true},
		{"one-byte-over", 1, "x", false},
		{"trailing-overflow", 2, "xx", false},
		{"already-over-bound", 0, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &io.LimitedReader{R: strings.NewReader(test.trailer), N: test.remaining}
			err := finishRedHatArchive(input)
			if (err == nil) != test.valid {
				t.Fatalf("expanded archive boundary: remaining=%d trailer=%q err=%v", test.remaining, test.trailer, err)
			}
		})
	}
}

func TestRedHatArchiveExpansionPreservesDecoderFailure(t *testing.T) {
	failure := errors.New("compressed frame checksum failed")
	input := &io.LimitedReader{R: redHatFailingReader{err: failure}, N: 1}
	if err := finishRedHatArchive(input); !errors.Is(err, failure) {
		t.Fatalf("tar EOF hid compressed trailer failure: %v", err)
	}
}
