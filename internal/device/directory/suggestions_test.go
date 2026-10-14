// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"strings"
	"testing"
)

// prefixEnd must bound exactly the strings starting with the prefix in byte
// order, or the fleet package index range would drop or admit values.
func TestPrefixEndBoundsExactlyThePrefixRange(t *testing.T) {
	for _, tc := range []struct {
		prefix, end string
		bounded     bool
	}{
		{"", "", false},
		{"py", "pz", true},
		{"a~", "a\u007f", true},
		{"lib\u00e9", "lib\u00ea", true},
		{"x\ud7ff", "x\ue000", true},
		{"x\U0010ffff", "y", true},
		{"\U0010ffff\U0010ffff", "", false},
	} {
		end, bounded := prefixEnd(tc.prefix)
		if end != tc.end || bounded != tc.bounded {
			t.Fatalf("prefixEnd(%q) = %q, %v; want %q, %v", tc.prefix, end, bounded, tc.end, tc.bounded)
		}
		if !bounded {
			continue
		}
		for _, inside := range []string{tc.prefix, tc.prefix + "\x00", tc.prefix + "\U0010ffff\U0010ffff"} {
			if inside < tc.prefix || inside >= end {
				t.Fatalf("%q outside [%q, %q)", inside, tc.prefix, end)
			}
		}
		if strings.HasPrefix(end, tc.prefix) {
			t.Fatalf("bound %q itself starts with %q", end, tc.prefix)
		}
	}
}

// PostgreSQL lower() under the "C" collation folds ASCII only; folding more
// here would search for values the database never lowercases.
func TestASCIILowerFoldsOnlyASCII(t *testing.T) {
	if got := asciiLower("PyQt5-ÉTÉ_%"); got != "pyqt5-ÉtÉ_%" {
		t.Fatalf("asciiLower = %q", got)
	}
}
