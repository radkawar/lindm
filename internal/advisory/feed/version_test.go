// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// These are cached upstream tests, not expectations derived from our comparator.
// Exact upstream revisions, extraction and licensing are in testdata/provenance.txt.
func TestUpstreamNativeVersionVectors(t *testing.T) {
	for _, manager := range []string{"dpkg", "rpm"} {
		t.Run(manager, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + manager + "-versions.txt")
			if err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			count := 0
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) != 3 {
					t.Fatalf("invalid upstream vector: %q", scanner.Text())
				}
				want, err := strconv.Atoi(fields[2])
				if err != nil {
					t.Fatal(err)
				}
				got, err := Compare(manager, fields[0], fields[1])
				if err != nil || got != want {
					t.Errorf("Compare(%q, %q, %q) = %d, %v; want %d", manager, fields[0], fields[1], got, err, want)
				}
				reverse, err := Compare(manager, fields[1], fields[0])
				if err != nil || reverse != -want {
					t.Errorf("reverse Compare(%q, %q) = %d, %v; want %d", fields[1], fields[0], reverse, err, -want)
				}
				count++
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			wantCount := 43
			if manager == "rpm" {
				wantCount = 91
			}
			if count != wantCount {
				t.Fatalf("read %d upstream vectors; want %d", count, wantCount)
			}
		})
	}
}

func TestEpochRevisionAndInvalidVersions(t *testing.T) {
	for _, test := range []struct {
		manager, a, b string
		want          int
	}{
		{"dpkg", "1:1.0-1", "2.0-99", 1},
		{"dpkg", "1.0", "1.0-0", 0},
		{"dpkg", "1.0-1~deb12u1", "1.0-1", -1},
		{"rpm", "1:3.0.7-28.el9_4", "3.0.7-99.el9_4", 1},
		{"rpm", "0:1.0-1", "1.0-1", 0},
		{"rpm", "1.0-1^git1", "1.0-1.1", -1},
		{"rpm", "1.0-1^git1", "1.0-1", 1},
		{"rpm", "18446744073709551616:1-1", "18446744073709551615:99-1", 1},
	} {
		got, err := Compare(test.manager, test.a, test.b)
		if err != nil || got != test.want {
			t.Errorf("%+v = %d, %v", test, got, err)
		}
	}
	for _, manager := range []string{"dpkg", "rpm"} {
		for _, invalid := range []string{"", ":1", "a:1", "1-", "1\n", "-1"} {
			if _, err := Compare(manager, invalid, "1"); err == nil {
				t.Errorf("%s accepted %q", manager, invalid)
			}
		}
	}
	if _, err := Compare("semver", "1", "2"); err == nil {
		t.Error("accepted unsupported version manager")
	}
}
