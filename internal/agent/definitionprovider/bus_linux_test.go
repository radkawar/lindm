//go:build linux

package definitionprovider

import "testing"

// EL 9's manager reports "252-67.el9_8" without a dot; reading up to the first
// dot made it unparsable and refused the qualified EL 9 systemd.
func TestSystemdMajorReadsDistributionVersions(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    int
	}{
		{"255.4-1ubuntu8.10", 255},
		{"258.1-1.fc44", 258},
		{"252-67.el9_8.6.alma.1", 252},
		{"252-67.el9_8.2", 252},
		{"257", 257},
	} {
		if got, err := systemdMajor(tc.version); err != nil || got != tc.want {
			t.Fatalf("%q = %d, %v", tc.version, got, err)
		}
	}
	for _, version := range []string{"", "  ", "v252", "-252"} {
		if _, err := systemdMajor(version); err == nil {
			t.Fatalf("unparsable manager version %q accepted", version)
		}
	}
}
