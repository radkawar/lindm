package devlab

import "testing"

// Scale fixtures promise unique names and the long names and versions that
// console layouts must wrap.
func TestSyntheticPackagesScale(t *testing.T) {
	for _, manager := range []string{"dpkg", "rpm"} {
		seen := map[string]bool{}
		longName, longVersion := false, false
		for i := range 3000 {
			name := SyntheticPackageName(manager, i)
			if seen[name] {
				t.Fatalf("%s package %d repeats %q", manager, i, name)
			}
			seen[name] = true
			longName = longName || len(name) > 100
			longVersion = longVersion || len(SyntheticPackageVersion(manager, i)) > 80
		}
		if !longName || !longVersion {
			t.Fatalf("%s: long name %v, long version %v", manager, longName, longVersion)
		}
	}
}
