//go:build linux

package firewallprovider

import "testing"

// Debian 12 (systemd 252) and Ubuntu 22.04 (249) enable the packaged restore
// unit through the split-/usr name /lib/systemd/system; the provider refused
// that link as missing persistence custody. It is the same verified file only
// while /lib is the merged-/usr link; nothing else stands in for the unit.
func TestRestoreEnablementAcceptsOnlyThePackagedUnit(t *testing.T) {
	for _, tc := range []struct {
		target    string
		mergedUsr bool
		want      bool
	}{
		{RestoreUnitPath, false, true},
		{RestoreUnitPath, true, true},
		{"/lib/systemd/system/lindm-firewall-restore.service", true, true},
		{"/lib/systemd/system/lindm-firewall-restore.service", false, false},
		{"../../../usr/lib/systemd/system/lindm-firewall-restore.service", true, false},
		{"/etc/systemd/system/lindm-firewall-restore.service", true, false},
		{"/lib/systemd/system/other.service", true, false},
		{"/dev/null", true, false},
	} {
		if got := restoreLinkAccepted(tc.target, tc.mergedUsr); got != tc.want {
			t.Errorf("%s merged-usr=%t accepted=%t", tc.target, tc.mergedUsr, got)
		}
	}
}
