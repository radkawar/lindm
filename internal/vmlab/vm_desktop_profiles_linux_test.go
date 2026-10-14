// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/platform"
)

// openSUSE's GDM answers autologin from /etc/sysconfig/displaymanager ahead of
// custom.conf, so a TW autologin left only a greeter session. The GNOME profile
// names the user there, in place, keeping the file's other settings.
func TestGNOMEAutologinNamesUserInOpenSUSESysconfig(t *testing.T) {
	sysconfig := filepath.Join(t.TempDir(), "displaymanager")
	original := "## Type: string\nDISPLAYMANAGER_AUTOLOGIN=\"\"\nDISPLAYMANAGER_PASSWORD_LESS_LOGIN=\"no\"\n"
	if err := os.WriteFile(sysconfig, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(sysconfig)
	if err != nil {
		t.Fatal(err)
	}
	session := platform.LabSession{GDMConfig: "/etc/gdm/custom.conf", GDMSysconfig: sysconfig, Name: "gnome"}
	gnome := labDesktops[0]
	if gnome.name != "gnome" || !strings.Contains(gnome.autologin(session), gdmSysconfigAutologin(session, `"$u"`)) || !strings.Contains(gnome.autologin(session), "restorecon -RF '/etc/gdm/custom.conf' '"+sysconfig+"'") {
		t.Fatalf("GNOME autologin omits the sysconfig user:\n%s", gnome.autologin(session))
	}
	for range 2 {
		if output, err := exec.Command("sh", "-eu", "-c", "u=lindm-desktop-test\n"+gdmSysconfigAutologin(session, `"$u"`)).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, output)
		}
	}
	data, err := os.ReadFile(sysconfig)
	if err != nil {
		t.Fatal(err)
	}
	want := "## Type: string\nDISPLAYMANAGER_PASSWORD_LESS_LOGIN=\"no\"\nDISPLAYMANAGER_AUTOLOGIN=\"lindm-desktop-test\"\n"
	if string(data) != want {
		t.Fatalf("sysconfig =\n%s\nwant\n%s", data, want)
	}
	after, err := os.Stat(sysconfig)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("sysconfig replaced instead of rewritten in place: %v", err)
	}
	if gdmSysconfigAutologin(platform.LabSession{GDMConfig: "/etc/gdm/custom.conf"}, `"$u"`) != "" {
		t.Fatal("release without GDM sysconfig gained a sysconfig write")
	}
}
