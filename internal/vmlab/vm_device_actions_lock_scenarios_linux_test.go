//go:build linux

package vmlab

import (
	"strings"
	"testing"
)

func TestActionDesktopRequiresGenuineUserAndBothLockOracles(t *testing.T) {
	for _, desktop := range []string{"", "ubuntu", "gnome"} {
		for _, kind := range []string{"wayland", "x11"} {
			for _, locked := range []bool{false, true} {
				fields := []string{"4", kind, desktop, "no", "user", actionDesktopUser, "gdm-autologin", "(false,)"}
				if locked {
					fields[3], fields[7] = "yes", "(true,)"
				}
				observed, err := parseActionDesktop([]byte(strings.Join(fields, "\n")+"\n"), locked)
				if err != nil || observed == nil || observed.LockedHint != locked || observed.ScreenSaverActive != locked || observed.Desktop != desktop {
					t.Fatalf("%s/%s locked=%t: observed=%+v error=%v", desktop, kind, locked, observed, err)
				}
			}
		}
	}
	for _, test := range []struct {
		name  string
		field int
		value string
	}{
		{"greeter", 4, "greeter"},
		{"ssh", 1, "tty"},
		{"wrong_user", 5, "gdm"},
		{"not_gdm_login", 6, "sshd"},
		{"missing_logind_ack", 3, "no"},
		{"missing_gnome_ack", 7, "(false,)"},
		{"invalid_logind", 3, "unknown"},
		{"invalid_gnome", 7, "()"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := []string{"4", "wayland", "ubuntu", "yes", "user", actionDesktopUser, "gdm-autologin", "(true,)"}
			fields[test.field] = test.value
			if _, err := parseActionDesktop([]byte(strings.Join(fields, "\n")), true); err == nil {
				t.Fatal("invalid native observation was accepted")
			}
		})
	}
	if _, err := parseActionDesktop(nil, false); err == nil {
		t.Fatal("no logged-in session was accepted")
	}
}
