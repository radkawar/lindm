//go:build linux

package vmlab

import "testing"

func TestWallSessionRequiresNativeTerminalIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		text string
		want bool
	}{
		{"local PAM login", "terminal /dev/pts/1\r\nTTY=pts/1\r\nType=tty\r\nRemote=no\r\nClass=user\r\n", true},
		{"absolute TTY", "terminal /dev/pts/1\nTTY=/dev/pts/1\nType=tty\nRemote=no\nClass=user\n", true},
		{"SSH missing TTY", "terminal /dev/pts/0\nTTY=\nType=tty\nRemote=yes\nClass=user\n", false},
		{"different terminal", "terminal /dev/pts/1\nTTY=pts/2\nType=tty\nRemote=no\nClass=user\n", false},
		{"remote session", "terminal /dev/pts/1\nTTY=pts/1\nType=tty\nRemote=yes\nClass=user\n", false},
		{"manager session", "terminal /dev/pts/1\nTTY=pts/1\nType=tty\nRemote=no\nClass=manager\n", false},
		{"graphical session", "terminal /dev/pts/1\nTTY=pts/1\nType=wayland\nRemote=no\nClass=user\n", false},
		{"partial output", "terminal /dev/pts/1\nTTY=pts/1\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := wallSessionReady(test.text + "session-id c7\nsession-ready\n"); got != test.want {
				t.Fatalf("wall session ready = %t, want %t", got, test.want)
			}
		})
	}
}

func TestWallSessionReadinessIgnoresTerminalTitleMarker(t *testing.T) {
	const title = "\x1b]2;command printf session-ready\x1b\\"
	const metadata = "\nterminal /dev/pts/2\r\nsession-id c7\r\nTTY=pts/2\r\nRemote=no\r\nType=tty\r\nClass=user\r\n"
	if wallSessionReady(title + metadata) {
		t.Fatal("terminal title was mistaken for the completed login")
	}
	if !wallSessionReady(title + metadata + "session-ready\r\n") {
		t.Fatal("framed native metadata after a terminal title was rejected")
	}
}

func TestWallSessionCleanupMatchesOnlyItsSession(t *testing.T) {
	const sessions = "7 1000 lindm-lab - 123 user pts/1 no -\n17 1001 other - 456 user pts/2 no -\n"
	if !wallSessionListed(sessions, "7") || wallSessionListed(sessions, "1") || wallSessionListed(sessions, "") {
		t.Fatal("cleanup session matching did not use the exact first column")
	}
	if wallSessionListed("17 1001 other - 456 user pts/2 no -\n", "7") {
		t.Fatal("unrelated session blocked cleanup")
	}
	if id := wallSessionID("\x1b]2;session-id forged\x1b\\\nsession-id c7\r\n"); id != "c7" {
		t.Fatalf("session ID = %q, want c7", id)
	}
}
