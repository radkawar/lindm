//go:build linux

package vmlab

import "testing"

func TestTruthActiveSession(t *testing.T) {
	got, err := parseTruthActiveSession([]byte("Name=lindm-lab\nClass=user\nType=tty\nSeat=\nRemote=yes\nActive=yes\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.UserName.Value != "lindm-lab" || got.SessionClass.Value != "user" || got.SessionType.Value != "tty" || got.Seat.Status != truthUnavailable || got.Remote.Status != truthSuccess || !got.Remote.Value {
		t.Fatalf("incorrect active remote-session truth: %v", got)
	}
	got, err = parseTruthActiveSession([]byte("Active=yes\nName=lindm-lab\nClass=manager\nType=unspecified\nSeat=seat0\nRemote=no\n"))
	if err != nil || got == nil || got.SessionClass.Value != "manager" || got.Seat.Value != "seat0" || got.Remote.Status != truthSuccess || got.Remote.Value {
		t.Fatalf("incorrect active manager-session truth: %v, %v", got, err)
	}
	got, err = parseTruthActiveSession([]byte("Active=no\n"))
	if err != nil || got != nil {
		t.Fatalf("inactive session included: %v, %v", got, err)
	}
	got, err = parseTruthActiveSession([]byte("Active=yes\n"))
	if err != nil || got == nil || got.UserName.Status != truthUnavailable || got.SessionClass.Status != truthUnavailable || got.SessionType.Status != truthUnavailable || got.Seat.Status != truthUnavailable || got.Remote.Status != truthUnavailable {
		t.Fatalf("missing properties invented: %v, %v", got, err)
	}
}

func TestTruthActiveSessionRejectInvalidEvidence(t *testing.T) {
	for _, data := range []string{
		"", "Name=user\n", "Active=maybe\n", "Active=\n",
		"Active=yes\nActive=no\n", "Active=yes\nRemote=maybe\n",
		"Active=yes\nUnexpected=value\n", "Active=yes\nmalformed\n",
	} {
		if _, err := parseTruthActiveSession([]byte(data)); err == nil {
			t.Errorf("accepted invalid native session properties %q", data)
		}
	}
}
