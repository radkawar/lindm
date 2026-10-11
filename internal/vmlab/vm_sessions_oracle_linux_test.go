//go:build linux

package vmlab

import (
	"encoding/json"
	"os"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestTruthActiveSession(t *testing.T) {
	got, err := parseTruthActiveSession([]byte("Name=lindm-lab\nClass=user\nType=tty\nSeat=\nRemote=yes\nActive=yes\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.UserName.Value != "lindm-lab" || got.SessionClass.Value != "user" || got.SessionType.Value != "tty" || got.Seat.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE || got.Remote.Status != truthSuccess || !got.Remote.Value {
		t.Fatalf("incorrect active remote-session truth: %v", got)
	}
	got, err = parseTruthActiveSession([]byte("Active=yes\nName=lindm-lab\nClass=user\nType=x11\nSeat=\nRemote=no\n"))
	if err != nil || got == nil || got.Seat.Status != truthUnavailable {
		t.Fatalf("local graphical session without seat must stay unavailable: %v, %v", got, err)
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

func TestTruthSeatApplicability(t *testing.T) {
	for _, tc := range []struct {
		name, context string
		status        inventoryv1.CollectionStatus
	}{
		{"manager", "Class=manager\nType=unspecified\nRemote=no\n", inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE},
		{"background", "Class=background\nType=unspecified\nRemote=no\n", inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE},
		{"remote", "Class=user\nType=x11\nRemote=yes\n", inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE},
		{"tty", "Class=user\nType=tty\nRemote=no\n", inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE},
		{"local-x11", "Class=user\nType=x11\nRemote=no\n", truthUnavailable},
		{"local-wayland", "Class=user\nType=wayland\nRemote=no\n", truthUnavailable},
		{"missing-class", "Type=tty\nRemote=yes\n", truthUnavailable},
		{"missing-type", "Class=manager\nRemote=no\n", truthUnavailable},
		{"missing-remote", "Class=manager\nType=unspecified\n", truthUnavailable},
		{"unknown-class", "Class=unknown\nType=unspecified\nRemote=no\n", truthUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, seat := range []string{"", "Seat=\n", "Seat=seat0\n"} {
				got, err := parseTruthActiveSession([]byte("Active=yes\nName=lindm-lab\n" + tc.context + seat))
				if err != nil {
					t.Fatal(err)
				}
				want := tc.status
				if seat == "Seat=seat0\n" {
					want = truthSuccess
				}
				if got.GetSeat().GetStatus() != want {
					t.Fatalf("seat %q: got %v, want %v", seat, got.GetSeat(), want)
				}
			}
		})
	}
}

func TestTruthCapturedFedora44Sessions(t *testing.T) {
	data, err := os.ReadFile("../agent/inventory/testdata/sessions-fedora44-aarch64/sessions.json")
	if err != nil {
		t.Fatal(err)
	}
	var captured struct {
		Sessions []struct {
			Loginctl struct {
				Stdout string `json:"stdout"`
			} `json:"loginctl"`
		} `json:"active_sessions"`
	}
	if err := json.Unmarshal(data, &captured); err != nil {
		t.Fatal(err)
	}
	if len(captured.Sessions) != 2 {
		t.Fatal("capture must retain both active user and manager sessions")
	}
	host, packages := healthyInventoryFixture()
	managerSeen := false
	for _, record := range captured.Sessions {
		got, err := parseTruthActiveSession([]byte(record.Loginctl.Stdout))
		if err != nil || got == nil || got.GetSeat().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE {
			t.Fatalf("captured seatless active session: %v, %v", got, err)
		}
		host.Details.Sessions.ActiveSessions.Sessions = append(host.Details.Sessions.ActiveSessions.Sessions, got)
		if got.GetSessionClass().GetValue() == "manager" {
			managerSeen = got.GetSessionType().GetValue() == "unspecified" && !got.GetRemote().GetValue()
		}
	}
	if !managerSeen {
		t.Fatal("native local non-graphical manager context omitted")
	}
	if err := CheckInventoryHealth(host, packages); err != nil {
		t.Fatalf("captured contextual health: %v", err)
	}
}
