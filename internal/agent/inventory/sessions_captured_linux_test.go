//go:build linux

package inventory

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestCapturedFedora44ARMSessionSeats(t *testing.T) {
	// These unmodified busctl replies capture both an SSH user session and
	// its systemd-user manager session. Neither native session has a seat.
	type commandReply struct {
		Command  []string `json:"command"`
		Stdout   string   `json:"stdout"`
		Stderr   string   `json:"stderr"`
		ExitCode int      `json:"exit_code"`
	}
	var capture struct {
		ListSessions   commandReply `json:"list_sessions"`
		ActiveSessions []struct {
			Busctl commandReply `json:"busctl"`
		} `json:"active_sessions"`
	}
	if err := json.Unmarshal(detailFixture(t, "sessions-fedora44-aarch64/sessions.json"), &capture); err != nil {
		t.Fatal(err)
	}
	if len(capture.ActiveSessions) != 2 {
		t.Fatalf("captured active sessions = %d, want 2", len(capture.ActiveSessions))
	}
	replies := []commandReply{capture.ListSessions}
	for _, session := range capture.ActiveSessions {
		replies = append(replies, session.Busctl)
	}
	for _, reply := range replies {
		if len(reply.Command) < 2 || reply.Command[0] != "busctl" || reply.ExitCode != 0 || reply.Stderr != "" || reply.Stdout == "" {
			t.Fatalf("unsuccessful captured command: %+v", reply)
		}
	}
	calls := 0
	got := collectSessionCounts(t.Context(), func(_ context.Context, b backend, parse func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		calls++
		if b.path != "/usr/bin/busctl" || len(b.args) == 0 {
			t.Fatalf("unexpected native command: %+v", b)
		}
		if b.args[len(b.args)-1] == "ListUsers" {
			// ListUsers was not captured. Do not synthesize a native reply.
			return unavailable
		}
		for _, reply := range replies {
			if slices.Equal(b.args, reply.Command[1:]) {
				return parse(strings.NewReader(reply.Stdout))
			}
		}
		t.Fatalf("uncaptured native command: %v", b.args)
		return invalid
	})
	if calls != 4 || got.Users.Status != unavailable || got.Sessions.Status != success || got.Sessions.Value != 2 || got.ActiveSessions.Status != success || len(got.ActiveSessions.Sessions) != 2 {
		t.Fatalf("captured session collection = %v, calls = %d", got, calls)
	}
	for i, want := range []struct {
		class       string
		sessionType string
		remote      bool
	}{
		{"user", "tty", true},
		{"manager", "unspecified", false},
	} {
		session := got.ActiveSessions.Sessions[i]
		if session.UserName.Status != success || session.UserName.Value != "lindm-lab" ||
			session.SessionClass.Status != success || session.SessionClass.Value != want.class ||
			session.SessionType.Status != success || session.SessionType.Value != want.sessionType ||
			session.Remote.Status != success || session.Remote.Value != want.remote ||
			session.Seat.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE || session.Seat.Value != "" {
			t.Fatalf("captured session %d lost native seat applicability: %v", i, session)
		}
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}
