//go:build linux

package inventory

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const activeSessionReply = `{"type":"a{sv}","data":[{"Active":{"type":"b","data":true},"Name":{"type":"s","data":"alice"},"Class":{"type":"s","data":"user"},"Type":{"type":"s","data":"wayland"},"Seat":{"type":"(so)","data":["seat0","/org/freedesktop/login1/seat/seat0"]},"Remote":{"type":"b","data":false}}]}`

func TestParseActiveSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reply  string
		status inventoryv1.CollectionStatus
		active bool
	}{
		{"active", activeSessionReply, success, true},
		{"inactive", `{"type":"a{sv}","data":[{"Active":{"type":"b","data":false}}]}`, success, false},
		{"partial", `{"type":"a{sv}","data":[{"Active":{"type":"b","data":true}}]}`, success, true},
		{"missing membership", `{"type":"a{sv}","data":[{}]}`, unavailable, false},
		{"null membership", `{"type":"a{sv}","data":[{"Active":{"type":"b","data":null}}]}`, invalid, false},
		{"wrong membership type", `{"type":"a{sv}","data":[{"Active":{"type":"s","data":"true"}}]}`, invalid, false},
		{"wrong signature", `{"type":"s","data":[{}]}`, invalid, false},
		{"null properties", `{"type":"a{sv}","data":[null]}`, invalid, false},
		{"truncated", `{"type":"a{sv}"`, invalid, false},
		{"trailing reply", activeSessionReply + `{}`, invalid, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, status := parseActiveSession(strings.NewReader(tc.reply))
			if status != tc.status || (got != nil) != tc.active {
				t.Fatalf("session = %v, status = %v", got, status)
			}
			if got != nil {
				if err := protovalidate.Validate(got); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	got, _ := parseActiveSession(strings.NewReader(activeSessionReply))
	if got.UserName.Value != "alice" || got.SessionClass.Value != "user" || got.SessionType.Value != "wayland" || got.Seat.Value != "seat0" || got.Remote.Status != success || got.Remote.Value {
		t.Fatalf("active facts = %v", got)
	}
	partial, status := parseActiveSession(strings.NewReader(`{"type":"a{sv}","data":[{"Active":{"type":"b","data":true},"Name":{"type":"s","data":null},"Class":{"type":"u","data":2},"Seat":{"type":"(so)","data":["","/"]},"Remote":{"type":"b","data":"false"}}]}`))
	if status != success || partial.UserName.Status != invalid || partial.SessionClass.Status != invalid || partial.SessionType.Status != unavailable || partial.Seat.Status != unavailable || partial.Remote.Status != invalid {
		t.Fatalf("partial facts = %v, %v", partial, status)
	}
	if err := protovalidate.Validate(partial); err != nil {
		t.Fatal(err)
	}
}

func TestCollectActiveSessions(t *testing.T) {
	for _, tc := range []struct {
		name           string
		list           string
		propertyStatus inventoryv1.CollectionStatus
		status         inventoryv1.CollectionStatus
		rows           int
		calls          int
	}{
		{"active and inactive", sessionList(2), success, success, 1, 4},
		{"empty", sessionList(0), success, success, 0, 2},
		{"membership failure discards rows", sessionList(2), unavailable, unavailable, 0, 4},
		{"timeout discards rows", sessionList(2), inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT, inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT, 0, 4},
		{"capacity", sessionList(4097), success, capacity, 0, 2},
		{"unsafe path", strings.Replace(sessionList(1), "/session/s0", "/session/../s0", 1), success, invalid, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			run := func(ctx context.Context, b backend, parse func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("session calls must share a bounded deadline")
				}
				if b.path != "/usr/bin/busctl" {
					t.Fatalf("unexpected native executable: %s", b.path)
				}
				switch calls {
				case 1:
					return parse(strings.NewReader(`{"type":"a(uso)","data":[[[1000,"alice","/org/freedesktop/login1/user/_1000"]]]}`))
				case 2:
					return parse(strings.NewReader(tc.list))
				default:
					if len(b.args) != 11 || b.args[7] != "org.freedesktop.DBus.Properties" || b.args[8] != "GetAll" || b.args[10] != "org.freedesktop.login1.Session" || !validSessionPath(b.args[6]) {
						t.Fatalf("unexpected session call: %v", b.args)
					}
					if calls == 3 {
						return parse(strings.NewReader(activeSessionReply))
					}
					if tc.propertyStatus != success {
						return tc.propertyStatus
					}
					return parse(strings.NewReader(`{"type":"a{sv}","data":[{"Active":{"type":"b","data":false}}]}`))
				}
			}
			got := collectSessionCounts(t.Context(), run)
			if got.ActiveSessions.Status != tc.status || len(got.ActiveSessions.Sessions) != tc.rows || calls != tc.calls || got.Users.Value != 1 {
				t.Fatalf("result = %v, calls = %d", got, calls)
			}
			if tc.status != capacity && got.Sessions.Status != success {
				t.Fatalf("membership failure erased total count: %v", got.Sessions)
			}
			if err := protovalidate.Validate(got); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func sessionList(count int) string {
	var result strings.Builder
	result.WriteString(`{"type":"a(susso)","data":[[`)
	for i := range count {
		if i > 0 {
			result.WriteByte(',')
		}
		fmt.Fprintf(&result, `["s%d",1000,"alice","seat0","/org/freedesktop/login1/session/s%d"]`, i, i)
	}
	result.WriteString(`]]}`)
	return result.String()
}

func TestSessionListBoundsAndPaths(t *testing.T) {
	for _, count := range []int{0, 4096, 4097} {
		rows, status := parseSessionRows(strings.NewReader(sessionList(count)), "a(susso)")
		if count <= 4096 && (status != success || len(rows) != count) || count > 4096 && (status != capacity || len(rows) != 0) {
			t.Fatalf("count %d: rows=%d status=%v", count, len(rows), status)
		}
	}
	for _, path := range []string{"", "/", "/org/freedesktop/login1/session/", "/org/freedesktop/login1/session/a/b", "/org/freedesktop/login1/session/a-b", "--help"} {
		if validSessionPath(path) {
			t.Fatalf("accepted unsafe path %q", path)
		}
	}
	if !validSessionPath("/org/freedesktop/login1/session/_32") {
		t.Fatal("rejected escaped logind session path")
	}
}

func TestActiveSessionSchema(t *testing.T) {
	session, _ := parseActiveSession(strings.NewReader(activeSessionReply))
	legacy := &inventoryv1.SessionCounts{Users: number(0, nil), Sessions: number(0, nil)}
	if err := protovalidate.Validate(legacy); err != nil {
		t.Fatalf("historical absence rejected: %v", err)
	}
	for _, bad := range []*inventoryv1.ActiveSessions{
		{Status: unavailable, Sessions: []*inventoryv1.ActiveSession{session}},
		{Status: success, Sessions: make([]*inventoryv1.ActiveSession, 4097)},
	} {
		if err := protovalidate.Validate(bad); err == nil {
			t.Fatalf("accepted invalid collection: %v", bad.Status)
		}
	}
	for _, field := range []string{"user_name", "session_class", "session_type", "seat", "remote"} {
		bad := proto.CloneOf(session)
		message := bad.ProtoReflect()
		fields := message.Descriptor().Fields()
		for i := range fields.Len() {
			if string(fields.Get(i).Name()) == field {
				message.Clear(fields.Get(i))
			}
		}
		if err := protovalidate.Validate(bad); err == nil {
			t.Fatalf("accepted absent required property %s", field)
		}
	}
}

func TestSessionCollectionFailures(t *testing.T) {
	for _, status := range []inventoryv1.CollectionStatus{unavailable, invalid, capacity, inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT} {
		got := collectSessionCounts(t.Context(), func(context.Context, backend, func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
			return status
		})
		if got.Users.Status != status || got.Sessions.Status != status || got.ActiveSessions.Status != status || len(got.ActiveSessions.Sessions) != 0 {
			t.Fatalf("failed collection = %v", got)
		}
		if err := protovalidate.Validate(got); err != nil {
			t.Fatal(err)
		}
	}
	oversized := `{"type":"a{sv}","data":[{"Active":{"type":"b","data":true},"Name":{"type":"s","data":"` + strings.Repeat("a", maxDetailFile) + `"}}]}`
	if session, status := parseActiveSession(strings.NewReader(oversized)); status != capacity || session != nil {
		t.Fatalf("oversized reply = %v, %v", session, status)
	}
}

func TestActiveSessionNullSeatFields(t *testing.T) {
	for _, seat := range []string{`[null,"/"]`, `["",null]`} {
		reply := `{"type":"a{sv}","data":[{"Active":{"type":"b","data":true},"Seat":{"type":"(so)","data":` + seat + `}}]}`
		got, status := parseActiveSession(strings.NewReader(reply))
		if status != success || got.Seat.Status != invalid {
			t.Fatalf("null seat field = %v, %v", got, status)
		}
		if err := protovalidate.Validate(got); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBoundActiveSessionsPreservesCounts(t *testing.T) {
	got := collectDetails(t.Context(), fixtureDetails(t.TempDir()))
	session, _ := parseActiveSession(strings.NewReader(activeSessionReply))
	session.UserName = observed(strings.Repeat("a", 4096), nil)
	got.Sessions = &inventoryv1.SessionCounts{
		Users:          number(1, nil),
		Sessions:       number(32, nil),
		ActiveSessions: &inventoryv1.ActiveSessions{Status: success},
	}
	for range 32 {
		got.Sessions.ActiveSessions.Sessions = append(got.Sessions.ActiveSessions.Sessions, session)
	}
	if err := protovalidate.Validate(got.Sessions); err != nil {
		t.Fatalf("invalid oversized fixture: %v", err)
	}
	boundDetails(got)
	if got.Sessions.ActiveSessions.Status != capacity || len(got.Sessions.ActiveSessions.Sessions) != 0 {
		t.Fatalf("oversized active sessions partially published: %v", got.Sessions.ActiveSessions)
	}
	if got.Sessions.Users.Status != success || got.Sessions.Users.Value != 1 || got.Sessions.Sessions.Status != success || got.Sessions.Sessions.Value != 32 {
		t.Fatalf("active category capacity erased counts: %v", got.Sessions)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}
