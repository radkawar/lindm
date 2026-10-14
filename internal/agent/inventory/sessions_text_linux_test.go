// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// AlmaLinux 8.10 aarch64 inspection: busctl from systemd 239 rejects
// --json=short, while loginctl natively listed one remote tty session. Replies
// below follow systemd v239 busctl.c format_cmdline/get_property output.
func TestLegacyBusctlTextSessions(t *testing.T) {
	var commands [][]string
	got := collectSessionCounts(t.Context(), func(_ context.Context, b backend, parse func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		if b.path != "/usr/bin/busctl" {
			t.Fatalf("unexpected native command: %+v", b)
		}
		commands = append(commands, b.args)
		if slices.Contains(b.args, "--json=short") {
			return commandFailure
		}
		var reply string
		switch {
		case slices.Equal(b.args, []string{"--version"}):
			reply = "systemd 239 (239-82.el8_10.5)\n+PAM +AUDIT +SELINUX +IMA -APPARMOR +SMACK\n"
		case b.args[len(b.args)-1] == "ListUsers":
			reply = `a(uso) 1 1000 "lindm-lab" "/org/freedesktop/login1/user/_1000"` + "\n"
		case b.args[len(b.args)-1] == "ListSessions":
			reply = `a(susso) 2 "3" 1000 "lindm-lab" "" "/org/freedesktop/login1/session/_33" "c1" 42 "gdm" "seat0" "/org/freedesktop/login1/session/c1"` + "\n"
		case b.args[0] == "--system" && b.args[3] == "get-property" && b.args[5] == "/org/freedesktop/login1/session/_33":
			reply = "b true\ns \"lindm-lab\"\ns \"user\"\ns \"tty\"\nb true\n(so) \"\" \"/\"\n"
		case b.args[0] == "--system" && b.args[3] == "get-property" && b.args[5] == "/org/freedesktop/login1/session/c1":
			reply = "b false\ns \"gdm\"\ns \"greeter\"\ns \"wayland\"\nb false\n(so) \"seat0\" \"/org/freedesktop/login1/seat/seat0\"\n"
		default:
			t.Fatalf("unexpected busctl arguments: %v", b.args)
		}
		return parse(strings.NewReader(reply))
	})
	if got.Users.Status != success || got.Users.Value != 1 || got.Sessions.Status != success || got.Sessions.Value != 2 ||
		got.ActiveSessions.Status != success || len(got.ActiveSessions.Sessions) != 1 {
		t.Fatalf("legacy session collection = %v", got)
	}
	session := got.ActiveSessions.Sessions[0]
	if session.UserName.Value != "lindm-lab" || session.SessionClass.Value != "user" || session.SessionType.Value != "tty" ||
		session.Remote.Status != success || !session.Remote.Value || session.Seat.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE {
		t.Fatalf("legacy active session = %v", session)
	}
	// One JSON attempt and one release probe; later calls use the text form.
	if len(commands) != 6 || !slices.Contains(commands[0], "--json=short") || !slices.Equal(commands[1], []string{"--version"}) {
		t.Fatalf("commands = %v", commands)
	}
	for _, args := range commands[2:] {
		if slices.Contains(args, "--json=short") || !slices.Equal(args[:3], []string{"--system", "--timeout=5s", "--auto-start=no"}) {
			t.Fatalf("legacy call kept JSON or lost bounds: %v", args)
		}
	}
	want := append([]string{"--system", "--timeout=5s", "--auto-start=no", "get-property", "org.freedesktop.login1", "/org/freedesktop/login1/session/_33", "org.freedesktop.login1.Session"}, textSessionProperties...)
	if !slices.Equal(commands[4], want) {
		t.Fatalf("property call = %v", commands[4])
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}

// A JSON-capable busctl that fails is a native failure, not a reason to parse
// another output format; its release is probed once.
func TestModernBusctlFailureStands(t *testing.T) {
	calls := 0
	got := collectSessionCounts(t.Context(), func(_ context.Context, b backend, parse func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		calls++
		if slices.Equal(b.args, []string{"--version"}) {
			return parse(strings.NewReader("systemd 257 (257.9-1)\n"))
		}
		if !slices.Contains(b.args, "--json=short") {
			t.Fatalf("modern busctl used text form: %v", b.args)
		}
		return commandFailure
	})
	if calls != 3 || got.Users.Status != commandFailure || got.Sessions.Status != commandFailure || got.ActiveSessions.Status != commandFailure {
		t.Fatalf("modern failure = %v after %d calls", got, calls)
	}
}

func TestBusctlTextFields(t *testing.T) {
	fields, ok := busctlFields(`s "a\\\"b\303\251\t\101" 7`)
	if !ok || len(fields) != 3 || fields[0] != (busctlField{value: "s"}) ||
		fields[1] != (busctlField{value: "a\\\"bé\tA", quoted: true}) || fields[2] != (busctlField{value: "7"}) {
		t.Fatalf("fields = %#v, %v", fields, ok)
	}
	if fields, ok := busctlFields(`(so) "" "/"`); !ok || len(fields) != 3 || fields[1] != (busctlField{quoted: true}) {
		t.Fatalf("empty string fields = %#v, %v", fields, ok)
	}
	for _, line := range []string{
		"", " s", "s ", `s  "a"`, `s"a"`, `s "a`, `s "a\"`, `s "\400"`, `s "\8aa"`, `s "\1"`,
		"s \"\x01\"", `s "\377"`, "s \"\xc3\xa9\"",
	} {
		if fields, ok := busctlFields(line); ok {
			t.Fatalf("accepted %q as %#v", line, fields)
		}
	}
}

func TestLegacyBusctlTextShapes(t *testing.T) {
	for _, tc := range []struct {
		reply string
		want  inventoryv1.CollectionStatus
	}{
		{"a(uso) 0\n", success},
		{"a(uso) 1 1000 \"alice\"\n", invalid},
		{"a(uso) 1 \"1000\" \"alice\" \"/org/freedesktop/login1/user/_1000\"\n", invalid},
		{"a(uso) 01 1000 \"alice\" \"/org/freedesktop/login1/user/_1000\"\n", invalid},
		{"a(susso) 0\n", invalid},
		{"a(uso) 4097\n", capacity},
		{"a(uso) 0", invalid},
		{"a(uso) 0\na(uso) 0\n", invalid},
	} {
		if _, status := parseSessionRowsText(strings.NewReader(tc.reply), "a(uso)"); status != tc.want {
			t.Fatalf("%q: status %v, want %v", tc.reply, status, tc.want)
		}
	}
	// A property of another native type invalidates only that field.
	session, status := parseActiveSessionText(strings.NewReader("b true\nu 5\ns \"user\"\ns \"tty\"\nb true\n(so) \"\" \"/\"\n"))
	if status != success || session.UserName.Status != invalid || session.SessionClass.Value != "user" {
		t.Fatalf("mistyped property = %v, %v", session, status)
	}
	for _, reply := range []string{
		"b true\ns \"lindm-lab\"\ns \"user\"\ns \"tty\"\nb true\n",
		"b yes\ns \"lindm-lab\"\ns \"user\"\ns \"tty\"\nb true\n(so) \"\" \"/\"\n",
		"b true\ns lindm\ns \"user\"\ns \"tty\"\nb true\n(so) \"\" \"/\"\n",
	} {
		if session, status := parseActiveSessionText(strings.NewReader(reply)); status != invalid || session != nil {
			t.Fatalf("%q: %v, %v", reply, session, status)
		}
	}
	if release, status := busctlRelease(t.Context(), func(_ context.Context, _ backend, parse func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		return parse(strings.NewReader("systemd 0239 (239)\n"))
	}); status != invalid || release != 0 {
		t.Fatalf("noncanonical release = %d, %v", release, status)
	}
}
