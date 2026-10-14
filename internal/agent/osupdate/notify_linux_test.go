// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestRebootMessage(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	at := time.Date(2026, 10, 12, 1, 30, 0, 0, time.UTC)
	if got, want := rebootMessage("Patch Tuesday maintenance", at, berlin), "Patch Tuesday maintenance (lindm: reboot scheduled for Mon, 12 Oct 2026 03:30:00 CEST to complete OS updates)"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
	if got, want := rebootMessage("", at, berlin), "(lindm: reboot scheduled for Mon, 12 Oct 2026 03:30:00 CEST to complete OS updates)"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}

type notifyCall struct {
	app, icon, summary, body string
	replaces                 uint32
	actions                  []string
	urgency                  any
	expire                   int32
}

type notificationServer struct {
	calls chan notifyCall
	block chan struct{}
}

func (s *notificationServer) Notify(app string, replaces uint32, icon, summary, body string, actions []string, hints map[string]dbus.Variant, expire int32) (uint32, *dbus.Error) {
	if s.block != nil {
		<-s.block
	}
	s.calls <- notifyCall{app: app, icon: icon, summary: summary, body: body, replaces: replaces, actions: actions, urgency: hints["urgency"].Value(), expire: expire}
	return 7, nil
}

// startSessionBus runs a private dbus-daemon owned by the test user and
// exports an org.freedesktop.Notifications server on it.
func startSessionBus(t *testing.T, server *notificationServer) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not installed")
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "bus")
	config := filepath.Join(dir, "session.conf")
	if err := os.WriteFile(config, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=`+socket+`</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, daemon, "--config-file="+config, "--nofork", "--print-address=1", "--nopidfile")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	ready := make(chan error, 1)
	go func() {
		_, err := bufio.NewReader(stdout).ReadString('\n')
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("dbus-daemon did not start: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dbus-daemon start timed out")
	}
	conn, err := dbus.Connect("unix:path=" + socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Export(server, notificationsPath, notificationsName); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.RequestName(notificationsName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request name: %v %v", reply, err)
	}
	return socket
}

func TestNotifyDesktopPostsCriticalNotification(t *testing.T) {
	server := &notificationServer{calls: make(chan notifyCall, 1)}
	socket := startSessionBus(t, server)
	berlin := mustZone(t, "Europe/Berlin")
	body := rebootMessage("Planned maintenance", time.Date(2026, 10, 12, 1, 30, 0, 0, time.UTC), berlin)
	ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
	defer cancel()
	if err := notifyDesktop(ctx, socket, uint32(os.Geteuid()), body); err != nil {
		t.Fatal(err)
	}
	call := <-server.calls
	if call.app != "lindm" || call.summary != notificationSummary || call.body != body || call.icon != "" || call.replaces != 0 || len(call.actions) != 0 || call.expire != -1 {
		t.Fatalf("notify call = %+v", call)
	}
	if urgency, ok := call.urgency.(byte); !ok || urgency != 2 {
		t.Fatalf("urgency = %#v, want critical byte 2", call.urgency)
	}
	if !strings.Contains(call.body, "Planned maintenance (lindm: reboot scheduled for Mon, 12 Oct 2026 03:30:00 CEST to complete OS updates)") {
		t.Fatalf("body = %q", call.body)
	}
}

func TestNotifyDesktopIsBounded(t *testing.T) {
	server := &notificationServer{calls: make(chan notifyCall, 1), block: make(chan struct{})}
	socket := startSessionBus(t, server)
	defer close(server.block)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := notifyDesktop(ctx, socket, uint32(os.Geteuid()), "body"); err == nil {
		t.Fatal("unanswered notification reported success")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("notification wait took %v", elapsed)
	}
}

func TestNotifyDesktopRefusesForeignBusAndControlCharacters(t *testing.T) {
	server := &notificationServer{calls: make(chan notifyCall, 1)}
	socket := startSessionBus(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
	defer cancel()
	if err := notifyDesktop(ctx, socket, uint32(os.Geteuid())+1, "body"); !errors.Is(err, errUntrustedBus) {
		t.Fatalf("foreign bus owner = %v", err)
	}
	if err := notifyDesktop(ctx, socket, uint32(os.Geteuid()), "line\nbreak"); !errors.Is(err, errNotifyInput) {
		t.Fatalf("control character = %v", err)
	}
	if err := notifyDesktop(context.Background(), socket, uint32(os.Geteuid()), "body"); !errors.Is(err, errBusDeadline) {
		t.Fatalf("unbounded call = %v", err)
	}
}

func TestNotifyChildAcceptsOnlyItsOwnUserBus(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the notify child refuses root")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/other/bus")
	if err := Notify(context.Background(), strings.NewReader("body")); !errors.Is(err, errNotifyInput) {
		t.Fatalf("foreign address = %v", err)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+userBusPath(uint32(os.Geteuid())))
	if err := Notify(context.Background(), strings.NewReader(strings.Repeat("x", maxNotificationBody+1))); !errors.Is(err, errNotifyInput) {
		t.Fatalf("oversized body = %v", err)
	}
}
