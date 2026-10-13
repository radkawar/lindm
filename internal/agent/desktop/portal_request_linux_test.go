//go:build linux

package desktop

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// privateSessionBus starts a private dbus-daemon whose server connection owns
// names, and connects the helper's SessionBus to it. It qualifies wire
// semantics against controlled services, not a compositor, notification
// server or a user's native consent.
func privateSessionBus(t *testing.T, ctx context.Context, names ...string) (server *dbus.Conn, bus *SessionBus) {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("private D-Bus boundary needs dbus-daemon")
	}
	ctx, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(ctx, daemon, "--session", "--nofork", "--print-address=1", "--nopidfile")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		var exit *exec.ExitError
		if err := command.Wait(); err != nil && !errors.As(err, &exit) {
			t.Error(err)
		}
	})
	address, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	server, err = dbus.Connect(strings.TrimSpace(address))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, name := range names {
		if reply, err := server.RequestName(name, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
			t.Fatalf("%s owner: %v %v", name, reply, err)
		}
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", strings.TrimSpace(address))
	bus, err = ConnectSessionBus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bus.Close(); err != nil {
			t.Error(err)
		}
	})
	return server, bus
}

func TestPortalRequestClosesBeforeMethodAcknowledgement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	server, bus := privateSessionBus(t, ctx, portalName)
	started := make(chan dbus.ObjectPath, 1)
	closed := make(chan dbus.ObjectPath, 1)
	release := make(chan struct{})
	defer close(release)
	if err := server.ExportMethodTable(map[string]any{"CreateSession": func(sender dbus.Sender, options map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
		token, ok := options["handle_token"].Value().(string)
		if !ok {
			return "", dbus.MakeFailedError(errors.New("missing handle token"))
		}
		path := dbus.ObjectPath("/org/freedesktop/portal/desktop/request/" + strings.ReplaceAll(strings.TrimPrefix(string(sender), ":"), ".", "_") + "/" + token)
		if err := server.ExportMethodTable(map[string]any{"Close": func(caller dbus.Sender) *dbus.Error {
			if caller != sender {
				return dbus.MakeFailedError(errors.New("foreign caller"))
			}
			closed <- path
			return nil
		}}, path, requestIface); err != nil {
			return "", dbus.MakeFailedError(err)
		}
		started <- path
		select {
		case <-release:
		case <-ctx.Done():
		}
		return path, nil
	}}, portalPath, remoteDesktopIface); err != nil {
		t.Fatal(err)
	}
	portal, err := NewDesktopPortal(bus, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := bus.nameOwner(ctx, portalName)
	if err != nil {
		t.Fatal(err)
	}
	sender := strings.ReplaceAll(strings.TrimPrefix(bus.conn.Names()[0], ":"), ".", "_")
	requestCtx, stop := context.WithCancel(ctx)
	defer stop()
	result := make(chan error, 1)
	go func() {
		values, err := portal.request(requestCtx, owner, sender, remoteDesktopIface+".CreateSession", nil, map[string]dbus.Variant{})
		if values != nil {
			err = errors.Join(err, errors.New("cancelled request returned authority"))
		}
		result <- err
	}()
	var expected dbus.ObjectPath
	select {
	case expected = <-started:
	case <-ctx.Done():
		t.Fatal("request not exported")
	}
	stop()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrPortalCancelled) {
			t.Fatalf("cancellation semantics changed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("cancelled request did not finish")
	}
	select {
	case path := <-closed:
		if path != expected {
			t.Fatal("wrong predicted handle closed")
		}
	case <-ctx.Done():
		t.Fatal("predicted request was not closed before acknowledgement")
	}
}
