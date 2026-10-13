//go:build linux

package desktop

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// replyDescriptor returns a pipe whose read end is owned by a reply
// descriptor; writes to the returned end fail with EPIPE once that
// descriptor is closed.
func replyDescriptor(t *testing.T) (dbus.UnixFD, *os.File) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = write.Close() })
	fd, err := syscall.Dup(int(read.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	return dbus.UnixFD(fd), write
}

func waitReaderClosed(t *testing.T, write *os.File) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := write.Write([]byte{0})
		if errors.Is(err, syscall.EPIPE) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("reply descriptor stayed open")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A remote the portal returns after the helper stopped waiting is closed
// rather than leaked: godbus would drop that reply with its descriptor open.
func TestLatePipeWireRemoteIsClosed(t *testing.T) {
	fd, write := replyDescriptor(t)
	replies := make(chan *dbus.Call, 1)
	wait, cancel := context.WithCancel(t.Context())
	cancel()
	file, err := awaitPipeWireRemote(wait, replies)
	if file != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("abandoned wait returned %v, %v", file, err)
	}
	replies <- &dbus.Call{Body: []any{fd}}
	waitReaderClosed(t, write)
}

func TestPipeWireRemoteOwnsEveryReplyDescriptor(t *testing.T) {
	fd, write := replyDescriptor(t)
	replies := make(chan *dbus.Call, 1)
	replies <- &dbus.Call{Body: []any{fd}}
	file, err := awaitPipeWireRemote(t.Context(), replies)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := write.Write([]byte{1}); err != nil {
		t.Fatalf("returned remote is not the reply descriptor: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	waitReaderClosed(t, write)

	first, firstWrite := replyDescriptor(t)
	second, secondWrite := replyDescriptor(t)
	if file, err := pipeWireRemote(&dbus.Call{Body: []any{first, second}}); file != nil || err == nil {
		t.Fatalf("two descriptors accepted: %v, %v", file, err)
	}
	waitReaderClosed(t, firstWrite)
	waitReaderClosed(t, secondWrite)

	for _, reply := range []*dbus.Call{
		{Body: []any{dbus.UnixFD(-1)}},
		{Body: []any{uint32(3)}},
		{Err: dbus.MakeFailedError(errors.New("no streams"))},
	} {
		if file, err := pipeWireRemote(reply); file != nil || err == nil {
			t.Fatalf("%+v accepted: %v, %v", reply, file, err)
		}
	}
}

// Only this session's own owner announcement releases OpenPipeWire, and a
// repeated one is harmless.
func TestClipboardAnnouncementIsOwnSessionOnly(t *testing.T) {
	grant := &portalGrant{handle: "/session/ours", closed: make(chan struct{})}
	c := &portalClipboard{grant: grant, serials: make(map[uint32]struct{}), announced: make(chan struct{})}
	options := map[string]dbus.Variant{"mime_types": dbus.MakeVariant([]string{clipboardUTF8})}
	c.observeOwner([]any{dbus.ObjectPath("/session/other"), options}, 1)
	select {
	case <-c.announced:
		t.Fatal("another session's owner change counted as this session's announcement")
	default:
	}
	c.observeOwner([]any{grant.handle, options}, 2)
	c.observeOwner([]any{grant.handle, options}, 3)
	select {
	case <-c.announced:
	default:
		t.Fatal("own owner announcement not recorded")
	}
}

func TestAwaitAnnouncementHoldsUntilAnnouncedSettledOrStopped(t *testing.T) {
	pending := func() *portalClipboard {
		return &portalClipboard{announced: make(chan struct{}), done: make(chan struct{}), settled: time.Now().Add(time.Hour)}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := pending().awaitAnnouncement(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unannounced clipboard released OpenPipeWire before its settle bound: %v", err)
	}
	announced := pending()
	close(announced.announced)
	stopped := pending()
	close(stopped.done)
	settled := pending()
	settled.settled = time.Now()
	for name, c := range map[string]*portalClipboard{"announced": announced, "stopped": stopped, "settled": settled} {
		if err := c.awaitAnnouncement(t.Context()); err != nil {
			t.Fatalf("%s clipboard held OpenPipeWire: %v", name, err)
		}
	}
}

// On a real bus, the portal's forwarded SelectionOwnerChanged releases
// OpenPipeWireRemote, which a controlled portal service observes only after
// the announcement. This qualifies the helper's ordering, not the portal.
func TestPipeWireRemoteFollowsClipboardAnnouncement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	server, bus := privateSessionBus(t, ctx, portalName)
	handle := dbus.ObjectPath("/org/freedesktop/portal/desktop/session/1_1/lindm")
	fd, _ := replyDescriptor(t)
	t.Cleanup(func() { _ = syscall.Close(int(fd)) })
	var announced atomic.Bool
	opened := make(chan bool, 1)
	if err := server.ExportMethodTable(map[string]any{"RequestClipboard": func(dbus.ObjectPath, map[string]dbus.Variant) *dbus.Error {
		return nil
	}}, portalPath, clipboardIface); err != nil {
		t.Fatal(err)
	}
	if err := server.ExportMethodTable(map[string]any{"OpenPipeWireRemote": func(session dbus.ObjectPath, _ map[string]dbus.Variant) (dbus.UnixFD, *dbus.Error) {
		opened <- announced.Load() && session == handle
		return fd, nil
	}}, portalPath, screenCastIface); err != nil {
		t.Fatal(err)
	}
	owner, err := bus.nameOwner(ctx, portalName)
	if err != nil {
		t.Fatal(err)
	}
	grant := &portalGrant{bus: bus, owner: owner, handle: handle, closed: make(chan struct{})}
	if err := grant.requestClipboard(ctx, ctx); err != nil {
		t.Fatal(err)
	}
	grant.startClipboard(map[string]dbus.Variant{"clipboard_enabled": dbus.MakeVariant(true)})
	t.Cleanup(grant.clipboard.close)
	grant.clipboard.settled = time.Now().Add(time.Hour)
	unannounced, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	remote, err := grant.OpenPipeWire(unannounced)
	stop()
	if remote != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("OpenPipeWireRemote was not held for the owner announcement: %v", err)
	}
	announced.Store(true)
	if err := server.Emit(portalPath, clipboardIface+".SelectionOwnerChanged", handle, map[string]dbus.Variant{"mime_types": dbus.MakeVariant([]string{clipboardUTF8}), "session_is_owner": dbus.MakeVariant(false)}); err != nil {
		t.Fatal(err)
	}
	remote, err = grant.OpenPipeWire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Close(); err != nil {
		t.Fatal(err)
	}
	if ordered := <-opened; !ordered {
		t.Fatal("OpenPipeWireRemote preceded the session's clipboard owner announcement")
	}
}
