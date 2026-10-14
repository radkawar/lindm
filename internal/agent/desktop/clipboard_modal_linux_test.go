// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// This uses the production clipboard boundary, real D-Bus and a blocked Unix
// socket; it is not a native desktop qualification claim.
func TestClipboardModalCancelsJoinsAndDiscardsAdvertisedTransfers(t *testing.T) {
	f := newChooserBusFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	grant := &portalGrant{bus: f.portal.bus, owner: f.conn.Names()[0], handle: dbus.ObjectPath("/session/ours"), closed: make(chan struct{})}
	c := &portalClipboard{grant: grant, enabled: true, ctx: ctx, cancel: cancel, owner: true, hasText: true, text: "prequeued approval", mime: clipboardUTF8, expires: time.Now().Add(time.Minute), serials: make(map[uint32]struct{})}
	grant.clipboard = c
	joined := make(chan struct{})
	withdrawn := make(chan bool, 1)
	if err := f.conn.ExportMethodTable(map[string]any{"SetSelection": func(handle dbus.ObjectPath, options map[string]dbus.Variant) *dbus.Error {
		joinedFirst := false
		select {
		case <-joined:
			joinedFirst = true
		default:
		}
		mimes, ok := options["mime_types"].Value().([]string)
		withdrawn <- joinedFirst && handle == grant.handle && ok && len(mimes) == 0
		return nil
	}}, portalPath, clipboardIface); err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(fds[1]); err != nil {
			t.Error(err)
		}
	}()
	var fill [4096]byte
	for {
		if _, err := unix.Write(fds[0], fill[:]); errors.Is(err, unix.EAGAIN) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	operation, finish, err := c.operation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		err := writeClipboardFD(operation, dbus.UnixFD(fds[0]), "must not reach the chooser")
		close(joined)
		finish()
		writeDone <- err
	}()
	if err := grant.PauseClipboard(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err == nil {
		t.Fatal("modal boundary let blocked clipboard write finish successfully")
	}
	if !<-withdrawn {
		t.Fatal("clipboard text remained advertised or native transfer was not joined")
	}
	if _, allowed, _ := c.claimTransfer(clipboardUTF8, 1, 10, time.Now()); allowed {
		t.Fatal("paused advertised transfer supplied text")
	}
	if _, _, err := c.operation(ctx); err == nil {
		t.Fatal("clipboard read/write operation admitted while modal")
	}
	if err := grant.ResumeClipboard(); err != nil {
		t.Fatal(err)
	}
	if _, allowed, _ := c.claimTransfer(clipboardUTF8, 2, 11, time.Now()); allowed {
		t.Fatal("resume replayed old advertised transfer")
	}
	if c.hasText || c.text != "" || c.mime != "" || c.owner {
		t.Fatal("resume restored pre-modal clipboard state")
	}
}
