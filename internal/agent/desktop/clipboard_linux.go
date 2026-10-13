//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	clipboardIface           = "org.freedesktop.portal.Clipboard"
	clipboardUTF8            = "text/plain;charset=utf-8"
	maxClipboardBytes        = 16 << 10
	clipboardTransferTimeout = 5 * time.Second
	maxClipboardTransfers    = 256
	// clipboardAnnounceSettle bounds how long OpenPipeWire waits after Start
	// for the backend's announcement of the current clipboard owner; see
	// awaitAnnouncement. Mutter announces an existing owner when the backend
	// enables the clipboard during Start, and xdg-desktop-portal forwarded it
	// about 1 ms after the Start response on the Fedora 44 aarch64 lab; with
	// no owner nothing is announced and the wait ends here.
	clipboardAnnounceSettle = time.Second
)

// portalClipboard retains metadata, and only explicitly supplied operator text.
// SelectionOwnerChanged never reads clipboard contents. All calls address the
// unique owner and the same RemoteDesktop session that granted access.
type portalClipboard struct {
	grant             *portalGrant
	events            *busWatch
	enabled           bool
	ctx               context.Context
	cancel            context.CancelFunc
	done              chan struct{}
	mu                sync.Mutex
	mime              string
	owner             bool
	mimeReason        string
	version           uint64
	text              string
	hasText           bool
	expires           time.Time
	serials           map[uint32]struct{}
	selectionSequence dbus.Sequence
	// announced closes on the first SelectionOwnerChanged for this session;
	// settled is when OpenPipeWire stops waiting for it.
	announced    chan struct{}
	announceOnce sync.Once
	settled      time.Time
}

func (g *portalGrant) requestClipboard(ctx, lifetime context.Context) error {
	err := g.bus.call(ctx, g.owner, portalPath, clipboardIface+".RequestClipboard", g.handle, map[string]dbus.Variant{}).Err
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if reason := clipboardRequestRefusal(err); reason != "" {
			g.clipboardReason = reason
			return nil
		}
		return err
	}
	// A request is not a grant. Subscribe before Start but do not process any
	// selection/transfer signal until its clipboard_enabled response is true.
	events, err := g.bus.watch(ctx, g.owner, portalPath, clipboardIface, "")
	if err != nil {
		return err
	}
	life, cancel := context.WithCancel(lifetime)
	g.clipboard = &portalClipboard{grant: g, events: events, ctx: life, cancel: cancel, serials: make(map[uint32]struct{}), announced: make(chan struct{})}
	return nil
}

// Only explicit optional-interface failures can continue. In xdg-desktop-portal
// 1.20, RequestClipboard AccessDenied means an invalid session/type and Failed
// means invalid session state; neither is an independent clipboard refusal.
// Timeout/NoReply, connection loss and cancellation are never "unsupported".
func clipboardRequestRefusal(err error) string {
	switch dbusErrorName(err) {
	case "org.freedesktop.DBus.Error.UnknownMethod", "org.freedesktop.DBus.Error.UnknownInterface",
		"org.freedesktop.DBus.Error.NotSupported", "org.freedesktop.portal.Error.NotSupported":
		return "portal_clipboard_unsupported"
	case "org.freedesktop.portal.Error.NotAllowed":
		return "portal_clipboard_denied"
	default:
		return ""
	}
}

func dbusErrorName(err error) string {
	var pointer *dbus.Error
	if errors.As(err, &pointer) {
		return pointer.Name
	}
	var value dbus.Error
	if errors.As(err, &value) {
		return value.Name
	}
	return ""
}

func (g *portalGrant) ClipboardGranted() bool  { return g.clipboard != nil && g.clipboard.enabled }
func (g *portalGrant) ClipboardReason() string { return g.clipboardReason }

func (g *portalGrant) startClipboard(started map[string]dbus.Variant) {
	// A spurious Start flag can never manufacture a successful prior request.
	if g.clipboard == nil {
		return
	}
	enabled, valid := started["clipboard_enabled"].Value().(bool)
	if !valid || !enabled {
		g.clipboard.close()
		g.clipboard = nil
		g.clipboardReason = "portal_clipboard_not_granted"
		return
	}
	g.clipboard.enabled = true
	g.clipboard.start()
}

func (c *portalClipboard) start() {
	c.done = make(chan struct{})
	c.settled = time.Now().Add(clipboardAnnounceSettle)
	go c.run()
}

// awaitAnnouncement returns once the session's current clipboard owner has
// been announced, the settle bound passed or the clipboard stopped.
//
// xdg-desktop-portal 1.21.1 serves OpenPipeWireRemote holding the session's
// lock while it creates and destroys a PipeWire context. With PipeWire 1.6
// that context's module-rt thread reads the portal's own Realtime properties,
// which only the portal main loop answers, and destroying the context joins
// that thread. The main loop forwards SelectionOwnerChanged under the same
// session lock (flatpak/xdg-desktop-portal#2091). The announcement after Start
// therefore must be forwarded before OpenPipeWireRemote is sent; otherwise the
// portal stalls until libdbus times out the three reads (75 s on the lab).
func (c *portalClipboard) awaitAnnouncement(ctx context.Context) error {
	wait := time.Until(c.settled)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-c.announced:
	case <-timer.C:
	case <-c.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (c *portalClipboard) close() {
	c.cancel()
	if c.done != nil {
		<-c.done
	}
	ctx, cancel := context.WithTimeout(context.Background(), busCallTimeout)
	defer cancel()
	// Removing watches is best effort after the owning bus or session closes.
	_ = c.events.stop(ctx)
	c.mu.Lock()
	c.text, c.hasText, c.mime = "", false, ""
	clear(c.serials)
	c.mu.Unlock()
}

func (c *portalClipboard) run() {
	defer close(c.done)
	defer c.cancel()
	defer func() {
		c.mu.Lock()
		c.text, c.hasText, c.mime = "", false, ""
		c.mu.Unlock()
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.grant.Closed():
			return
		case <-c.grant.bus.done:
			return
		case <-ticker.C:
			c.mu.Lock()
			if c.hasText && !time.Now().Before(c.expires) {
				c.text, c.hasText = "", false
			}
			c.mu.Unlock()
		case <-c.events.overflow:
			// Missing ownership or transfer signals cannot be treated as current.
			c.grant.markClosed()
			return
		case signal := <-c.events.signals:
			switch signal.Name {
			case clipboardIface + ".SelectionOwnerChanged":
				c.observeOwner(signal.Body, signal.Sequence)
			case clipboardIface + ".SelectionTransfer":
				c.transfer(signal.Body, signal.Sequence)
			}
		}
	}
}

// normalizeClipboardMIMEs accepts precisely the documented as variant and the
// GNOME 46 backend's (as) tuple. godbus decodes a received (as) struct as []any
// with signature av (ubuntu24arm-tier1-12 clipboard_mime_variant_invalid), so
// av is accepted only as exactly one string array. Arbitrary nested/flattened
// variants fail closed.
func normalizeClipboardMIMEs(value dbus.Variant) ([]string, error) {
	var types []string
	switch value.Signature().String() {
	case "as":
		if err := value.Store(&types); err != nil {
			return nil, err
		}
	case "(as)":
		var tuple struct{ Types []string }
		if err := value.Store(&tuple); err != nil {
			return nil, err
		}
		types = tuple.Types
	case "av":
		fields, ok := value.Value().([]any)
		if !ok || len(fields) != 1 {
			return nil, errors.New("clipboard_mime_variant_invalid")
		}
		if types, ok = fields[0].([]string); !ok {
			return nil, errors.New("clipboard_mime_variant_invalid")
		}
	default:
		// A D-Bus type signature only; never the offered MIME strings.
		slog.Warn("clipboard owner metadata has an unsupported mime_types signature", "signature", value.Signature().String())
		return nil, errors.New("clipboard_mime_variant_invalid")
	}
	if len(types) > 32 {
		return nil, errors.New("clipboard_mime_count_exceeded")
	}
	for _, mime := range types {
		if len(mime) > 128 {
			return nil, errors.New("clipboard_mime_invalid")
		}
	}
	return types, nil
}

func clipboardTextMIME(mime string) bool {
	return mime == clipboardUTF8 || mime == "text/plain;charset=UTF-8" || mime == "UTF8_STRING"
}

// Clipboard diagnostics contain only locally chosen categories. In particular,
// a portal error's message/body and offered MIME strings may contain user data.
type clipboardReadError struct {
	reason string
	err    error
}

func (e *clipboardReadError) Error() string { return e.reason }
func (e *clipboardReadError) Unwrap() error { return e.err }

func clipboardReadDiagnostic(err error) (reason, category string) {
	reason = "clipboard_read_failed"
	var failure *clipboardReadError
	cause := err
	if errors.As(err, &failure) {
		reason = failure.reason
		cause = failure.err
	}
	switch {
	case errors.Is(err, context.Canceled):
		return reason, "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return reason, "timeout"
	case errors.Is(err, os.ErrNoDeadline):
		return reason, "fd_deadline_unsupported"
	case errors.Is(err, unix.EBADF):
		return reason, "fd_invalid"
	}
	switch dbusErrorName(err) {
	case "org.freedesktop.DBus.Error.AccessDenied":
		return reason, "dbus_access_denied"
	case "org.freedesktop.DBus.Error.NoReply":
		return reason, "dbus_no_reply"
	case "org.freedesktop.DBus.Error.FileNotFound":
		return reason, "dbus_selection_missing"
	case "org.freedesktop.DBus.Error.LimitsExceeded":
		return reason, "dbus_limits_exceeded"
	case "org.freedesktop.DBus.Error.Failed", "org.freedesktop.portal.Error.Failed":
		return reason, "dbus_failed"
	}
	if dbusErrorName(err) != "" {
		return reason, "dbus_other"
	}
	if failure != nil && failure.err == nil {
		return reason, "local_refusal"
	}
	// Exact local validation errors only; never copy an arbitrary error string.
	if cause != nil {
		switch cause.Error() {
		case "clipboard_text_too_large":
			return reason, "text_too_large"
		case "clipboard_text_not_utf8":
			return reason, "text_not_utf8"
		case "clipboard_fd_invalid", "clipboard_fd_not_pollable":
			return reason, "fd_invalid"
		}
	}
	return reason, "other"
}

func (c *portalClipboard) observeOwner(body []any, sequence dbus.Sequence) {
	var handle dbus.ObjectPath
	var options map[string]dbus.Variant
	if dbus.Store(body, &handle, &options) != nil || handle != c.grant.handle {
		return
	}
	c.announceOnce.Do(func() { close(c.announced) })
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version++
	c.mime = ""
	c.mimeReason = "clipboard_mime_unavailable"
	owner, valid := options["session_is_owner"].Value().(bool)
	c.owner = valid && owner
	if !c.owner && sequence > c.selectionSequence {
		c.text, c.hasText = "", false
	}
	value, present := options["mime_types"]
	if !present {
		c.mimeReason = "clipboard_mime_missing"
		return
	}
	types, err := normalizeClipboardMIMEs(value)
	if err != nil {
		// Only locally chosen codes; never an offered MIME string.
		c.mimeReason = "clipboard_mime_invalid"
		if code := err.Error(); strings.HasPrefix(code, "clipboard_mime_") {
			c.mimeReason = code
		}
		return
	}
	for _, mime := range types {
		if clipboardTextMIME(mime) {
			c.mime = mime
			c.mimeReason = ""
			return
		}
	}
}

func (g *portalGrant) ClipboardWrite(ctx context.Context, text string, deadline time.Time) error {
	if !g.ClipboardGranted() {
		return errors.New("clipboard_not_granted")
	}
	c := g.clipboard
	c.mu.Lock()
	defer c.mu.Unlock()
	c.text, c.hasText, c.expires = text, true, deadline
	call := g.bus.call(ctx, g.owner, portalPath, clipboardIface+".SetSelection", g.handle,
		map[string]dbus.Variant{"mime_types": dbus.MakeVariant([]string{clipboardUTF8})})
	if call.Err != nil {
		c.text, c.hasText = "", false
		return fmt.Errorf("set clipboard selection: %w", call.Err)
	}
	c.owner = true
	c.selectionSequence = call.ResponseSequence
	return nil // Selection ownership is not evidence that the user pasted.
}

func (g *portalGrant) ClipboardRead(ctx context.Context) (string, error) {
	if !g.ClipboardGranted() {
		return "", &clipboardReadError{reason: "clipboard_not_granted"}
	}
	c := g.clipboard
	c.mu.Lock()
	mime, mimeReason, version, owner := c.mime, c.mimeReason, c.version, c.owner
	c.mu.Unlock()
	if owner {
		return "", &clipboardReadError{reason: "clipboard_session_is_owner"}
	}
	if mime == "" {
		if version == 0 {
			mimeReason = "clipboard_owner_unobserved"
		} else if mimeReason == "" {
			mimeReason = "clipboard_mime_unavailable"
		}
		return "", &clipboardReadError{reason: mimeReason}
	}
	var fd dbus.UnixFD
	if err := g.bus.call(ctx, g.owner, portalPath, clipboardIface+".SelectionRead", g.handle, mime).Store(&fd); err != nil {
		return "", &clipboardReadError{reason: "clipboard_selection_read_failed", err: err}
	}
	text, err := readClipboardFD(ctx, fd)
	if err != nil {
		return "", &clipboardReadError{reason: "clipboard_fd_read_failed", err: err}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if version != c.version || c.owner {
		return "", &clipboardReadError{reason: "clipboard_owner_changed"}
	}
	return text, nil
}

func (c *portalClipboard) transfer(body []any, sequence dbus.Sequence) {
	var handle dbus.ObjectPath
	var mime string
	var serial uint32
	if dbus.Store(body, &handle, &mime, &serial) != nil || handle != c.grant.handle {
		return
	}
	text, allowed, duplicate := c.claimTransfer(mime, serial, sequence, time.Now())
	if duplicate {
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, clipboardTransferTimeout)
	defer cancel()
	success := false
	if allowed {
		var fd dbus.UnixFD
		if c.grant.bus.call(ctx, c.grant.owner, portalPath, clipboardIface+".SelectionWrite", handle, serial).Store(&fd) == nil {
			success = writeClipboardFD(ctx, fd, text) == nil
		}
	}
	// The serial is consumed once whether data delivery succeeds or fails.
	finish, stop := context.WithTimeout(context.WithoutCancel(ctx), busCallTimeout)
	defer stop()
	_ = c.grant.bus.call(finish, c.grant.owner, portalPath, clipboardIface+".SelectionWriteDone", handle, serial, success).Err
}

func (c *portalClipboard) claimTransfer(mime string, serial uint32, sequence dbus.Sequence, now time.Time) (string, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, duplicate := c.serials[serial]; duplicate {
		return "", false, true
	}
	if len(c.serials) >= maxClipboardTransfers {
		c.grant.markClosed()
		return "", false, true
	}
	c.serials[serial] = struct{}{}
	allowed := c.ctx.Err() == nil && c.enabled && c.owner && c.hasText && now.Before(c.expires) && clipboardTextMIME(mime) && sequence > c.selectionSequence
	if !allowed {
		return "", false, false
	}
	return c.text, true, false
}

// clipboardFile takes ownership of the received FD, accepts only pollable
// pipes/sockets, and bounds every read/write without a blocked I/O goroutine.
func clipboardFile(ctx context.Context, fd dbus.UnixFD) (*os.File, func(), error) {
	if fd < 0 {
		return nil, nil, errors.New("clipboard_fd_invalid")
	}
	unix.CloseOnExec(int(fd))
	var stat unix.Stat_t
	if err := unix.Fstat(int(fd), &stat); err != nil {
		return nil, nil, errors.Join(err, unix.Close(int(fd)))
	}
	kind := stat.Mode & unix.S_IFMT
	if kind != unix.S_IFIFO && kind != unix.S_IFSOCK {
		return nil, nil, errors.Join(errors.New("clipboard_fd_not_pollable"), unix.Close(int(fd)))
	}
	if err := unix.SetNonblock(int(fd), true); err != nil {
		return nil, nil, errors.Join(err, unix.Close(int(fd)))
	}
	file := os.NewFile(uintptr(fd), "portal-clipboard")
	deadline := time.Now().Add(clipboardTransferTimeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := file.SetDeadline(deadline); err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	stop := context.AfterFunc(ctx, func() { _ = file.SetDeadline(time.Now()) })
	return file, func() { stop() }, nil
}

func readClipboardFD(ctx context.Context, fd dbus.UnixFD) (text string, err error) {
	file, stop, err := clipboardFile(ctx, fd)
	if err != nil {
		return "", err
	}
	defer func() { stop(); err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(io.LimitReader(file, maxClipboardBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxClipboardBytes {
		return "", errors.New("clipboard_text_too_large")
	}
	if !utf8.Valid(data) {
		return "", errors.New("clipboard_text_not_utf8")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return string(data), nil
}

func writeClipboardFD(ctx context.Context, fd dbus.UnixFD, text string) (err error) {
	file, stop, err := clipboardFile(ctx, fd)
	if err != nil {
		return err
	}
	defer func() { stop(); err = errors.Join(err, file.Close()) }()
	_, err = io.Copy(file, strings.NewReader(text))
	return errors.Join(err, ctx.Err())
}
