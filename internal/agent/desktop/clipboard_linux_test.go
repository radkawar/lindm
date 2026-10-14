// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// These tests exercise typed metadata and real Unix FDs, not a native portal.
func TestClipboardMIMENormalizesOnlyDocumentedAndGNOME46Tuple(t *testing.T) {
	for _, variant := range []dbus.Variant{
		dbus.MakeVariant([]string{clipboardUTF8}),
		dbus.MakeVariantWithSignature([]any{[]string{clipboardUTF8}}, dbus.ParseSignatureMust("(as)")),
		dbus.MakeVariant([]any{[]string{clipboardUTF8}}),
	} {
		types, err := normalizeClipboardMIMEs(variant)
		if err != nil || len(types) != 1 || types[0] != clipboardUTF8 {
			t.Fatalf("normalization = %v, %v", types, err)
		}
	}
	for _, variant := range []dbus.Variant{
		dbus.MakeVariant(clipboardUTF8),
		dbus.MakeVariant([][]string{{clipboardUTF8}}),
		dbus.MakeVariant([]string{strings.Repeat("a", 129)}),
		dbus.MakeVariant(make([]string, 33)),
		dbus.MakeVariant(dbus.MakeVariant([]string{clipboardUTF8})),
		dbus.MakeVariant([]any{[]string{clipboardUTF8}, []string{clipboardUTF8}}),
		dbus.MakeVariant([]any{clipboardUTF8}),
	} {
		if _, err := normalizeClipboardMIMEs(variant); err == nil {
			t.Fatalf("accepted %v", variant)
		}
	}
	for _, mime := range []string{"text/html", "text/plain", "application/vnd.portal.filetransfer", "image/png", "UTF8_STRING;extra"} {
		if clipboardTextMIME(mime) {
			t.Fatalf("accepted non-UTF8-text format %s", mime)
		}
	}
}

func TestClipboardOwnershipAndSerialFences(t *testing.T) {
	now := time.Now()
	grant := &portalGrant{handle: dbus.ObjectPath("/session/ours"), closed: make(chan struct{})}
	c := &portalClipboard{grant: grant, ctx: t.Context(), enabled: true, owner: true, hasText: true, text: "operator text", expires: now.Add(time.Minute), serials: make(map[uint32]struct{}), selectionSequence: 10, announced: make(chan struct{})}
	owner := func(handle dbus.ObjectPath, own bool) []any {
		return []any{handle, map[string]dbus.Variant{"mime_types": dbus.MakeVariant([]string{clipboardUTF8}), "session_is_owner": dbus.MakeVariant(own)}}
	}
	c.observeOwner(owner("/session/other", false), 11)
	if !c.owner || c.text != "operator text" {
		t.Fatal("foreign session changed ownership")
	}
	if text, allowed, duplicate := c.claimTransfer(clipboardUTF8, 1, 9, now); text != "" || allowed || duplicate {
		t.Fatal("stale transfer read replacement text")
	}
	if _, allowed, duplicate := c.claimTransfer(clipboardUTF8, 1, 12, now); allowed || !duplicate {
		t.Fatal("serial replay accepted")
	}
	if text, allowed, duplicate := c.claimTransfer(clipboardUTF8, 2, 12, now); text != "operator text" || !allowed || duplicate {
		t.Fatal("explicit current transfer refused")
	}
	if text, allowed, _ := c.claimTransfer("text/html", 3, 13, now); text != "" || allowed {
		t.Fatal("nontext transfer exposed content")
	}
	if text, allowed, _ := c.claimTransfer(clipboardUTF8, 4, 14, now.Add(time.Minute)); text != "" || allowed {
		t.Fatal("expired text exposed")
	}
	c.observeOwner(owner(grant.handle, false), 15)
	if c.owner || c.text != "" || c.hasText || c.mime != clipboardUTF8 {
		t.Fatal("new user selection did not clear operator contents and retain metadata")
	}
	for i := uint32(5); i <= maxClipboardTransfers; i++ {
		c.claimTransfer(clipboardUTF8, i, 16, now)
	}
	c.claimTransfer(clipboardUTF8, maxClipboardTransfers+1, 17, now)
	if len(c.serials) != maxClipboardTransfers {
		t.Fatal("serial history unbounded")
	}
	select {
	case <-grant.Closed():
	default:
		t.Fatal("serial exhaustion did not fail closed")
	}
}

func TestClipboardReadFDUTF8BoundAndClose(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		wantError  bool
	}{
		{"empty", "", false}, {"unicode", "Grüße\n日本語", false}, {"bound", strings.Repeat("x", maxClipboardBytes), false},
		{"too-large", strings.Repeat("x", maxClipboardBytes+1), true}, {"invalid-utf8", string([]byte{0xff}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := unix.Write(fds[1], []byte(tc.text)); err != nil {
				t.Fatal(err)
			}
			if err := unix.Close(fds[1]); err != nil {
				t.Fatal(err)
			}
			text, err := readClipboardFD(t.Context(), dbus.UnixFD(fds[0]))
			if (err != nil) != tc.wantError || (!tc.wantError && text != tc.text) {
				t.Fatalf("read = %q, %v", text, err)
			}
			if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatalf("received FD leaked: %v", err)
			}
		})
	}
}

func TestClipboardBlockedFDReadAndWriteCancel(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "write"}[write], func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := unix.Close(fds[1]); err != nil {
					t.Error(err)
				}
			}()
			if write {
				buf := make([]byte, 4096)
				for {
					if _, err := unix.Write(fds[0], buf); errors.Is(err, unix.EAGAIN) {
						break
					} else if err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				if write {
					done <- writeClipboardFD(ctx, dbus.UnixFD(fds[0]), "must not hang")
				} else {
					_, err := readClipboardFD(ctx, dbus.UnixFD(fds[0]))
					done <- err
				}
			}()
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled I/O succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("FD cancellation blocked")
			}
			if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatal("cancelled FD leaked")
			}
		})
	}
}

func TestClipboardRejectsRegularFileFD(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "not-a-portal-pipe")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readClipboardFD(t.Context(), dbus.UnixFD(fd)); err == nil {
		t.Fatal("accepted nonpollable filesystem FD")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("rejected FD leaked")
	}
}

func TestClipboardReadRefusalsClassifyObservedMetadataWithoutReading(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options map[string]dbus.Variant
		reason  string
	}{
		{"unobserved", nil, "clipboard_owner_unobserved"},
		{"missing", map[string]dbus.Variant{}, "clipboard_mime_missing"},
		{"malformed", map[string]dbus.Variant{"mime_types": dbus.MakeVariant("private offered data")}, "clipboard_mime_variant_invalid"},
		{"nontext", map[string]dbus.Variant{"mime_types": dbus.MakeVariant([]string{"application/private-offer"})}, "clipboard_mime_unavailable"},
		{"owned", map[string]dbus.Variant{"mime_types": dbus.MakeVariant([]string{clipboardUTF8}), "session_is_owner": dbus.MakeVariant(true)}, "clipboard_session_is_owner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A nil bus ensures no refusal attempts a native read or fallback.
			grant := &portalGrant{handle: "/session/ours"}
			grant.clipboard = &portalClipboard{grant: grant, enabled: true, announced: make(chan struct{})}
			if tc.options != nil {
				grant.clipboard.observeOwner([]any{grant.handle, tc.options}, 1)
			}
			text, err := grant.ClipboardRead(t.Context())
			if err == nil || text != "" {
				t.Fatal("unavailable selection returned clipboard text")
			}
			reason, category := clipboardReadDiagnostic(err)
			if reason != tc.reason || category != "local_refusal" {
				t.Fatalf("diagnostic = %s/%s", reason, category)
			}
		})
	}
}

type clipboardReadFailureGrant struct {
	*fakeGrant
	err error
}

func (g *clipboardReadFailureGrant) ClipboardRead(context.Context) (string, error) {
	return "private partial clipboard contents", g.err
}

func TestClipboardReadFailureLogsOnlyCategoriesAndKeepsExternalFailureGeneric(t *testing.T) {
	const private = "private clipboard or portal error data"
	for _, tc := range []struct {
		name, reason, category string
		err                    error
	}{
		{"portal", "clipboard_selection_read_failed", "dbus_access_denied", dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", []any{private})},
		{"unknown-portal", "clipboard_selection_read_failed", "dbus_other", dbus.NewError("org.example."+private, []any{private})},
		{"timeout", "clipboard_fd_read_failed", "timeout", os.ErrDeadlineExceeded},
		{"cancelled", "clipboard_fd_read_failed", "cancelled", context.Canceled},
		{"too-large", "clipboard_fd_read_failed", "text_too_large", errors.New("clipboard_text_too_large")},
		{"invalid-utf8", "clipboard_fd_read_failed", "text_not_utf8", errors.New("clipboard_text_not_utf8")},
		{"invalid-fd", "clipboard_fd_read_failed", "fd_invalid", unix.EBADF},
		{"unknown", "clipboard_fd_read_failed", "other", errors.New(private)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			var logs bytes.Buffer
			inv := tierOneInvitation(modeControl)
			s := &session{
				deps: h.helper.deps, invitation: inv,
				granted: &agentv1.AssistanceCapabilities{Policy: inv.GetEffectiveCapabilities()},
				logger:  slog.New(slog.NewTextHandler(&logs, nil)),
			}
			wrapped := fmt.Errorf("private wrapper: %w", &clipboardReadError{reason: tc.reason, err: tc.err})
			if !errors.Is(wrapped, tc.err) {
				t.Fatal("diagnostic wrapper lost underlying error identity")
			}
			grant := &clipboardReadFailureGrant{fakeGrant: &fakeGrant{}, err: wrapped}
			command := &agentv1.AssistanceCommand{
				Kind:     agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ,
				Deadline: timestamppb.New(h.clock.Now().Add(20 * time.Second)),
			}
			result := s.executeCommand(t.Context(), &sessionResources{grant: grant}, command)
			if result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED || result.GetReason() != "command_failed" || result.GetText() != "" {
				t.Fatal("diagnostics changed external failure or exposed partial clipboard text")
			}
			line := logs.String()
			if !strings.Contains(line, "reason="+tc.reason) || !strings.Contains(line, "category="+tc.category) {
				t.Fatalf("missing classified diagnostic: %s", line)
			}
			if strings.Contains(line, "private") || strings.Contains(line, "org.example") {
				t.Fatal("diagnostics exposed clipboard content or arbitrary error values")
			}
		})
	}
}
