// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// These tests exercise the production chooser against a controlled service on a
// private real D-Bus daemon. They are method/response/lifetime boundary tests,
// not native FileChooser, GNOME, Nautilus or local-consent qualification.
func TestChooseFileOpensOnlyNativeSelection(t *testing.T) {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Skip("chooser storage requires the current nonroot session user")
	}
	f := newChooserBusFixture(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "selected file.txt")
	if err := os.WriteFile(path, []byte("local selection"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := f.choose(ctx, "Choose a file, not /operator/supplied/path")
	call := f.nextCall(t)
	if call.parent != "" || call.title != "Choose a file, not /operator/supplied/path" {
		t.Fatal("unexpected chooser parent or title")
	}
	if len(call.options) != 4 {
		t.Fatalf("chooser passed default/path/filter options: %v", call.options)
	}
	for key, want := range map[string]bool{"modal": true, "multiple": false, "directory": false} {
		value, ok := call.options[key].Value().(bool)
		if !ok || value != want {
			t.Fatalf("option %s = %v, want %v", key, call.options[key], want)
		}
	}
	// An early Response must not be lost while OpenFile still owes its handle.
	f.respond(t, call.path, responseSuccess, map[string]dbus.Variant{
		"uris": dbus.MakeVariant([]string{(&url.URL{Scheme: "file", Path: path}).String()}),
	})
	call.reply <- chooserTestReply{path: call.path}
	got := awaitChooserResult(t, result)
	if got.err != nil || got.file == nil {
		t.Fatalf("ChooseFile = %v, %v", got.file, got.err)
	}
	t.Cleanup(func() {
		if err := got.file.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(got.file)
	if err != nil || string(contents) != "local selection" {
		t.Fatalf("selected descriptor reopened its path: %q, %v", contents, err)
	}
	if _, err := got.file.Write([]byte("must remain read-only")); err == nil {
		t.Fatal("chooser returned a writable descriptor")
	}
	f.assertNoWatches(t)
}

func TestChooseFileRejectsInvalidResponse(t *testing.T) {
	uri := "file:///never-open-this-file"
	for _, tc := range []struct {
		name        string
		body        []any
		cancelled   bool
		closed      bool
		wireInvalid bool
		// refusalURIs is a delivered refusal that still names files.
		refusalURIs bool
	}{
		{name: "missing uris", body: []any{responseSuccess, map[string]dbus.Variant{}}},
		{name: "scalar uris", body: []any{responseSuccess, map[string]dbus.Variant{"uris": dbus.MakeVariant(uri)}}},
		{name: "no files", body: []any{responseSuccess, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{})}}},
		{name: "empty uri", body: []any{responseSuccess, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{""})}}},
		{name: "multiple files", body: []any{responseSuccess, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{uri, uri})}}},
		{name: "object paths", body: []any{responseSuccess, map[string]dbus.Variant{"uris": dbus.MakeVariant([]dbus.ObjectPath{"/file"})}}},
		{name: "remote uri", body: []any{responseSuccess, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{"https://example.test/file"})}}},
		{name: "uri authority", body: []any{responseSuccess, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{"file://localhost/tmp/file"})}}},
		{name: "bare path", body: []any{responseSuccess, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{"/tmp/file"})}}},
		{name: "cancelled", body: []any{responseCancel, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{})}}, cancelled: true},
		// GNOME 46 answers Escape or the window's close with response 2 and
		// an empty URI list (layers-ubuntu24-files-17/-19).
		{name: "closed", body: []any{responseOther, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{})}}, closed: true},
		{name: "closed without results", body: []any{responseOther, map[string]dbus.Variant{}}, closed: true},
		{name: "cancelled naming a file", body: []any{responseCancel, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{uri})}}, refusalURIs: true},
		{name: "closed naming a file", body: []any{responseOther, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{uri})}}, refusalURIs: true},
		{name: "unknown result", body: []any{uint32(99), map[string]dbus.Variant{}}},
		{name: "malformed body", body: []any{"0", map[string]dbus.Variant{}}, wireInvalid: true},
		{name: "signed response", body: []any{int32(0), map[string]dbus.Variant{}}, wireInvalid: true},
		{name: "missing results", body: []any{responseSuccess}, wireInvalid: true},
		{name: "extra result", body: []any{responseSuccess, map[string]dbus.Variant{}, uint32(0)}, wireInvalid: true},
		{name: "wrong dictionary", body: []any{responseSuccess, map[string]string{"uris": uri}}, wireInvalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newChooserBusFixture(t)
			result := f.choose(t.Context(), "Choose a file")
			call := f.nextCall(t)
			f.respond(t, call.path, tc.body...)
			call.reply <- chooserTestReply{path: call.path}
			got := awaitChooserResult(t, result)
			if got.file != nil || got.err == nil || errors.Is(got.err, ErrPortalCancelled) != tc.cancelled || errors.Is(got.err, ErrPortalClosed) != tc.closed {
				t.Fatalf("invalid response yielded %v, %v", got.file, got.err)
			}
			if tc.cancelled && got.err != ErrPortalCancelled || tc.closed && got.err != ErrPortalClosed {
				t.Fatalf("clean local dismissal lost its resume authority: %v", got.err)
			}
			if tc.wireInvalid || tc.refusalURIs {
				var endErr *EndError
				if !errors.As(got.err, &endErr) || endErr.Detail != "portal_response_invalid" {
					t.Fatalf("malformed native wire body reached chooser results: %v", got.err)
				}
			}
			if tc.wireInvalid {
				f.awaitClose(t, call.path)
			}
			f.assertNoWatches(t)
		})
	}
}

func TestChooseFileRequiresSupportedPortal(t *testing.T) {
	for _, tc := range []struct {
		name        string
		version     dbus.Variant
		propertyErr *dbus.Error
	}{
		{name: "old version", version: dbus.MakeVariant(uint32(2))},
		{name: "malformed version", version: dbus.MakeVariant("3")},
		{name: "signed version", version: dbus.MakeVariant(int32(3))},
		{name: "missing interface", propertyErr: &dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownInterface"}},
		{name: "backend unavailable", propertyErr: &dbus.Error{Name: "org.freedesktop.DBus.Error.Failed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newChooserBusFixture(t)
			f.controlsMu.Lock()
			f.version, f.propertyErr = tc.version, tc.propertyErr
			f.controlsMu.Unlock()
			got := awaitChooserResult(t, f.choose(t.Context(), "Choose a file"))
			if got.file != nil || got.err == nil {
				t.Fatalf("unsupported portal yielded %v, %v", got.file, got.err)
			}
			select {
			case <-f.calls:
				t.Fatal("unsupported portal received OpenFile")
			default:
			}
			f.assertNoWatches(t)
		})
	}
}

func TestChooseFileMethodFailureClosesPredictedRequest(t *testing.T) {
	f := newChooserBusFixture(t)
	result := f.choose(t.Context(), "Choose a file")
	call := f.nextCall(t)
	call.reply <- chooserTestReply{err: &dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownMethod"}}
	got := awaitChooserResult(t, result)
	if got.file != nil || got.err == nil || errors.Is(got.err, ErrPortalCancelled) {
		t.Fatalf("method failure yielded %v, %v", got.file, got.err)
	}
	f.awaitClose(t, call.path)
	f.assertNoWatches(t)
}

func TestChooseFileCancellationClosesNativeRequest(t *testing.T) {
	for _, phase := range []string{"before acknowledgement", "waiting for response", "success races cancellation"} {
		t.Run(phase, func(t *testing.T) {
			f := newChooserBusFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := f.choose(ctx, "Choose a file")
			call := f.nextCall(t)
			if phase == "waiting for response" {
				call.reply <- chooserTestReply{path: call.path}
			}
			if phase == "success races cancellation" {
				f.respond(t, call.path, responseSuccess, map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{"file:///never-open-this-file"})})
			}
			cancel()
			got := awaitChooserResult(t, result)
			if got.file != nil || !errors.Is(got.err, ErrPortalCancelled) || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("cancelled chooser yielded %v, %v", got.file, got.err)
			}
			f.awaitClose(t, call.path)
			f.assertNoWatches(t)
		})
	}
}

func TestChooseFileCancellationReportsCloseFailure(t *testing.T) {
	f := newChooserBusFixture(t)
	closeErr := &dbus.Error{Name: "org.freedesktop.portal.Error.Failed", Body: []any{"native close not acknowledged"}}
	f.controlsMu.Lock()
	f.closeErr = closeErr
	f.controlsMu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := f.choose(ctx, "Choose a file")
	call := f.nextCall(t)
	cancel()
	got := awaitChooserResult(t, result)
	var nativeErr dbus.Error
	if got.file != nil || !errors.Is(got.err, ErrPortalCancelled) || !errors.Is(got.err, context.Canceled) ||
		!errors.As(got.err, &nativeErr) || nativeErr.Name != closeErr.Name {
		t.Fatalf("native cleanup failure was hidden: %v, %v", got.file, got.err)
	}
	f.awaitClose(t, call.path)
	f.assertNoWatches(t)
}

func TestChooseFileRejectsUnexpectedRequestPath(t *testing.T) {
	f := newChooserBusFixture(t)
	result := f.choose(t.Context(), "Choose a file")
	call := f.nextCall(t)
	unexpected := dbus.ObjectPath(string(call.path) + "_unexpected")
	if err := f.conn.ExportMethodTable(map[string]any{"Close": func() *dbus.Error {
		select {
		case f.closed <- unexpected:
			return nil
		case <-f.ctx.Done():
			return dbus.MakeFailedError(f.ctx.Err())
		}
	}}, unexpected, requestIface); err != nil {
		t.Fatal(err)
	}
	call.reply <- chooserTestReply{path: unexpected}
	got := awaitChooserResult(t, result)
	var endErr *EndError
	if got.file != nil || !errors.As(got.err, &endErr) || endErr.Detail != "portal_request_path_unexpected" {
		t.Fatalf("unexpected Request path was accepted: %v, %v", got.file, got.err)
	}
	f.awaitClose(t, unexpected)
	f.assertNoWatches(t)
}

func TestPortalRequestCancellationRetainsContextError(t *testing.T) {
	f := newChooserBusFixture(t)
	owner, err := f.portal.bus.nameOwner(t.Context(), portalName)
	if err != nil {
		t.Fatal(err)
	}
	sender := strings.ReplaceAll(strings.TrimPrefix(f.portal.bus.conn.Names()[0], ":"), ".", "_")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := f.portal.request(ctx, owner, sender, fileChooserIface+".OpenFile", []any{"", "Choose a file"}, map[string]dbus.Variant{})
		result <- err
	}()
	call := f.nextCall(t)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrPortalCancelled) {
			t.Fatalf("shared request changed RemoteDesktop cancellation semantics: %v", err)
		}
	case <-f.ctx.Done():
		t.Fatal("request failed to finish")
	}
	f.awaitClose(t, call.path)
}

func TestChooseFileRejectsForeignResponses(t *testing.T) {
	f := newChooserBusFixture(t)
	result := f.choose(t.Context(), "Choose a file")
	call := f.nextCall(t)
	other := f.connect(t)
	// A forged failure would differ from the original owner's cancellation.
	if err := other.Emit(call.path, requestIface+".Response", uint32(2), map[string]dbus.Variant{}); err != nil {
		t.Fatal(err)
	}
	// Flush the other connection through the daemon before the real response.
	var busID string
	if err := other.BusObject().Call("org.freedesktop.DBus.GetId", 0).Store(&busID); err != nil {
		t.Fatal(err)
	}
	f.respond(t, dbus.ObjectPath(string(call.path)+"_other"), uint32(2), map[string]dbus.Variant{})
	f.respond(t, call.path, responseCancel, map[string]dbus.Variant{})
	call.reply <- chooserTestReply{path: call.path}
	got := awaitChooserResult(t, result)
	if got.file != nil || !errors.Is(got.err, ErrPortalCancelled) {
		t.Fatalf("foreign response satisfied chooser: %v, %v", got.file, got.err)
	}
	f.assertNoWatches(t)
}

func TestChooseFileAlreadyCancelledDoesNotCallPortal(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// No bus: any native interaction after cancellation would panic.
	file, err := (&DesktopPortal{}).ChooseFile(ctx, "Choose a file")
	if file != nil || !errors.Is(err, ErrPortalCancelled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled chooser yielded %v, %v", file, err)
	}
}

func TestChooseFileCloseStaysWithOriginalOwner(t *testing.T) {
	f := newChooserBusFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := f.choose(ctx, "Choose a file")
	call := f.nextCall(t)
	other := f.connect(t)
	if _, err := f.conn.ReleaseName(portalName); err != nil {
		t.Fatal(err)
	}
	if reply, err := other.RequestName(portalName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("replace owner: %v, %v", reply, err)
	}
	wrongClose := make(chan struct{}, 1)
	if err := other.ExportMethodTable(map[string]any{"Close": func() *dbus.Error {
		wrongClose <- struct{}{}
		return nil
	}}, call.path, requestIface); err != nil {
		t.Fatal(err)
	}
	// Keep the original OpenFile unacknowledged: cancellation must use the
	// original unique owner, not whichever process now owns the service name.
	cancel()
	got := awaitChooserResult(t, result)
	if got.file != nil || !errors.Is(got.err, ErrPortalCancelled) {
		t.Fatalf("owner-bound cancellation yielded %v, %v", got.file, got.err)
	}
	f.awaitClose(t, call.path)
	select {
	case <-wrongClose:
		t.Fatal("request close followed a replacement service owner")
	default:
	}
	f.assertNoWatches(t)
}

func TestChosenTransferURIRequiresExactWireShape(t *testing.T) {
	for _, value := range []dbus.Variant{
		dbus.MakeVariant("file:///tmp/file"),
		dbus.MakeVariant([]string{}),
		dbus.MakeVariant([]string{""}),
		dbus.MakeVariant([]string{"file:///a", "file:///b"}),
		dbus.MakeVariant([]dbus.ObjectPath{"/tmp/file"}),
		dbus.MakeVariant([]any{"file:///tmp/file"}),
	} {
		if uri, err := chosenTransferURI(map[string]dbus.Variant{"uris": value}); err == nil || uri != "" {
			t.Fatalf("accepted invalid uris variant %s", value.Signature())
		}
	}
	if uri, err := chosenTransferURI(nil); err == nil || uri != "" {
		t.Fatal("missing uris accepted")
	}
	uri := "file:///tmp/a%20file"
	got, err := chosenTransferURI(map[string]dbus.Variant{"uris": dbus.MakeVariant([]string{uri})})
	if err != nil || got != uri {
		t.Fatalf("exact URI changed before storage validation: %q, %v", got, err)
	}
}

type chooserTestReply struct {
	path dbus.ObjectPath
	err  *dbus.Error
}

type chooserTestCall struct {
	parent  string
	title   string
	options map[string]dbus.Variant
	path    dbus.ObjectPath
	reply   chan chooserTestReply
}

type chooserTestResult struct {
	file *os.File
	err  error
}

type chooserBusFixture struct {
	ctx     context.Context
	address string
	conn    *dbus.Conn
	portal  *DesktopPortal
	calls   chan chooserTestCall
	closed  chan dbus.ObjectPath

	// D-Bus messages do not synchronize Go memory accesses to test controls.
	controlsMu  sync.Mutex
	version     dbus.Variant
	propertyErr *dbus.Error
	closeErr    *dbus.Error
}

func newChooserBusFixture(t *testing.T) *chooserBusFixture {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not installed; native chooser boundary not exercised")
	}
	dir := t.TempDir()
	address := "unix:path=" + filepath.Join(dir, "bus")
	config := filepath.Join(dir, "session.conf")
	if err := os.WriteFile(config, []byte(`<busconfig><type>session</type><listen>`+address+`</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cmd := exec.CommandContext(ctx, daemon, "--config-file="+config, "--nofork", "--print-address=1", "--nopidfile")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		var exitErr *exec.ExitError
		if err := cmd.Wait(); err != nil && !errors.As(err, &exitErr) {
			t.Error(err)
		}
	})
	ready := make(chan error, 1)
	go func() {
		_, err := bufio.NewReader(stdout).ReadString('\n')
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("private D-Bus daemon startup timed out")
	}
	f := &chooserBusFixture{ctx: ctx, address: address, version: dbus.MakeVariant(uint32(3)), calls: make(chan chooserTestCall, 1), closed: make(chan dbus.ObjectPath, 4)}
	f.conn = f.connect(t)
	if err := f.conn.ExportMethodTable(map[string]any{"Get": func(iface, name string) (dbus.Variant, *dbus.Error) {
		if iface != fileChooserIface || name != "version" {
			return dbus.Variant{}, dbus.MakeFailedError(errors.New("unexpected property"))
		}
		f.controlsMu.Lock()
		defer f.controlsMu.Unlock()
		return f.version, f.propertyErr
	}}, portalPath, "org.freedesktop.DBus.Properties"); err != nil {
		t.Fatal(err)
	}
	if err := f.conn.ExportMethodTable(map[string]any{"OpenFile": f.openFile}, portalPath, fileChooserIface); err != nil {
		t.Fatal(err)
	}
	if reply, err := f.conn.RequestName(portalName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request portal name: %v, %v", reply, err)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", address)
	bus, err := ConnectSessionBus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bus.Close(); err != nil {
			t.Error(err)
		}
	})
	f.portal, err = NewDesktopPortal(bus, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *chooserBusFixture) connect(t *testing.T) *dbus.Conn {
	t.Helper()
	conn, err := dbus.Connect(f.address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	return conn
}

func (f *chooserBusFixture) openFile(sender dbus.Sender, parent, title string, options map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	token, ok := options["handle_token"].Value().(string)
	if !ok || !strings.HasPrefix(token, "lindm_") {
		return "", dbus.MakeFailedError(errors.New("missing request token"))
	}
	path := dbus.ObjectPath("/org/freedesktop/portal/desktop/request/" + strings.ReplaceAll(strings.TrimPrefix(string(sender), ":"), ".", "_") + "/" + token)
	if err := f.conn.ExportMethodTable(map[string]any{"Close": func(caller dbus.Sender) *dbus.Error {
		if caller != sender {
			return dbus.MakeFailedError(errors.New("wrong request caller"))
		}
		select {
		case f.closed <- path:
			f.controlsMu.Lock()
			defer f.controlsMu.Unlock()
			return f.closeErr
		case <-f.ctx.Done():
			return dbus.MakeFailedError(f.ctx.Err())
		}
	}}, path, requestIface); err != nil {
		return "", dbus.MakeFailedError(err)
	}
	call := chooserTestCall{parent: parent, title: title, options: options, path: path, reply: make(chan chooserTestReply, 1)}
	select {
	case f.calls <- call:
	case <-f.ctx.Done():
		return "", dbus.MakeFailedError(f.ctx.Err())
	}
	select {
	case reply := <-call.reply:
		return reply.path, reply.err
	case <-f.ctx.Done():
		return "", dbus.MakeFailedError(f.ctx.Err())
	}
}

func (f *chooserBusFixture) choose(ctx context.Context, title string) <-chan chooserTestResult {
	result := make(chan chooserTestResult, 1)
	go func() {
		file, err := f.portal.ChooseFile(ctx, title)
		result <- chooserTestResult{file: file, err: err}
	}()
	return result
}

func (f *chooserBusFixture) nextCall(t *testing.T) chooserTestCall {
	t.Helper()
	select {
	case call := <-f.calls:
		return call
	case <-f.ctx.Done():
		t.Fatal("OpenFile was not called")
		return chooserTestCall{}
	}
}

func (f *chooserBusFixture) respond(t *testing.T, path dbus.ObjectPath, body ...any) {
	t.Helper()
	if err := f.conn.Emit(path, requestIface+".Response", body...); err != nil {
		t.Fatal(err)
	}
}

func (f *chooserBusFixture) awaitClose(t *testing.T, want dbus.ObjectPath) {
	t.Helper()
	select {
	case got := <-f.closed:
		if got != want {
			t.Fatalf("closed %q, want %q", got, want)
		}
	case <-f.ctx.Done():
		t.Fatal("native request was not closed")
	}
}

func (f *chooserBusFixture) assertNoWatches(t *testing.T) {
	t.Helper()
	f.portal.bus.mu.Lock()
	defer f.portal.bus.mu.Unlock()
	if len(f.portal.bus.watches) != 0 {
		t.Fatal("chooser left a response subscription")
	}
}

func awaitChooserResult(t *testing.T, result <-chan chooserTestResult) chooserTestResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("chooser did not finish before test deadline")
		return chooserTestResult{}
	}
}
