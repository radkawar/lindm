// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/godbus/dbus/v5"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	portalName         = "org.freedesktop.portal.Desktop"
	portalPath         = dbus.ObjectPath("/org/freedesktop/portal/desktop")
	screenCastIface    = "org.freedesktop.portal.ScreenCast"
	remoteDesktopIface = "org.freedesktop.portal.RemoteDesktop"
	requestIface       = "org.freedesktop.portal.Request"
	portalSessionIface = "org.freedesktop.portal.Session"
)

// Portal enumerations (xdg-desktop-portal ScreenCast/RemoteDesktop).
const (
	sourceMonitor  uint32 = 1
	cursorHidden   uint32 = 1
	cursorEmbedded uint32 = 2
	deviceKeyboard uint32 = 1
	devicePointer  uint32 = 2
	persistNone    uint32 = 0
	// persistUntilRevoked asks the desktop for a grant it keeps until revoked;
	// the local dialog still decides, through its own remember choice.
	persistUntilRevoked uint32 = 2
	responseSuccess     uint32 = 0
	responseCancel      uint32 = 1
	// responseOther ends the interaction "in some other way";
	// xdg-desktop-portal-gnome 46.2 filechooser.c sends it for GTK's
	// delete-event (Escape or closing the chooser).
	responseOther uint32 = 2
)

// errPortalOther marks a Request that ended with responseOther. Only the
// file chooser treats it as a local outcome; every other portal fails closed.
var errPortalOther = errors.New("portal_response_other")

// DesktopPortal drives xdg-desktop-portal over the session bus. Every
// Request follows the documented pattern: the Response signal on the
// predicted request path is subscribed before the method call, and only
// signals from the portal's unique name are accepted.
type DesktopPortal struct {
	bus    *SessionBus
	logger *slog.Logger
}

var _ Portal = (*DesktopPortal)(nil)

// NewDesktopPortal returns a portal client bound to bus.
func NewDesktopPortal(bus *SessionBus, logger *slog.Logger) (*DesktopPortal, error) {
	if bus == nil || logger == nil {
		return nil, errors.New("desktop: missing portal dependency")
	}
	return &DesktopPortal{bus: bus, logger: logger}, nil
}

// Check probes the portal frontend's advertised interfaces for the request
// without creating a session, so no dialog is shown.
func (p *DesktopPortal) Check(ctx context.Context, request PortalRequest) error {
	_, err := p.capabilities(ctx, request)
	return err
}

// portalCapabilities are the frontend facts a servable request observed.
type portalCapabilities struct {
	cursorModes uint32
	// versions is the audited interface-version summary.
	versions string
}

// capabilities returns the advertised cursor modes and interface versions
// once the request is servable. The frontend exports an interface only when
// a backend selected for this desktop implements it: xdg-desktop-portal-xapp
// (Cinnamon) has no ScreenCast, and xdg-desktop-portal-hyprland has
// ScreenCast but no RemoteDesktop, so CONTROL there is refused rather than
// reduced to VIEW.
func (p *DesktopPortal) capabilities(ctx context.Context, request PortalRequest) (portalCapabilities, error) {
	mode := request.Mode
	// The first call to the well-known name D-Bus-activates the portal;
	// GetNameOwner alone would not.
	sourceTypes, err := p.uint32Property(ctx, screenCastIface, "AvailableSourceTypes")
	if err != nil {
		return portalCapabilities{}, unavailable("portal_screencast_unavailable", err)
	}
	if sourceTypes&sourceMonitor == 0 {
		return portalCapabilities{}, unavailable("portal_monitor_source_unavailable", nil)
	}
	screenCastVersion, _ := p.uint32Property(ctx, screenCastIface, "version")
	// Versions are clamped so the audited summary stays within its 64-byte bound.
	versions := fmt.Sprintf("screencast_%d", min(screenCastVersion, 999))
	var deviceTypes, remoteDesktopVersion uint32
	if mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		deviceTypes, err = p.uint32Property(ctx, remoteDesktopIface, "AvailableDeviceTypes")
		if err != nil {
			return portalCapabilities{}, unavailable("portal_remote_desktop_unavailable", err)
		}
		devicesRequested := request.deviceTypes()
		if deviceTypes&devicesRequested != devicesRequested {
			return portalCapabilities{}, unavailable("portal_input_devices_unavailable", nil)
		}
		remoteDesktopVersion, _ = p.uint32Property(ctx, remoteDesktopIface, "version")
		versions += fmt.Sprintf("_remote_desktop_%d", min(remoteDesktopVersion, 999))
	}
	// Absent before ScreenCast version 2: no cursor mode is requested then.
	cursorModes, err := p.uint32Property(ctx, screenCastIface, "AvailableCursorModes")
	if err != nil {
		cursorModes = 0
	}
	p.logger.Info("portal capabilities", "mode", mode.String(), "screencast_version", screenCastVersion, "source_types", sourceTypes,
		"cursor_modes", cursorModes, "remote_desktop_version", remoteDesktopVersion, "device_types", deviceTypes)
	return portalCapabilities{cursorModes: cursorModes, versions: versions}, nil
}

// Open creates, configures and starts a portal session. VIEW uses a
// ScreenCast session; CONTROL uses a RemoteDesktop session with the requested
// input devices plus ScreenCast sources on the same session.
func (p *DesktopPortal) Open(ctx context.Context, request PortalRequest) (_ Grant, err error) {
	mode := request.Mode
	if request.Lifetime == nil {
		return nil, errors.New("portal session lifetime missing")
	}
	observed, err := p.capabilities(ctx, request)
	cursorModes := observed.cursorModes
	if err != nil {
		return nil, err
	}
	owner, err := p.bus.nameOwner(ctx, portalName)
	if err != nil {
		return nil, unavailable("portal_unavailable", err)
	}
	control := mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
	devicesRequested := request.deviceTypes()
	createIface := screenCastIface
	if control {
		createIface = remoteDesktopIface
	}
	names := p.bus.conn.Names()
	if len(names) == 0 {
		return nil, unavailable("session_bus_name_missing", nil)
	}
	sender := strings.ReplaceAll(strings.TrimPrefix(names[0], ":"), ".", "_")
	sessionToken, err := portalToken()
	if err != nil {
		return nil, err
	}
	predicted := dbus.ObjectPath("/org/freedesktop/portal/desktop/session/" + sender + "/" + sessionToken)
	closedWatch, err := p.bus.watch(ctx, owner, predicted, portalSessionIface, "Closed")
	if err != nil {
		return nil, unavailable("portal_watch_failed", err)
	}
	grant := &portalGrant{
		bus:      p.bus,
		owner:    owner,
		watch:    closedWatch,
		versions: observed.versions,
		closed:   make(chan struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		control:  false,
	}
	go grant.watchClosed()
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), busCallTimeout)
			defer cancel()
			if grant.handle != "" {
				err = errors.Join(err, grant.Close(cleanup))
			} else {
				grant.stopWatching()
			}
		}
	}()

	results, err := p.request(ctx, owner, sender, createIface+".CreateSession", nil,
		map[string]dbus.Variant{"session_handle_token": dbus.MakeVariant(sessionToken)})
	if err != nil {
		return nil, err
	}
	handle, err := sessionHandle(results)
	if err != nil {
		return nil, unavailable("portal_session_handle_invalid", err)
	}
	grant.handle = handle
	if handle != predicted {
		return nil, unavailable("portal_session_path_unexpected", nil)
	}
	if err := p.configureSession(ctx, request, grant, sender, devicesRequested, cursorModes); err != nil {
		return nil, err
	}
	started, err := p.request(ctx, owner, sender, createIface+".Start", []any{handle, ""}, map[string]dbus.Variant{})
	if err != nil {
		return nil, err
	}
	streams, err := grantedStreams(started)
	if err != nil {
		return nil, unavailable("portal_stream_missing", err)
	}
	grant.streams, grant.stream = streams, streams[0]
	grant.startClipboard(started)
	if request.Persist || request.RestoreToken != "" {
		// Only a returned token proves the desktop kept the grant; each
		// restore consumes the old token and issues a new one.
		if value, ok := started["restore_token"]; ok {
			var token string
			if value.Store(&token) == nil && validRestoreToken(token) {
				grant.restoreToken = token
			}
		}
	}
	if control {
		if value, ok := started["devices"]; ok {
			var devices uint32
			if value.Store(&devices) == nil {
				grant.control = devices&devicePointer != 0
				grant.keyboard = devicesRequested&deviceKeyboard != 0 && devices&deviceKeyboard != 0
			}
		}
	}
	p.logger.Info("portal session started", "mode", mode.String(), "monitors", len(streams),
		"control_granted", grant.control, "cursor_modes", cursorModes)
	return grant, nil
}

func (r PortalRequest) deviceTypes() uint32 {
	if r.Mode != agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		return 0
	}
	devices := devicePointer
	if policyEnabled(r.Policy.GetKeyboard()) {
		devices |= deviceKeyboard
	}
	return devices
}

func (p *DesktopPortal) configureSession(ctx context.Context, request PortalRequest, grant *portalGrant, sender string, devicesRequested, cursorModes uint32) error {
	control := request.Mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
	persist := persistNone
	if request.Persist || request.RestoreToken != "" {
		persist = persistUntilRevoked
	}
	if control {
		devices := map[string]dbus.Variant{
			"types":        dbus.MakeVariant(devicesRequested),
			"persist_mode": dbus.MakeVariant(persist),
		}
		if request.RestoreToken != "" {
			devices["restore_token"] = dbus.MakeVariant(request.RestoreToken)
		}
		if _, err := p.request(ctx, grant.owner, sender, remoteDesktopIface+".SelectDevices", []any{grant.handle}, devices); err != nil {
			return err
		}
	}
	sources := map[string]dbus.Variant{
		"types":        dbus.MakeVariant(sourceMonitor),
		"multiple":     dbus.MakeVariant(request.Policy.GetDisplay() == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON),
		"persist_mode": dbus.MakeVariant(persistNone),
	}
	if !control {
		// A RemoteDesktop session persists through SelectDevices only.
		sources["persist_mode"] = dbus.MakeVariant(persist)
		if request.RestoreToken != "" {
			sources["restore_token"] = dbus.MakeVariant(request.RestoreToken)
		}
	}
	cursorMode, err := p.captureCursorMode(ctx, cursorModes)
	if err != nil {
		return err
	}
	if cursorMode != 0 {
		sources["cursor_mode"] = dbus.MakeVariant(cursorMode)
	}
	grant.cursorHidden = cursorMode == cursorHidden || cursorMode == 0
	p.logger.Info("portal cursor mode selected", "cursor_mode", cursorMode)
	if _, err := p.request(ctx, grant.owner, sender, screenCastIface+".SelectSources", []any{grant.handle}, sources); err != nil {
		return err
	}
	if control && policyEnabled(request.Policy.GetClipboard()) {
		version, versionErr := p.uint32Property(ctx, clipboardIface, "version")
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case versionErr != nil:
			grant.clipboardReason = clipboardRequestRefusal(versionErr)
			if dbusErrorName(versionErr) == "org.freedesktop.DBus.Error.UnknownProperty" {
				grant.clipboardReason = "portal_clipboard_unsupported"
			}
			if grant.clipboardReason == "" {
				return unavailable("portal_clipboard_probe_failed", versionErr)
			}
		case version < 1:
			grant.clipboardReason = "portal_clipboard_unsupported"
		default:
			grant.versions += fmt.Sprintf("_clipboard_%d", min(version, 999))
			if err := grant.requestClipboard(ctx, request.Lifetime); err != nil {
				return unavailable("portal_clipboard_request_failed", err)
			}
		}
	}
	return nil
}

func (p *DesktopPortal) uint32Property(ctx context.Context, iface, name string) (uint32, error) {
	value, err := p.bus.property(ctx, portalName, portalPath, iface, name)
	if err != nil {
		return 0, err
	}
	var out uint32
	if err := value.Store(&out); err != nil {
		return 0, fmt.Errorf("decode %s.%s: %w", iface, name, err)
	}
	return out, nil
}

// request calls a portal method returning a Request handle and waits for
// its Response. ctx bounds the user interaction; on expiry the request is
// closed so the dialog disappears.
func (p *DesktopPortal) request(ctx context.Context, owner, sender, method string, args []any, options map[string]dbus.Variant) (results map[string]dbus.Variant, err error) {
	token, err := portalToken()
	if err != nil {
		return nil, err
	}
	options["handle_token"] = dbus.MakeVariant(token)
	predicted := dbus.ObjectPath("/org/freedesktop/portal/desktop/request/" + sender + "/" + token)
	watch, err := p.bus.watch(ctx, owner, predicted, requestIface, "Response")
	if err != nil {
		return nil, unavailable("portal_watch_failed", err)
	}
	pending := true
	cleanupPath := predicted
	defer func() {
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), busCallTimeout)
		defer cancel()
		if watchErr := watch.stop(stop); watchErr != nil {
			err = errors.Join(err, watchErr)
		}
		// The native Request can exist before the method acknowledgement.
		// Cancellation must close that predicted handle, including a Response
		// racing cancellation, and must never return its grant.
		if pending || ctx.Err() != nil {
			err = errors.Join(err, p.closeRequest(ctx, owner, cleanupPath))
		}
		if ctx.Err() != nil {
			results, err = nil, errors.Join(ctx.Err(), err)
		}
	}()
	var handle dbus.ObjectPath
	if err := p.bus.call(ctx, owner, portalPath, method, append(args, options)...).Store(&handle); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, unavailable("portal_call_failed", fmt.Errorf("%s: %w", method, err))
	}
	if handle != predicted {
		// Portals older than 0.9 return unpredictable handles; refusing them
		// avoids missing a Response emitted before a late subscription.
		cleanupPath = handle
		return nil, unavailable("portal_request_path_unexpected", nil)
	}
	select {
	case signal := <-watch.signals:
		if len(signal.Body) != 2 {
			return nil, unavailable("portal_response_invalid", nil)
		}
		response, ok := signal.Body[0].(uint32)
		if !ok {
			return nil, unavailable("portal_response_invalid", nil)
		}
		results, ok = signal.Body[1].(map[string]dbus.Variant)
		if !ok {
			return nil, unavailable("portal_response_invalid", nil)
		}
		pending = false
		if response != responseSuccess && portalResultURIs(results) {
			// A refusal that still names files is not a refusal.
			return nil, unavailable("portal_response_invalid", fmt.Errorf("%s: response %d with URIs", method, response))
		}
		switch response {
		case responseSuccess:
			return results, nil
		case responseCancel:
			return nil, ErrPortalCancelled
		case responseOther:
			return nil, unavailable("portal_request_failed", fmt.Errorf("%s: response %d: %w", method, response, errPortalOther))
		default:
			return nil, unavailable("portal_request_failed", fmt.Errorf("%s: response %d", method, response))
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.bus.done:
		return nil, unavailable("session_bus_closed", nil)
	}
}

// portalResultURIs reports whether results carry any "uris" entry other than
// an empty string list (GNOME sends an empty list with every refusal).
func portalResultURIs(results map[string]dbus.Variant) bool {
	value, ok := results["uris"]
	if !ok {
		return false
	}
	uris, ok := value.Value().([]string)
	return !ok || len(uris) != 0
}

func (p *DesktopPortal) closeRequest(ctx context.Context, owner string, handle dbus.ObjectPath) error {
	call, cancel := context.WithTimeout(context.WithoutCancel(ctx), busCallTimeout)
	defer cancel()
	if err := p.bus.call(call, owner, handle, requestIface+".Close").Err; err != nil {
		return fmt.Errorf("close portal request: %w", err)
	}
	return nil
}

func portalToken() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("portal token: %w", err)
	}
	return "lindm_" + hex.EncodeToString(raw[:]), nil
}

// sessionHandle accepts the object path or, from version 1 portals, the
// string form of session_handle.
func sessionHandle(results map[string]dbus.Variant) (dbus.ObjectPath, error) {
	value, ok := results["session_handle"]
	if !ok {
		return "", errors.New("missing session_handle")
	}
	switch handle := value.Value().(type) {
	case dbus.ObjectPath:
		return handle, nil
	case string:
		path := dbus.ObjectPath(handle)
		if !path.IsValid() {
			return "", errors.New("invalid session_handle")
		}
		return path, nil
	default:
		return "", fmt.Errorf("unexpected session_handle type %s", value.Signature())
	}
}

type portalStream struct {
	Node       uint32
	Properties map[string]dbus.Variant
}

func grantedStreams(results map[string]dbus.Variant) ([]Stream, error) {
	value, ok := results["streams"]
	if !ok {
		return nil, errors.New("missing streams")
	}
	var granted []portalStream
	if err := value.Store(&granted); err != nil {
		return nil, fmt.Errorf("decode streams: %w", err)
	}
	if len(granted) == 0 || len(granted) > 8 {
		return nil, errors.New("invalid granted monitor count")
	}
	streams := make([]Stream, 0, len(granted))
	seen := make(map[uint32]bool, len(granted))
	for i, native := range granted {
		if native.Node == 0 || seen[native.Node] {
			return nil, errors.New("invalid granted monitor identity")
		}
		seen[native.Node] = true
		stream := Stream{NodeID: native.Node, ID: fmt.Sprintf("monitor-%d", i+1), Label: fmt.Sprintf("Monitor %d", i+1)}
		if size, ok := native.Properties["size"]; ok {
			var dims struct{ Width, Height int32 }
			if size.Store(&dims) == nil && dims.Width > 0 && dims.Height > 0 && dims.Width <= 16384 && dims.Height <= 16384 {
				stream.Width, stream.Height = int(dims.Width), int(dims.Height)
			}
		}
		if stream.Width == 0 || stream.Height == 0 {
			return nil, errors.New("monitor_geometry_unknown")
		}
		if position, ok := native.Properties["position"]; ok {
			var at struct{ X, Y int32 }
			if position.Store(&at) == nil && at.X > -65536 && at.X < 65536 && at.Y > -65536 && at.Y < 65536 {
				stream.X, stream.Y, stream.Positioned = int(at.X), int(at.Y), true
			}
		}
		streams = append(streams, stream)
	}
	return streams, nil
}

// portalGrant is a started portal session.
type portalGrant struct {
	bus             *SessionBus
	handle          dbus.ObjectPath
	owner           string
	streams         []Stream
	clipboard       *portalClipboard
	clipboardReason string
	stream          Stream
	control         bool
	keyboard        bool
	restoreToken    string
	cursorHidden    bool
	watch           *busWatch
	closed          chan struct{}
	closedOnce      sync.Once
	stop            chan struct{}
	stopOnce        sync.Once
	done            chan struct{}
	versions        string
}

var _ Grant = (*portalGrant)(nil)

func (g *portalGrant) Streams() []Stream  { return g.streams }
func (g *portalGrant) CursorHidden() bool { return g.cursorHidden }

func (g *portalGrant) SelectStream(id string) error {
	for _, stream := range g.streams {
		if stream.ID == id {
			g.stream = stream
			return nil
		}
	}
	return errors.New("display_not_granted")
}
func (g *portalGrant) ControlGranted() bool    { return g.control }
func (g *portalGrant) RestoreToken() string    { return g.restoreToken }
func (g *portalGrant) KeyboardGranted() bool   { return g.keyboard }
func (g *portalGrant) PortalVersions() string  { return g.versions }
func (g *portalGrant) Closed() <-chan struct{} { return g.closed }

func (g *portalGrant) watchClosed() {
	defer close(g.done)
	select {
	case <-g.watch.signals:
		g.markClosed()
	case <-g.bus.done:
		g.markClosed()
	case <-g.stop:
	}
}

func (g *portalGrant) markClosed() { g.closedOnce.Do(func() { close(g.closed) }) }

func (g *portalGrant) stopWatching() {
	g.stopOnce.Do(func() { close(g.stop) })
	<-g.done
	ctx, cancel := context.WithTimeout(context.Background(), busCallTimeout)
	defer cancel()
	_ = g.watch.stop(ctx)
}

// OpenPipeWire waits at most busCallTimeout for the remote. On a session with
// clipboard access it is sent only after the clipboard owner announcement
// that follows Start (see portalClipboard.awaitAnnouncement).
func (g *portalGrant) OpenPipeWire(ctx context.Context) (*os.File, error) {
	if g.clipboard != nil && g.clipboard.enabled {
		if err := g.clipboard.awaitAnnouncement(ctx); err != nil {
			return nil, fmt.Errorf("open pipewire remote: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("open pipewire remote: %w", err)
	}
	call := g.bus.conn.Object(g.owner, portalPath).Go(screenCastIface+".OpenPipeWireRemote", 0, make(chan *dbus.Call, 1), g.handle, map[string]dbus.Variant{})
	wait, cancel := context.WithTimeout(ctx, busCallTimeout)
	defer cancel()
	return awaitPipeWireRemote(wait, call.Done)
}

// awaitPipeWireRemote returns the remote of the one reply on replies, or an
// error once wait ends. A reply that arrives after that is still collected
// and its descriptor closed: godbus drops replies to abandoned calls without
// closing the descriptors they carry, which would leak the PipeWire
// connection. The collector ends with that reply; godbus delivers one for
// every call, at the latest when the bus connection closes.
func awaitPipeWireRemote(wait context.Context, replies <-chan *dbus.Call) (*os.File, error) {
	select {
	case reply := <-replies:
		return pipeWireRemote(reply)
	case <-wait.Done():
		go func() {
			if late, err := pipeWireRemote(<-replies); err == nil {
				_ = late.Close()
			}
		}()
		return nil, fmt.Errorf("open pipewire remote: %w", wait.Err())
	}
}

// pipeWireRemote takes ownership of every descriptor in an OpenPipeWireRemote
// reply and returns its single remote.
func pipeWireRemote(reply *dbus.Call) (*os.File, error) {
	if reply.Err != nil {
		return nil, fmt.Errorf("open pipewire remote: %w", reply.Err)
	}
	var files []*os.File
	for _, value := range reply.Body {
		if fd, ok := value.(dbus.UnixFD); ok && fd >= 0 {
			syscall.CloseOnExec(int(fd))
			files = append(files, os.NewFile(uintptr(fd), "pipewire-remote"))
		}
	}
	if len(reply.Body) != 1 || len(files) != 1 {
		for _, file := range files {
			_ = file.Close()
		}
		return nil, errors.New("open pipewire remote: invalid fd")
	}
	return files[0], nil
}

func (g *portalGrant) Inject(ctx context.Context, event InputEvent) error {
	if !g.control {
		return errors.New("input not granted")
	}
	if (event.kind == inputKey || event.kind == inputKeysym) && !g.keyboard {
		return errors.New("keyboard not granted")
	}
	options := map[string]dbus.Variant{}
	method := func(name string, args ...any) error {
		if err := g.bus.call(ctx, g.owner, portalPath, remoteDesktopIface+"."+name, append([]any{g.handle, options}, args...)...).Err; err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	state := func(down bool) uint32 {
		if down {
			return 1
		}
		return 0
	}
	switch event.kind {
	case inputMove:
		if g.stream.Width <= 0 || g.stream.Height <= 0 {
			return errors.New("stream size unknown")
		}
		x := min(event.X*float64(g.stream.Width), float64(g.stream.Width-1))
		y := min(event.Y*float64(g.stream.Height), float64(g.stream.Height-1))
		return method("NotifyPointerMotionAbsolute", g.stream.NodeID, x, y)
	case inputButton:
		return method("NotifyPointerButton", event.Button, state(event.Down))
	case inputWheel:
		if event.DY != 0 {
			if err := method("NotifyPointerAxisDiscrete", axisVertical, event.DY); err != nil {
				return err
			}
		}
		if event.DX != 0 {
			return method("NotifyPointerAxisDiscrete", axisHorizontal, event.DX)
		}
		return nil
	case inputKey:
		return method("NotifyKeyboardKeycode", event.Keycode, state(event.Down))
	case inputKeysym:
		return method("NotifyKeyboardKeysym", event.Keysym, state(event.Down))
	default:
		return errors.New("unknown input event")
	}
}

func (g *portalGrant) Close(ctx context.Context) error {
	if g.clipboard != nil {
		g.clipboard.cancel()
	}
	// Revoke the native authority before waiting for transfer acknowledgements
	// or D-Bus match cleanup, which must not delay local Stop.
	err := g.bus.call(ctx, g.owner, g.handle, portalSessionIface+".Close").Err
	g.markClosed()
	if g.clipboard != nil {
		g.clipboard.close()
	}
	g.stopWatching()
	if err != nil {
		return fmt.Errorf("close portal session: %w", err)
	}
	return nil
}

// validRestoreToken accepts the portal frontend's UUID tokens only.
func validRestoreToken(token string) bool {
	if len(token) != 36 {
		return false
	}
	for i, r := range token {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if r != '-' {
				return false
			}
		case (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F'):
			return false
		}
	}
	return true
}
