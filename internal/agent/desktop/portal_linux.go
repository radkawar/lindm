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
	sourceMonitor   uint32 = 1
	cursorHidden    uint32 = 1
	cursorEmbedded  uint32 = 2
	deviceKeyboard  uint32 = 1
	devicePointer   uint32 = 2
	persistNone     uint32 = 0
	responseSuccess uint32 = 0
	responseCancel  uint32 = 1
)

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

// Open creates, configures and starts a portal session. VIEW uses a
// ScreenCast session; CONTROL uses a RemoteDesktop session with keyboard and
// pointer plus ScreenCast sources on the same session.
func (p *DesktopPortal) Open(ctx context.Context, mode agentv1.AssistanceMode) (_ Grant, err error) {
	// The first call to the well-known name D-Bus-activates the portal;
	// GetNameOwner alone would not.
	sourceTypes, err := p.uint32Property(ctx, screenCastIface, "AvailableSourceTypes")
	if err != nil {
		return nil, unavailable("portal_screencast_unavailable", err)
	}
	if sourceTypes&sourceMonitor == 0 {
		return nil, unavailable("portal_monitor_source_unavailable", nil)
	}
	owner, err := p.bus.nameOwner(ctx, portalName)
	if err != nil {
		return nil, unavailable("portal_unavailable", err)
	}
	// Absent before ScreenCast version 2: no cursor mode is requested then.
	cursorModes, cursorErr := p.uint32Property(ctx, screenCastIface, "AvailableCursorModes")
	if cursorErr != nil {
		cursorModes = 0
	}
	control := mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
	createIface := screenCastIface
	if control {
		createIface = remoteDesktopIface
		deviceTypes, err := p.uint32Property(ctx, remoteDesktopIface, "AvailableDeviceTypes")
		if err != nil {
			return nil, unavailable("portal_remote_desktop_unavailable", err)
		}
		if deviceTypes&(deviceKeyboard|devicePointer) != deviceKeyboard|devicePointer {
			return nil, unavailable("portal_input_devices_unavailable", nil)
		}
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
		bus:     p.bus,
		watch:   closedWatch,
		closed:  make(chan struct{}),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		control: false,
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
	if control {
		if _, err := p.request(ctx, owner, sender, remoteDesktopIface+".SelectDevices", []any{handle},
			map[string]dbus.Variant{
				"types":        dbus.MakeVariant(deviceKeyboard | devicePointer),
				"persist_mode": dbus.MakeVariant(persistNone),
			}); err != nil {
			return nil, err
		}
	}
	sources := map[string]dbus.Variant{
		"types":        dbus.MakeVariant(sourceMonitor),
		"multiple":     dbus.MakeVariant(false),
		"persist_mode": dbus.MakeVariant(persistNone),
	}
	switch {
	case cursorModes&cursorEmbedded != 0:
		sources["cursor_mode"] = dbus.MakeVariant(cursorEmbedded)
	case cursorModes&cursorHidden != 0:
		sources["cursor_mode"] = dbus.MakeVariant(cursorHidden)
	}
	if _, err := p.request(ctx, owner, sender, screenCastIface+".SelectSources", []any{handle}, sources); err != nil {
		return nil, err
	}
	started, err := p.request(ctx, owner, sender, createIface+".Start", []any{handle, ""}, map[string]dbus.Variant{})
	if err != nil {
		return nil, err
	}
	stream, err := firstStream(started)
	if err != nil {
		return nil, unavailable("portal_stream_missing", err)
	}
	grant.stream = stream
	if control {
		if value, ok := started["devices"]; ok {
			var devices uint32
			if value.Store(&devices) == nil {
				grant.control = devices&(deviceKeyboard|devicePointer) == deviceKeyboard|devicePointer
			}
		}
	}
	p.logger.Info("portal session started", "mode", mode.String(), "node", stream.NodeID,
		"width", stream.Width, "height", stream.Height, "control_granted", grant.control, "cursor_modes", cursorModes)
	return grant, nil
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
func (p *DesktopPortal) request(ctx context.Context, owner, sender, method string, args []any, options map[string]dbus.Variant) (map[string]dbus.Variant, error) {
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
	defer func() {
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), busCallTimeout)
		defer cancel()
		if err := watch.stop(stop); err != nil {
			p.logger.Debug("portal request watch removal failed", "err", err)
		}
	}()
	var handle dbus.ObjectPath
	if err := p.bus.call(ctx, portalName, portalPath, method, append(args, options)...).Store(&handle); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, unavailable("portal_call_failed", fmt.Errorf("%s: %w", method, err))
	}
	if handle != predicted {
		// Portals older than 0.9 return unpredictable handles; refusing them
		// avoids missing a Response emitted before a late subscription.
		p.closeRequest(ctx, handle)
		return nil, unavailable("portal_request_path_unexpected", nil)
	}
	select {
	case signal := <-watch.signals:
		var response uint32
		var results map[string]dbus.Variant
		if err := dbus.Store(signal.Body, &response, &results); err != nil {
			return nil, unavailable("portal_response_invalid", err)
		}
		switch response {
		case responseSuccess:
			return results, nil
		case responseCancel:
			return nil, ErrPortalCancelled
		default:
			return nil, unavailable("portal_request_failed", fmt.Errorf("%s: response %d", method, response))
		}
	case <-ctx.Done():
		p.closeRequest(ctx, handle)
		return nil, ctx.Err()
	case <-p.bus.done:
		return nil, unavailable("session_bus_closed", nil)
	}
}

func (p *DesktopPortal) closeRequest(ctx context.Context, handle dbus.ObjectPath) {
	call, cancel := context.WithTimeout(context.WithoutCancel(ctx), busCallTimeout)
	defer cancel()
	if err := p.bus.call(call, portalName, handle, requestIface+".Close").Err; err != nil {
		p.logger.Debug("portal request close failed", "err", err)
	}
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

func firstStream(results map[string]dbus.Variant) (Stream, error) {
	value, ok := results["streams"]
	if !ok {
		return Stream{}, errors.New("missing streams")
	}
	var streams []portalStream
	if err := value.Store(&streams); err != nil {
		return Stream{}, fmt.Errorf("decode streams: %w", err)
	}
	if len(streams) == 0 {
		return Stream{}, errors.New("no stream granted")
	}
	stream := Stream{NodeID: streams[0].Node}
	if size, ok := streams[0].Properties["size"]; ok {
		var dims struct{ Width, Height int32 }
		if size.Store(&dims) == nil && dims.Width > 0 && dims.Height > 0 {
			stream.Width, stream.Height = int(dims.Width), int(dims.Height)
		}
	}
	return stream, nil
}

// portalGrant is a started portal session.
type portalGrant struct {
	bus      *SessionBus
	handle   dbus.ObjectPath
	stream   Stream
	control  bool
	watch    *busWatch
	closed   chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

var _ Grant = (*portalGrant)(nil)

func (g *portalGrant) Stream() Stream          { return g.stream }
func (g *portalGrant) ControlGranted() bool    { return g.control }
func (g *portalGrant) Closed() <-chan struct{} { return g.closed }

func (g *portalGrant) watchClosed() {
	defer close(g.done)
	select {
	case <-g.watch.signals:
		close(g.closed)
	case <-g.bus.done:
		close(g.closed)
	case <-g.stop:
	}
}

func (g *portalGrant) stopWatching() {
	g.stopOnce.Do(func() { close(g.stop) })
	<-g.done
	ctx, cancel := context.WithTimeout(context.Background(), busCallTimeout)
	defer cancel()
	_ = g.watch.stop(ctx)
}

func (g *portalGrant) OpenPipeWire(ctx context.Context) (*os.File, error) {
	var fd dbus.UnixFD
	if err := g.bus.call(ctx, portalName, portalPath, screenCastIface+".OpenPipeWireRemote", g.handle, map[string]dbus.Variant{}).Store(&fd); err != nil {
		return nil, fmt.Errorf("open pipewire remote: %w", err)
	}
	if fd < 0 {
		return nil, errors.New("open pipewire remote: invalid fd")
	}
	syscall.CloseOnExec(int(fd))
	return os.NewFile(uintptr(fd), "pipewire-remote"), nil
}

func (g *portalGrant) Inject(ctx context.Context, event InputEvent) error {
	if !g.control {
		return errors.New("input not granted")
	}
	options := map[string]dbus.Variant{}
	method := func(name string, args ...any) error {
		if err := g.bus.call(ctx, portalName, portalPath, remoteDesktopIface+"."+name, append([]any{g.handle, options}, args...)...).Err; err != nil {
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
	default:
		return errors.New("unknown input event")
	}
}

func (g *portalGrant) Close(ctx context.Context) error {
	g.stopWatching()
	if err := g.bus.call(ctx, portalName, g.handle, portalSessionIface+".Close").Err; err != nil {
		return fmt.Errorf("close portal session: %w", err)
	}
	return nil
}
