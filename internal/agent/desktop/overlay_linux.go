// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// The packaged GNOME Shell extension (lindm-overlay@lindm.dev) is the only
// qualified overlay: Wayland has no universal overlay portal, and an ordinary
// client window would take focus and intercept local input. The extension's
// actors are non-reactive, sit below system modal dialogs and the lock screen,
// and draw only lines and a fixed pointer glyph, never caller-supplied text.
const (
	overlayName          = "dev.lindm.AssistOverlay"
	overlayPath          = dbus.ObjectPath("/dev/lindm/AssistOverlay")
	overlayIface         = "dev.lindm.AssistOverlay1"
	overlayExtension     = "lindm-overlay@lindm.dev"
	overlayVersion       = uint32(2)
	shellPath            = dbus.ObjectPath("/org/gnome/Shell")
	shellExtensionsIface = "org.gnome.Shell.Extensions"
	overlayEnableWait    = 3 * time.Second
)

// ShellOverlay drives the GNOME Shell overlay extension.
type ShellOverlay struct {
	bus     *SessionBus
	desktop string

	mu      sync.Mutex
	owner   string
	enabled bool
}

var _ Overlay = (*ShellOverlay)(nil)

// NewShellOverlay returns the overlay client for currentDesktop.
func NewShellOverlay(bus *SessionBus, currentDesktop string) (*ShellOverlay, error) {
	if bus == nil {
		return nil, errors.New("desktop: missing overlay bus")
	}
	return &ShellOverlay{bus: bus, desktop: currentDesktop}, nil
}

// Check requires the extension to be served by the running gnome-shell
// itself, so another session-bus client cannot pose as the overlay.
func (o *ShellOverlay) Check(ctx context.Context) error {
	if !gnomeDesktop(o.desktop) {
		return unavailable("overlay_unsupported_desktop", nil)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	shell, err := o.bus.nameOwner(ctx, shellName)
	if err != nil {
		return unavailable("overlay_shell_unavailable", err)
	}
	owner, err := o.bus.nameOwner(ctx, overlayName)
	if err != nil {
		var enabled bool
		if callErr := o.bus.call(ctx, shellName, shellPath, shellExtensionsIface+".EnableExtension", overlayExtension).Store(&enabled); callErr != nil || !enabled {
			return unavailable("overlay_extension_unavailable", errors.Join(err, callErr))
		}
		o.enabled = true
		deadline := time.NewTimer(overlayEnableWait)
		defer deadline.Stop()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for owner == "" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-deadline.C:
				return unavailable("overlay_extension_unavailable", errors.New("overlay name not owned after enable"))
			case <-tick.C:
				owner, _ = o.bus.nameOwner(ctx, overlayName)
			}
		}
	}
	if owner != shell {
		return unavailable("overlay_owner_untrusted", nil)
	}
	value, err := o.bus.property(ctx, owner, overlayPath, overlayIface, "Version")
	var version uint32
	if err != nil || value.Store(&version) != nil || version != overlayVersion {
		return unavailable("overlay_extension_version", err)
	}
	// The extension verifies this connection's bus credentials and binds
	// Draw and Clear to it; other session-bus clients are refused.
	if err := o.bus.call(ctx, owner, overlayPath, overlayIface+".Claim").Err; err != nil {
		return unavailable("overlay_claim_refused", err)
	}
	o.owner = owner
	return nil
}

type overlayRect struct{ X, Y, Width, Height int32 }
type overlayPoint struct{ X, Y float64 }

func (o *ShellOverlay) target() (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.owner == "" {
		return "", errors.New("overlay_not_checked")
	}
	return o.owner, nil
}

func (o *ShellOverlay) Draw(ctx context.Context, frame OverlayFrame) error {
	owner, err := o.target()
	if err != nil {
		return err
	}
	rect := overlayRect{X: int32(frame.X), Y: int32(frame.Y), Width: int32(frame.Width), Height: int32(frame.Height)}
	var pointer overlayPoint
	if frame.Pointer != nil {
		pointer = overlayPoint{X: frame.Pointer.X, Y: frame.Pointer.Y}
	}
	strokes := make([][]overlayPoint, 0, len(frame.Strokes))
	for _, stroke := range frame.Strokes {
		points := make([]overlayPoint, len(stroke))
		for i, point := range stroke {
			points[i] = overlayPoint(point)
		}
		strokes = append(strokes, points)
	}
	return o.bus.call(ctx, owner, overlayPath, overlayIface+".Draw", rect, frame.Pointer != nil, pointer, strokes).Err
}

func (o *ShellOverlay) Clear(ctx context.Context) error {
	owner, err := o.target()
	if err != nil {
		return err
	}
	return o.bus.call(ctx, owner, overlayPath, overlayIface+".Clear").Err
}

// Release clears the overlay and disables the extension when this helper
// enabled it, leaving the employee's extension settings as they were.
func (o *ShellOverlay) Release(ctx context.Context) error {
	o.mu.Lock()
	owner, enabled := o.owner, o.enabled
	o.owner, o.enabled = "", false
	o.mu.Unlock()
	var errs []error
	if owner != "" {
		errs = append(errs, o.bus.call(ctx, owner, overlayPath, overlayIface+".Clear").Err)
	}
	if enabled {
		var disabled bool
		errs = append(errs, o.bus.call(ctx, shellName, shellPath, shellExtensionsIface+".DisableExtension", overlayExtension).Store(&disabled))
	}
	return errors.Join(errs...)
}

func gnomeDesktop(current string) bool {
	for desktop := range strings.SplitSeq(current, ":") {
		if desktop == "GNOME" {
			return true
		}
	}
	return false
}
