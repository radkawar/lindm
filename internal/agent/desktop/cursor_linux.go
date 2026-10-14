// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

// captureCursorMode probes the running compositor, not the installed package:
// upgraded packages need not describe the user's current desktop process.
func (p *DesktopPortal) captureCursorMode(ctx context.Context, modes uint32) (uint32, error) {
	owner, err := p.bus.nameOwner(ctx, shellName)
	if err != nil {
		if dbusErrorName(err) != "org.freedesktop.DBus.Error.NameHasNoOwner" {
			return 0, unavailable("cursor_compositor_probe_failed", err)
		}
		return selectCaptureCursorMode(modes, false, ""), nil
	}
	value, err := p.bus.property(ctx, owner, dbus.ObjectPath("/org/gnome/Shell"), shellName, "ShellVersion")
	var version string
	if err == nil {
		_ = value.Store(&version)
	}
	if len(version) > 64 {
		version = ""
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	// A running GNOME Shell with an unreadable/malformed version takes the
	// safe path too. Never fall back to embedded after a failed GNOME probe.
	mode := selectCaptureCursorMode(modes, true, version)
	p.logger.Info("capture compositor probed", "compositor", shellName, "version", version, "cursor_mode", mode)
	return mode, nil
}

func selectCaptureCursorMode(modes uint32, gnome bool, version string) uint32 {
	if gnome {
		major, _, _ := strings.Cut(version, ".")
		n, err := strconv.ParseUint(major, 10, 16)
		if len(version) > 64 || err != nil || n == 0 || n >= 50 {
			// Mutter >=50's embedded hardware-cursor inhibitor dereferences a
			// removed logical monitor on unplug. Stock pipewiresrc discards
			// bitmap/hotspot metadata, so use the owner's HIDDEN fallback.
			// HIDDEN is the portal default, even before AvailableCursorModes.
			if modes&cursorHidden != 0 {
				return cursorHidden
			}
			return 0
		}
	}
	if modes&cursorEmbedded != 0 {
		return cursorEmbedded
	}
	if modes&cursorHidden != 0 {
		return cursorHidden
	}
	return 0
}
