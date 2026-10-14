// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestCaptureCursorMode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		gnome       bool
		version     string
		modes, want uint32
	}{
		{"gnome46", true, "46.0", 7, cursorEmbedded},
		{"gnome49", true, "49.5", 7, cursorEmbedded},
		{"gnome50", true, "50.0", 7, cursorHidden},
		{"gnome50beta", true, "50.beta", 7, cursorHidden},
		{"gnome51", true, "51", 7, cursorHidden},
		{"unknownGNOME", true, "", 7, cursorHidden},
		{"invalidGNOME", true, "49junk", 7, cursorHidden},
		{"oversizedGNOME", true, "49." + strings.Repeat("x", 64), 7, cursorHidden},
		{"noAdvertisedHidden", true, "50.3", cursorEmbedded, 0},
		{"oldPortalDefault", true, "50", 0, 0},
		{"otherDesktop", false, "", 7, cursorEmbedded},
		{"hiddenOnly", false, "", cursorHidden, cursorHidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectCaptureCursorMode(tc.modes, tc.gnome, tc.version); got != tc.want {
				t.Fatalf("cursor mode = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRunningShellVersionControlsCaptureCursorMode(t *testing.T) {
	for _, version := range []string{"46.0", "49.1", "50.0", "50.3", ""} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			server, bus := privateSessionBus(t, ctx, shellName, portalName)
			if err := server.ExportMethodTable(map[string]any{"Get": func(iface, name string) (dbus.Variant, *dbus.Error) {
				if iface != shellName || name != "ShellVersion" {
					t.Error("wrong compositor property requested")
				}
				return dbus.MakeVariant(version), nil
			}}, dbus.ObjectPath("/org/gnome/Shell"), "org.freedesktop.DBus.Properties"); err != nil {
				t.Fatal(err)
			}
			portal, err := NewDesktopPortal(bus, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			got, err := portal.captureCursorMode(ctx, 7)
			want := cursorHidden
			if version == "46.0" || version == "49.1" {
				want = cursorEmbedded
			}
			if err != nil || got != want {
				t.Fatalf("mode = %d, %v; want %d", got, err, want)
			}
			// Qualify the actual capture setup options on the portal wire,
			// not just the selector: the unsafe embedded mode must not leak
			// into SelectSources and the report must match that request.
			if err := server.ExportMethodTable(map[string]any{"SelectSources": func(sender dbus.Sender, _ dbus.ObjectPath, options map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
				if options["cursor_mode"].Value() != want {
					t.Error("SelectSources did not use the safe cursor mode")
				}
				token, ok := options["handle_token"].Value().(string)
				if !ok {
					t.Error("missing request token")
					return "", dbus.MakeFailedError(io.ErrUnexpectedEOF)
				}
				path := dbus.ObjectPath("/org/freedesktop/portal/desktop/request/" + strings.ReplaceAll(strings.TrimPrefix(string(sender), ":"), ".", "_") + "/" + token)
				if err := server.Emit(path, requestIface+".Response", responseSuccess, map[string]dbus.Variant{}); err != nil {
					return "", dbus.MakeFailedError(err)
				}
				return path, nil
			}}, portalPath, screenCastIface); err != nil {
				t.Fatal(err)
			}
			owner, err := bus.nameOwner(ctx, portalName)
			if err != nil {
				t.Fatal(err)
			}
			grant := &portalGrant{owner: owner, handle: dbus.ObjectPath("/session/cursor")}
			sender := strings.ReplaceAll(strings.TrimPrefix(bus.conn.Names()[0], ":"), ".", "_")
			if err := portal.configureSession(ctx, PortalRequest{Mode: modeView}, grant, sender, 0, 7); err != nil {
				t.Fatal(err)
			}
			if grant.CursorHidden() != (want == cursorHidden) {
				t.Fatal("reported cursor visibility differs from capture setup")
			}
		})
	}
	t.Run("notGNOME", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		_, bus := privateSessionBus(t, ctx)
		portal, err := NewDesktopPortal(bus, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := portal.captureCursorMode(ctx, 7); err != nil || got != cursorEmbedded {
			t.Fatalf("non-GNOME mode = %d, %v", got, err)
		}
	})
	t.Run("unreadableGNOME", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		_, bus := privateSessionBus(t, ctx, shellName)
		portal, err := NewDesktopPortal(bus, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := portal.captureCursorMode(ctx, 7); err != nil || got != cursorHidden {
			t.Fatalf("unreadable GNOME mode = %d, %v", got, err)
		}
	})
}

func TestCursorLimitationSurvivesCapabilityProtocolWithoutChangingAuthority(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		policy := tierOneInvitation(modeControl).GetRequestedCapabilities()
		grant := &fakeGrant{control: true, clipboard: true, cursorHidden: hidden,
			streams: []Stream{{ID: "one"}, {ID: "two"}}}
		caps := grantedCapabilities(policy, grant)
		data, err := proto.Marshal(caps)
		if err != nil {
			t.Fatal(err)
		}
		decoded := new(agentv1.AssistanceCapabilities)
		if err := proto.Unmarshal(data, decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.GetCursorHidden() != hidden || !proto.Equal(decoded.GetPolicy(), policy) {
			t.Fatal("cursor limitation lost or changed consented authority")
		}
	}
}
