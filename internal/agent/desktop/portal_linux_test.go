// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/godbus/dbus/v5"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// TestGrantedStreamsDecodesWireShape uses godbus' a(ua{sv}) representation.
// This is a deterministic decoding test, not native portal qualification.
func TestGrantedStreamsDecodesWireShape(t *testing.T) {
	results := map[string]dbus.Variant{
		"devices": dbus.MakeVariant(uint32(3)),
		"streams": dbus.MakeVariantWithSignature([][]any{{
			uint32(51),
			map[string]dbus.Variant{
				"size":        dbus.MakeVariantWithSignature([]any{int32(1280), int32(800)}, dbus.ParseSignatureMust("(ii)")),
				"position":    dbus.MakeVariantWithSignature([]any{int32(1920), int32(0)}, dbus.ParseSignatureMust("(ii)")),
				"source_type": dbus.MakeVariant(uint32(1)),
			},
		}}, dbus.ParseSignatureMust("a(ua{sv})")),
	}
	streams, err := grantedStreams(results)
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 1 || streams[0] != (Stream{NodeID: 51, ID: "monitor-1", Label: "Monitor 1", Width: 1280, Height: 800, X: 1920, Positioned: true}) {
		t.Fatalf("streams = %+v", streams)
	}
	if _, err := grantedStreams(map[string]dbus.Variant{}); err == nil {
		t.Fatal("missing streams accepted")
	}
}

func TestSessionHandleForms(t *testing.T) {
	path := "/org/freedesktop/portal/desktop/session/1_42/lindm_ab"
	for _, value := range []dbus.Variant{dbus.MakeVariant(dbus.ObjectPath(path)), dbus.MakeVariant(path)} {
		got, err := sessionHandle(map[string]dbus.Variant{"session_handle": value})
		if err != nil || string(got) != path {
			t.Fatalf("sessionHandle(%v) = %q, %v", value, got, err)
		}
	}
	if _, err := sessionHandle(map[string]dbus.Variant{"session_handle": dbus.MakeVariant("not a path")}); err == nil {
		t.Fatal("invalid handle accepted")
	}
}

func TestPortalRequestedDevicesRespectModeAndKeyboardConsent(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     agentv1.AssistanceMode
		keyboard agentv1.AssistancePolicyMode
		want     uint32
	}{
		{"view", modeView, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, 0},
		{"pointer_only", modeControl, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, devicePointer},
		{"unspecified_keyboard", modeControl, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_UNSPECIFIED, devicePointer},
		{"printable_keyboard", modeControl, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, devicePointer | deviceKeyboard},
		{"full_keyboard", modeControl, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, devicePointer | deviceKeyboard},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := PortalRequest{Mode: test.mode, Policy: &agentv1.AssistancePolicy{
				Keyboard:  test.keyboard,
				Clipboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON,
				Display:   agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON,
				Messages:  agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON,
			}}
			if got := request.deviceTypes(); got != test.want {
				t.Fatalf("requested devices = %d, want %d", got, test.want)
			}
		})
	}
}

func TestPortalPreflightRequiresBothCosmicInterfacesWithoutControl(t *testing.T) {
	for _, test := range []struct {
		name                     string
		screenCast, remote, both bool
		detail                   string
	}{
		{"missing_screencast", false, true, true, "portal_screencast_unavailable"},
		{"cosmic_missing_remote", true, false, true, "portal_remote_desktop_unavailable"},
		{"ordinary_view", true, false, false, ""},
		{"cosmic_both", true, true, true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			server, bus := privateSessionBus(t, ctx, portalName)
			if err := server.ExportMethodTable(map[string]any{
				"Get": func(iface, property string) (dbus.Variant, *dbus.Error) {
					if iface == screenCastIface && !test.screenCast || iface == remoteDesktopIface && !test.remote {
						return dbus.Variant{}, dbus.MakeFailedError(errors.New("interface unavailable"))
					}
					var value uint32
					switch property {
					case "AvailableSourceTypes", "version":
						value = 1
					case "AvailableDeviceTypes":
						// VIEW must only probe presence, not demand input devices.
						value = 0
					}
					return dbus.MakeVariant(value), nil
				},
			}, portalPath, "org.freedesktop.DBus.Properties"); err != nil {
				t.Fatal(err)
			}
			portal, err := NewDesktopPortal(bus, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			err = portal.Check(ctx, PortalRequest{Mode: modeView, RequireRemoteDesktop: test.both})
			var end *EndError
			if test.detail == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.As(err, &end) || end.Detail != test.detail {
				t.Fatalf("preflight = %v, want %s", err, test.detail)
			}
		})
	}
}
