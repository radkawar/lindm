//go:build linux

package desktop

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

// TestFirstStreamDecodesWireShape uses the shape godbus produces when it
// decodes a(ua{sv}) Start results (structs become []any), as observed on the
// Ubuntu 24.04 GNOME 46 golden: node 51, size (1280,800).
func TestFirstStreamDecodesWireShape(t *testing.T) {
	results := map[string]dbus.Variant{
		"devices": dbus.MakeVariant(uint32(3)),
		"streams": dbus.MakeVariantWithSignature([][]any{{
			uint32(51),
			map[string]dbus.Variant{
				"size":        dbus.MakeVariantWithSignature([]any{int32(1280), int32(800)}, dbus.ParseSignatureMust("(ii)")),
				"position":    dbus.MakeVariantWithSignature([]any{int32(0), int32(0)}, dbus.ParseSignatureMust("(ii)")),
				"source_type": dbus.MakeVariant(uint32(1)),
			},
		}}, dbus.ParseSignatureMust("a(ua{sv})")),
	}
	stream, err := firstStream(results)
	if err != nil {
		t.Fatal(err)
	}
	if stream != (Stream{NodeID: 51, Width: 1280, Height: 800}) {
		t.Fatalf("stream = %+v", stream)
	}
	if _, err := firstStream(map[string]dbus.Variant{}); err == nil {
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
