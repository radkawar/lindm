//go:build linux

package serviceprovider

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"

	"lindm/internal/agent/admissiondetail"
)

func TestNotInstalledUnitNamesDetail(t *testing.T) {
	err := nativeReadError("load service", dbus.Error{Name: "org.freedesktop.systemd1.NoSuchUnit"})
	if !errors.Is(err, ErrUnsupported) || admissiondetail.Of(err) != "unit_not_installed" {
		t.Fatalf("NoSuchUnit = %v", err)
	}
	if err := loadStateError("not-found"); !errors.Is(err, ErrUnsupported) || admissiondetail.Of(err) != "unit_not_installed" {
		t.Fatalf("not-found = %v", err)
	}
	for _, state := range []string{"masked", "error", "bad-setting"} {
		if err := loadStateError(state); !errors.Is(err, ErrUnsupported) || admissiondetail.Of(err) != "" {
			t.Fatalf("%s = %v", state, err)
		}
	}
	if err := nativeReadError("load service", dbus.Error{Name: "org.freedesktop.systemd1.UnitMasked"}); !errors.Is(err, ErrUnsupported) || admissiondetail.Of(err) != "" {
		t.Fatalf("masked = %v", err)
	}
}
