package resource

import (
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestModuleBlocklistClosedTemplate(t *testing.T) {
	valid := desiredJSON(t, `{"managedFile":{"path":"/etc/modprobe.d/99-lindm-blocklist.conf","presence":1,"kernelModuleBlocklist":{"modules":["usb_storage","uas"]}}}`)
	if err := ValidateDesired(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*resourcev1.ManagedFileDesired){
		"arbitrary path":   func(d *resourcev1.ManagedFileDesired) { d.Path = "/etc/modprobe.d/arbitrary.conf" },
		"raw commands":     func(d *resourcev1.ManagedFileDesired) { d.Content = []byte("install usb_storage /bin/sh\n") },
		"arbitrary mode":   func(d *resourcev1.ManagedFileDesired) { d.Mode = proto.Uint32(0777) },
		"arbitrary owner":  func(d *resourcev1.ManagedFileDesired) { d.Uid = proto.Uint32(1000) },
		"empty list":       func(d *resourcev1.ManagedFileDesired) { d.KernelModuleBlocklist.Modules = nil },
		"duplicate":        func(d *resourcev1.ManagedFileDesired) { d.KernelModuleBlocklist.Modules = []string{"uas", "uas"} },
		"alias wildcard":   func(d *resourcev1.ManagedFileDesired) { d.KernelModuleBlocklist.Modules = []string{"usb*"} },
		"option injection": func(d *resourcev1.ManagedFileDesired) { d.KernelModuleBlocklist.Modules = []string{"--remove"} },
		"newline injection": func(d *resourcev1.ManagedFileDesired) {
			d.KernelModuleBlocklist.Modules = []string{"usb_storage\ninstall uas /bin/sh"}
		},
		"noncanonical hyphen": func(d *resourcev1.ManagedFileDesired) { d.KernelModuleBlocklist.Modules = []string{"usb-storage"} },
		"absent template":     func(d *resourcev1.ManagedFileDesired) { d.Presence = resourcev1.Presence_PRESENCE_ABSENT },
	} {
		t.Run(name, func(t *testing.T) {
			bad := proto.CloneOf(valid)
			mutate(bad.GetManagedFile())
			if err := ValidateDesired(bad); err == nil {
				t.Fatal("unsafe template accepted")
			}
		})
	}
	claims, err := Claims(valid)
	if err != nil {
		t.Fatal(err)
	}
	other := proto.CloneOf(valid)
	other.GetManagedFile().KernelModuleBlocklist.Modules = []string{"floppy"}
	otherClaims, err := Claims(other)
	if err != nil {
		t.Fatal(err)
	}
	if !Conflicts(claims, otherClaims) || Conflicts(claims, claims) {
		t.Fatal("blocklist did not retain exclusive native-file claims")
	}
}
