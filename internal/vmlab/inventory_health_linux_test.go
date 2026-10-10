//go:build linux

package vmlab

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func healthyInventoryFixture() (*inventoryv1.HostObservation, *inventoryv1.PackageObservation) {
	details := nativeDetailsFixture()
	details.Platform = &inventoryv1.PlatformDetails{Cpe: truthString(""), ReleaseverLock: truthString(""), Releasever: truthString(""), Repositories: &inventoryv1.RepositoryObservation{Status: truthUnavailable}}
	details.Sessions.ActiveSessions = &inventoryv1.ActiveSessions{Status: truthSuccess}
	iface := details.Network.Interfaces[0]
	iface.DefaultRouteIpv4, iface.DefaultRouteIpv6 = truthBool(true), truthBool(false)
	block := details.Storage.Devices[0]
	block.Identity = storageTruthIdentity(map[string]string{"TRAN": "virtio", "PARTUUID": "partition-id", "PARTTYPE": "linux-data", "UUID": "filesystem-id"})
	block.Identity.BackingDisk, block.Identity.RootBacking = truthString("vda"), truthBool(true)
	host := &inventoryv1.HostObservation{
		OsId: truthString("ubuntu"), OsVersion: truthString("24.04"), Architecture: truthString("x86_64"),
		KernelRelease: truthString("6.8.0"), Hostname: truthString("private-host"), BootId: truthString("private-boot"),
		HardwareVendor: truthString("QEMU"), HardwareModel: truthString("Standard PC"), HardwareSerial: truthString(""), Details: details,
	}
	packages := &inventoryv1.PackageObservation{Status: truthSuccess, Backend: "dpkg", Packages: []*inventoryv1.Package{{Name: "example", Version: "1", Architecture: "amd64", Manager: "dpkg", Module: &inventoryv1.ModuleObservation{Status: truthUnavailable}}}}
	return host, packages
}

func TestInventoryHealthAllowsReasonedNativeAbsence(t *testing.T) {
	host, packages := healthyInventoryFixture()
	if err := CheckInventoryHealth(host, packages); err != nil {
		t.Fatal(err)
	}
	// Successful false and zero values are health evidence, not absence.
	host.Details.Memory.SwapTotalBytes = truthUint(0)
	host.Details.Tpm.Present = truthBool(false)
	if err := CheckInventoryHealth(host, packages); err != nil {
		t.Fatal(err)
	}
	for _, rule := range inventoryUnavailableRules {
		if strings.TrimSpace(rule.reason) == "" || len(rule.distros) == 0 || strings.ContainsAny(rule.path, "*?") {
			t.Fatalf("unreasoned or wildcard exception: %s", rule.path)
		}
	}
}

func TestInventoryHealthRequiresCurrentCPUModelSource(t *testing.T) {
	for _, source := range []string{"proc_cpuinfo", "smbios_type4", "arm_midr_procfs", "arm_midr_sysfs"} {
		host, packages := healthyInventoryFixture()
		host.Details.Cpu.ModelSource = truthString(source)
		if err := CheckInventoryHealth(host, packages); err != nil {
			t.Fatalf("valid CPU model source rejected: %v", err)
		}
	}
	for _, source := range []*inventoryv1.ObservedString{nil, truthString(""), truthString("lscpu"), {Status: truthDenied}, {Status: truthSuccess}} {
		host, packages := healthyInventoryFixture()
		host.Details.Cpu.ModelSource = source
		if err := CheckInventoryHealth(host, packages); err == nil || !strings.Contains(err.Error(), "cpu.model_source") {
			t.Fatalf("invalid current CPU model source accepted or misattributed: %v", err)
		}
	}
	host, packages := healthyInventoryFixture()
	host.Architecture = truthString("aarch64")
	host.Details.Cpu.Model = truthString("")
	host.Details.Cpu.ModelSource = truthString("")
	if err := CheckInventoryHealth(host, packages); err == nil || !strings.Contains(err.Error(), "cpu.model") {
		t.Fatalf("unavailable ARM CPU model was weakened: %v", err)
	}
}

func TestInventoryHealthContextualSeatApplicability(t *testing.T) {
	notApplicable := inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE
	for _, tc := range []struct {
		name     string
		change   func(*inventoryv1.ActiveSession)
		accepted bool
	}{
		{"manager", func(s *inventoryv1.ActiveSession) {}, true},
		{"background", func(s *inventoryv1.ActiveSession) { s.SessionClass.Value = "background" }, true},
		{"remote", func(s *inventoryv1.ActiveSession) {
			s.SessionClass.Value = "user"
			s.SessionType.Value = "x11"
			s.Remote.Value = true
		}, true},
		{"tty", func(s *inventoryv1.ActiveSession) { s.SessionClass.Value = "user"; s.SessionType.Value = "tty" }, true},
		{"local-x11", func(s *inventoryv1.ActiveSession) { s.SessionClass.Value = "user"; s.SessionType.Value = "x11" }, false},
		{"local-wayland", func(s *inventoryv1.ActiveSession) { s.SessionClass.Value = "user"; s.SessionType.Value = "wayland" }, false},
		{"unknown", func(s *inventoryv1.ActiveSession) { s.SessionClass.Value = "unknown" }, false},
		{"nonempty-seat", func(s *inventoryv1.ActiveSession) { s.Seat.Value = "seat0" }, false},
		{"missing-class", func(s *inventoryv1.ActiveSession) { s.SessionClass = nil }, false},
		{"missing-type", func(s *inventoryv1.ActiveSession) { s.SessionType = nil }, false},
		{"missing-remote", func(s *inventoryv1.ActiveSession) { s.Remote = nil }, false},
		{"failed-class", func(s *inventoryv1.ActiveSession) { s.SessionClass.Status = truthDenied }, false},
		{"failed-type", func(s *inventoryv1.ActiveSession) { s.SessionType.Status = truthDenied }, false},
		{"failed-remote", func(s *inventoryv1.ActiveSession) { s.Remote.Status = truthDenied }, false},
		{"wrong-field", func(s *inventoryv1.ActiveSession) { s.UserName.Status = notApplicable; s.UserName.Value = "" }, false},
		{"unavailable-manager", func(s *inventoryv1.ActiveSession) { s.Seat.Status = truthUnavailable }, false},
		{"unavailable-remote", func(s *inventoryv1.ActiveSession) { s.Seat.Status = truthUnavailable; s.Remote.Value = true }, false},
		{"unavailable-tty", func(s *inventoryv1.ActiveSession) { s.Seat.Status = truthUnavailable; s.SessionType.Value = "tty" }, false},
		{"actual-seat", func(s *inventoryv1.ActiveSession) { s.Seat = truthString("seat0") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, packages := healthyInventoryFixture()
			session := &inventoryv1.ActiveSession{
				UserName: truthString("lindm-lab"), SessionClass: truthString("manager"),
				SessionType: truthString("unspecified"), Remote: truthBool(false),
				Seat: &inventoryv1.ObservedString{Status: notApplicable},
			}
			tc.change(session)
			host.Details.Sessions.ActiveSessions.Sessions = []*inventoryv1.ActiveSession{session}
			if err := CheckInventoryHealth(host, packages); (err == nil) != tc.accepted {
				t.Fatalf("accepted=%t: %v", tc.accepted, err)
			}
		})
	}
	// A valid context cannot authorize another message or path.
	session := &inventoryv1.ActiveSession{
		SessionClass: truthString("manager"), SessionType: truthString("unspecified"), Remote: truthBool(false),
		Seat: &inventoryv1.ObservedString{Status: notApplicable},
	}
	context := inventoryHealthContext{session: session}
	for _, path := range []string{"host.hostname", "host.details.sessions.active_sessions", "host.details.sessions.active_sessions.sessions.remote"} {
		if err := checkInventoryMessage(session.Seat.ProtoReflect(), path, context, true); err == nil {
			t.Fatalf("accepted forged status at %s", path)
		}
	}
	if err := checkInventoryMessage((&inventoryv1.ObservedString{Status: notApplicable}).ProtoReflect(), "host.details.sessions.active_sessions.sessions.seat", context, true); err == nil {
		t.Fatal("accepted seat unrelated to current session")
	}
}

func TestInventoryHealthRejectsEveryNonSuccessOutsideExactExceptions(t *testing.T) {
	for _, status := range []inventoryv1.CollectionStatus{
		inventoryv1.CollectionStatus_COLLECTION_STATUS_UNSPECIFIED,
		truthUnavailable, truthDenied,
		inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT,
		inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT,
		inventoryv1.CollectionStatus_COLLECTION_STATUS_CAPACITY_EXCEEDED,
		inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE,
		inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE,
		inventoryv1.CollectionStatus(99),
	} {
		t.Run(status.String(), func(t *testing.T) {
			host, packages := healthyInventoryFixture()
			host.Details.Memory.TotalBytes.Status = status
			if err := CheckInventoryHealth(host, packages); err == nil || !strings.Contains(err.Error(), "host.details.memory.total_bytes") {
				t.Fatalf("non-success memory accepted or misattributed: %v", err)
			}
			before, after, actual := nativeDetailsFixture(), nativeDetailsFixture(), nativeDetailsFixture()
			for _, details := range []*inventoryv1.NativeDetails{before, after, actual} {
				details.Memory.TotalBytes.Status = status
			}
			if err := compareVMDetails("ubuntu", "x86_64", before, after, actual); err == nil {
				t.Fatal("matching native failures were accepted")
			}
		})
	}
}

func TestInventoryHealthNeverAllowsFailuresAtAllowlistedFields(t *testing.T) {
	for _, status := range []inventoryv1.CollectionStatus{truthDenied, inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT, inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT, inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE, inventoryv1.CollectionStatus(99)} {
		host, packages := healthyInventoryFixture()
		host.Details.Snap.Status = status
		if err := CheckInventoryHealth(host, packages); err == nil {
			t.Fatalf("allowlist suppressed %s", status)
		}
		before, after, actual := nativeDetailsFixture(), nativeDetailsFixture(), nativeDetailsFixture()
		before.Snap.Status, after.Snap.Status, actual.Snap.Status = status, status, status
		if err := compareVMDetails("ubuntu", "x86_64", before, after, actual); err == nil {
			t.Fatalf("matching allowlisted-field failures accepted: %s", status)
		}
	}
}

func TestInventoryHealthRequiresDistroAndNativeCapabilityContext(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*inventoryv1.HostObservation, *inventoryv1.PackageObservation)
	}{
		{"unknown distro", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.OsId.Value = "ubuntu-lookalike"
		}},
		{"non-QEMU serial", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.HardwareVendor.Value = "physical-vendor"
		}},
		{"installed RPM platform", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.Details.Backends.Rpm.Value = true
		}},
		{"installed snap", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.Details.Backends.Snap.Value = true
		}},
		{"installed flatpak", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.Details.Backends.Flatpak.Value = true
		}},
		{"present TPM", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.Details.Tpm.Present.Value = true
		}},
		{"UEFI secure boot", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.Details.Firmware.Mode.Value = "uefi"
		}},
		{"backend detection", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.Details.Backends.Rpm.Status = truthUnavailable
		}},
		{"missing category", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) { h.Details.Platform = nil }},
		{"missing identity", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.Details.Storage.Devices[0].Identity = nil
		}},
		{"package collection", func(_ *inventoryv1.HostObservation, p *inventoryv1.PackageObservation) { p.Status = truthUnavailable }},
		{"package module failure", func(_ *inventoryv1.HostObservation, p *inventoryv1.PackageObservation) {
			p.Packages[0].Module.Status = truthDenied
		}},
		{"missing package module", func(_ *inventoryv1.HostObservation, p *inventoryv1.PackageObservation) { p.Packages[0].Module = nil }},
		{"non-native module absence", func(_ *inventoryv1.HostObservation, p *inventoryv1.PackageObservation) { p.Packages[0].Manager = "rpm" }},
		{"missing LUKS metadata", func(h *inventoryv1.HostObservation, _ *inventoryv1.PackageObservation) {
			h.Details.Storage.Devices[0].Filesystem.Value = "crypto_LUKS"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, packages := healthyInventoryFixture()
			test.mutate(host, packages)
			if err := CheckInventoryHealth(host, packages); err == nil {
				t.Fatal("accepted inapplicable exception or incomplete evidence")
			}
		})
	}
}

func TestInventoryHealthFedoraRepositoriesAreApplicable(t *testing.T) {
	host, packages := healthyInventoryFixture()
	host.OsId.Value, host.OsVersion.Value = "fedora", "44"
	host.Details.Platform.Cpe = truthString("cpe:/o:fedoraproject:fedora:44")
	host.Details.Platform.Releasever = truthString("44")
	host.Details.Backends.Dpkg.Value, host.Details.Backends.Rpm.Value = false, true
	packages.Backend, packages.Packages[0].Manager = "rpm", "rpm"
	packages.Packages[0].Module.Status = truthSuccess
	if err := CheckInventoryHealth(host, packages); err == nil || !strings.Contains(err.Error(), "platform.repositories") {
		t.Fatalf("Fedora repository collector gap did not fail: %v", err)
	}
	host.Details.Platform.Repositories = &inventoryv1.RepositoryObservation{Status: truthSuccess, Backend: "dnf5", Ids: []string{"fedora", "updates"}, Configurations: []*inventoryv1.RepositoryConfiguration{{Id: "fedora"}, {Id: "updates"}}}
	if err := CheckInventoryHealth(host, packages); err != nil {
		t.Fatal(err)
	}
	host.Details.Platform.Releasever = truthString("")
	if err := CheckInventoryHealth(host, packages); err == nil || !strings.Contains(err.Error(), "platform.releasever") {
		t.Fatalf("Fedora effective releasever gap did not fail: %v", err)
	}
	host.Details.Platform.Releasever = truthString("44")
	host.Details.Platform.Repositories.Configurations = nil
	if err := CheckInventoryHealth(host, packages); err == nil || !strings.Contains(err.Error(), "platform.repositories.configurations") {
		t.Fatalf("Fedora repository configuration gap did not fail: %v", err)
	}
}

func TestInventoryHealthRHELRequiresEffectiveReleaseAndCompleteConfiguration(t *testing.T) {
	host, packages := healthyInventoryFixture()
	host.OsId.Value, host.OsVersion.Value = "rhel", "9.8"
	host.Details.Platform.Cpe = truthString("cpe:/o:redhat:enterprise_linux:9::baseos")
	host.Details.Platform.Releasever = truthString("9.8")
	host.Details.Platform.Repositories = &inventoryv1.RepositoryObservation{
		Status: truthSuccess, Backend: "dnf4", Ids: []string{"rhel-9-for-x86_64-baseos-rpms"},
		Configurations: []*inventoryv1.RepositoryConfiguration{{Id: "rhel-9-for-x86_64-baseos-rpms", Gpgcheck: true}},
	}
	host.Details.Backends.Dpkg.Value, host.Details.Backends.Rpm.Value = false, true
	packages.Backend, packages.Packages[0].Manager = "rpm", "rpm"
	packages.Packages[0].Module.Status = truthSuccess
	if err := CheckInventoryHealth(host, packages); err != nil {
		t.Fatal(err)
	}
	// A missing explicit lock remains optional; the resolved native value does not.
	host.Details.Platform.Releasever = truthString("")
	if err := CheckInventoryHealth(host, packages); err == nil || !strings.Contains(err.Error(), "platform.releasever") {
		t.Fatalf("RHEL effective releasever absence accepted: %v", err)
	}
	host.Details.Platform.Releasever = truthString("9.8")
	host.Details.Platform.Repositories.Configurations[0].Id = "unrelated"
	if err := CheckInventoryHealth(host, packages); err == nil || !strings.Contains(err.Error(), "platform.repositories.configurations") {
		t.Fatalf("RHEL mismatched configuration identity accepted: %v", err)
	}
}

func TestInventoryHealthMatchingPackageModuleFailuresFail(t *testing.T) {
	truth, actual := vmTestObservation()
	failed := make(map[nativePackage]int, len(truth.packages))
	for key, count := range truth.packages {
		key.module.status = truthDenied
		failed[key] = count
	}
	truth.packages = failed
	actual.Packages.Packages[0].Module.Status = truthDenied
	if err := compareVMObservation(truth, actual); err == nil {
		t.Fatal("matching package module failures accepted")
	}
}

func TestInventoryHealthDoesNotMutateEvidence(t *testing.T) {
	host, packages := healthyInventoryFixture()
	beforeHost, beforePackages := proto.CloneOf(host), proto.CloneOf(packages)
	if err := CheckInventoryHealth(host, packages); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(host, beforeHost) || !proto.Equal(packages, beforePackages) {
		t.Fatal("health gate changed evidence")
	}
}
