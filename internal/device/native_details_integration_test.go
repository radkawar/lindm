//go:build integration

package device

import (
	"strings"
	"testing"

	"lindm/internal/device/inventory"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func nativeDetailsFixture() *inventoryv1.NativeDetails {
	unavailable := inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	text := func() *inventoryv1.ObservedString { return &inventoryv1.ObservedString{Status: unavailable} }
	number := func() *inventoryv1.ObservedUint64 { return &inventoryv1.ObservedUint64{Status: unavailable} }
	boolean := func() *inventoryv1.ObservedBool { return &inventoryv1.ObservedBool{Status: unavailable} }
	return &inventoryv1.NativeDetails{
		Cpu:               &inventoryv1.CpuDetails{Model: text(), LogicalCores: number(), PhysicalCores: number(), X86_64Level: text()},
		Memory:            &inventoryv1.MemoryDetails{TotalBytes: number(), AvailableBytes: number(), SwapTotalBytes: number()},
		Storage:           &inventoryv1.StorageDetails{Status: unavailable},
		Network:           &inventoryv1.NetworkDetails{Status: unavailable},
		Firmware:          &inventoryv1.FirmwareDetails{Mode: text(), SecureBoot: text()},
		Tpm:               &inventoryv1.TpmDetails{Present: boolean(), Version: text()},
		Power:             &inventoryv1.PowerDetails{Chassis: text(), Batteries: &inventoryv1.BatteryDetails{Status: unavailable}},
		Sessions:          &inventoryv1.SessionCounts{Users: number(), Sessions: number()},
		LocalUsers:        &inventoryv1.LocalUsers{Status: unavailable},
		KernelModuleCount: number(), UptimeSeconds: number(), BootTimeUnixSeconds: number(),
		Backends: &inventoryv1.BackendDetails{Dpkg: boolean(), Rpm: boolean(), Pacman: boolean(), Zypper: boolean(), RpmOstree: boolean(), Nix: boolean(), Flatpak: boolean(), Snap: boolean()},
		Flatpak:  &inventoryv1.ApplicationDetails{Status: unavailable}, Snap: &inventoryv1.ApplicationDetails{Status: unavailable},
	}
}

func TestNativeDetailsLatestStatusAndReplay(t *testing.T) {
	f := newEnrolled(t, 0)
	report := hostObservation(f.generation, 1, "native-details")
	report.Observation.Details = nativeDetailsFixture()
	report.Observation.Details.Cpu.Model = observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "Native CPU")
	report.Observation.Details.Cpu.LogicalCores = &inventoryv1.ObservedUint64{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: 8}
	report.Observation.Details.Platform = &inventoryv1.PlatformDetails{
		Cpe:            observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "cpe:/o:redhat:enterprise_linux:9::baseos"),
		ReleaseverLock: observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "9.6"),
		Repositories: &inventoryv1.RepositoryObservation{
			Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Backend: "dnf",
			Ids: []string{"rhel-9-for-x86_64-baseos-eus-rpms"},
		},
	}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	detail, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(detail.Msg.GetHost().GetObservation().GetDetails(), report.Observation.Details) {
		t.Fatal("native details changed during persistence")
	}
	report.Observation.Details.Cpu.LogicalCores.Value = 16
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("changed replay accepted: %v", err)
	}
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	report.Sequence = 2
	report.Observation.Details.Cpu.LogicalCores = &inventoryv1.ObservedUint64{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED}
	report.Observation.Details.Platform.Repositories = &inventoryv1.RepositoryObservation{
		Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE,
	}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	detail, err = f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	cores := detail.Msg.GetHost().GetObservation().GetDetails().GetCpu().GetLogicalCores()
	if cores.GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED || cores.GetValue() != 0 {
		t.Fatalf("latest failure hidden by previous success: %v", cores)
	}
	if !proto.Equal(detail.Msg.GetHost().GetObservation().GetDetails(), report.Observation.Details) {
		t.Fatal("latest native platform failure retained stale evidence")
	}
}

func TestNativeDetailsRejectIncompleteOrFalseSuccess(t *testing.T) {
	f := newEnrolled(t, 0)
	report := hostObservation(f.generation, 1, "invalid-details")
	report.Observation.Details = &inventoryv1.NativeDetails{}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("incomplete details accepted: %v", err)
	}
	report.Observation.Details = nativeDetailsFixture()
	report.Observation.Details.Cpu.Model.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("empty successful model accepted: %v", err)
	}
}

func TestPackageSourceIdentitySurvivesSnapshot(t *testing.T) {
	f := newEnrolled(t, 0)
	pkg := &inventoryv1.Package{Name: "libc6", Version: "2.39-0ubuntu8.6", Architecture: "amd64", Manager: "dpkg", SourceName: "glibc", SourceVersion: "2.39-0ubuntu8.6"}
	batch := packageBatch(t, pkg)
	manifest := snapshotManifest(t, f.generation, 1, f.now, [][]byte{batch})
	if _, err := f.begin(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.put(t, manifest.GetSnapshotId(), 0, batch, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.ListDevicePackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Msg.Packages) != 1 || page.Msg.Packages[0].SourceName != pkg.SourceName || page.Msg.Packages[0].SourceVersion != pkg.SourceVersion {
		t.Fatalf("source metadata lost: %v", page.Msg)
	}
}

func TestPackageModuleIdentitySurvivesSnapshot(t *testing.T) {
	f := newEnrolled(t, 0)
	modules := []*inventoryv1.ModuleObservation{
		nil,
		{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS},
		{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
		{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED},
		{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT},
		{
			Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Modular: true,
			Name: "nodejs", Stream: "18", Version: "9020020230414112707", Context: "abcd1234",
		},
	}
	packages := make([]*inventoryv1.Package, len(modules))
	for i, module := range modules {
		packages[i] = &inventoryv1.Package{
			Name: "package-" + string(rune('a'+i)), Version: "1.0-1.el9",
			Architecture: "x86_64", Manager: "rpm", Module: module,
		}
	}
	batch := packageBatch(t, packages...)
	manifest := snapshotManifest(t, f.generation, 1, f.now, [][]byte{batch})
	manifest.Backend = "rpm"
	if _, err := f.begin(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.put(t, manifest.GetSnapshotId(), 0, batch, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.ListDevicePackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Msg.Packages) != len(modules) {
		t.Fatalf("package count = %d, want %d", len(page.Msg.Packages), len(modules))
	}
	for i, item := range page.Msg.Packages {
		if !proto.Equal(item.GetModule(), modules[i]) {
			t.Errorf("package %d module = %v, want %v", i, item.GetModule(), modules[i])
		}
	}
}

func TestPackageAptOriginSurvivesSnapshot(t *testing.T) {
	f := newEnrolled(t, 0)
	verified := inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED
	origins := []*inventoryv1.PackageOrigin{
		nil,
		{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS},
		{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
		{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Listings: []*inventoryv1.AptListing{
			{Origin: "Ubuntu", Label: "Ubuntu", Suite: "noble-security", Codename: "noble", Signature: verified, Signer: "F6ECB3762474EDA9D21B7022871920D1991BC93C"},
			{Origin: "linuxmint", Label: "linuxmint", Suite: "zena", Codename: "zena", Signature: verified, Signer: strings.Repeat("A1", 32)},
			{Origin: "Ubuntu", Label: "Ubuntu", Suite: "noble", Codename: "noble", Signature: inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_UNSIGNED},
		}},
	}
	packages := make([]*inventoryv1.Package, len(origins))
	for i, origin := range origins {
		packages[i] = &inventoryv1.Package{
			Name: "package-" + string(rune('a'+i)), Version: "1.0-1ubuntu1", Architecture: "amd64", Manager: "dpkg",
			SourceName: "package", SourceVersion: "1.0-1ubuntu1", Origin: origin,
		}
	}
	batch := packageBatch(t, packages...)
	manifest := snapshotManifest(t, f.generation, 1, f.now, [][]byte{batch})
	manifest.Backend = "dpkg"
	if _, err := f.begin(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.put(t, manifest.GetSnapshotId(), 0, batch, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.ListDevicePackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Msg.Packages) != len(origins) {
		t.Fatalf("package count = %d, want %d", len(page.Msg.Packages), len(origins))
	}
	for i, item := range page.Msg.Packages {
		if !proto.Equal(item.GetOrigin(), origins[i]) {
			t.Errorf("package %d origin = %v, want %v", i, item.GetOrigin(), origins[i])
		}
	}
}

func TestNativeDetailsJSONExpansionReservesDetailEnvelope(t *testing.T) {
	f := newEnrolled(t, 0)
	report := hostObservation(f.generation, 1, "oversized-details")
	report.Observation.Details = nativeDetailsFixture()
	users := &inventoryv1.LocalUsers{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS}
	for range 24 {
		users.Users = append(users.Users, &inventoryv1.LocalUser{Name: "account", Shell: strings.Repeat("\x01", 4096)})
	}
	report.Observation.Details.LocalUsers = users
	if proto.Size(report.Observation) >= core.MaxMessageBytes/2 {
		t.Fatal("fixture must fit binary budget to exercise JSON expansion")
	}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); connect.CodeOf(err) != connect.CodeInvalidArgument || rpcReason(err) != "observation_capacity" {
		t.Fatalf("oversized JSON details admitted: %v", err)
	}
	detail, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if detail.Msg.GetHost() != nil {
		t.Fatal("rejected details changed durable observation")
	}
}
