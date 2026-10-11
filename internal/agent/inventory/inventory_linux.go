//go:build linux

// Package inventory collects bounded local Linux evidence. It does not enroll a
// device, assert compliance, or establish a distribution's lifecycle qualification.
package inventory

import (
	"context"
	"fmt"
	"os"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/platform"
)

// Collect returns actual host and native-package evidence. Collection failures
// are represented by typed statuses; a failed package attempt never has rows.
// An error indicates that the resulting evidence could not be validated.
func Collect(ctx context.Context) (*inventoryv1.NativeObservation, error) {
	return collect(ctx, false)
}

// CollectForUpload leaves storage, hardware serial and firmware unavailable for
// replacement by the executor's bounded read-only observation. Public CPU facts
// are collected locally, then replaced by the executor's complete CPU observation
// (including ARM SMBIOS model evidence). The network process never attempts these
// privileged probes; Collect retains the standalone caller's own privileges.
func CollectForUpload(ctx context.Context) (*inventoryv1.NativeObservation, error) {
	return collect(ctx, true)
}

func collect(ctx context.Context, rootObservation bool) (*inventoryv1.NativeObservation, error) {
	host, release := collectHost(ctx, readHostFile, rootObservation)
	host.Details = collectDetails(ctx, detailSources{
		readFile: readDetailFile, readDir: readDetailDir, stat: os.Stat,
		run: runNative, sessions: collectSessions, openBlock: openStorageBlock, nvmeScope: actionprovider.ReadNVMeSanitizeScope,
		snap: collectSnap, rootObservation: rootObservation,
	})
	host.FinishedAt = timestamppb.Now()
	if err := boundHostDetails(host); err != nil {
		return nil, fmt.Errorf("bound host observation: %w", err)
	}
	if !nativePackageIdentityAvailable(host) {
		release = nil
	}
	result := &inventoryv1.NativeObservation{
		Host:     host,
		Packages: collectPackages(ctx, release, os.Stat, runNative),
	}
	if err := protovalidate.Validate(result); err != nil {
		return nil, fmt.Errorf("validate native observation: %w", err)
	}
	return result, nil
}

// nativePackageIdentityAvailable requires an observed VERSION_ID unless the
// release is a rolling registry row that has none.
func nativePackageIdentityAvailable(host *inventoryv1.HostObservation) bool {
	return host.OsId.Status == success && (host.OsVersion.Status == success ||
		host.OsVersion.Status == unavailable && platform.Identify(platform.OSRelease{ID: host.OsId.Value}).Version.Rule == platform.VersionAbsent)
}

func boundHostDetails(host *inventoryv1.HostObservation) error {
	data, err := (protojson.MarshalOptions{Multiline: true}).Marshal(host)
	if err != nil {
		return err
	}
	if proto.Size(host) <= 512<<10 && len(data) <= 512<<10 {
		return nil
	}
	details := host.Details
	if details.Storage.Status == success {
		details.Storage = &inventoryv1.StorageDetails{Status: capacity}
	}
	if details.Network.Status == success {
		details.Network = &inventoryv1.NetworkDetails{Status: capacity}
	}
	if details.Power.Batteries.Status == success {
		details.Power.Batteries = &inventoryv1.BatteryDetails{Status: capacity}
	}
	if details.LocalUsers.Status == success {
		details.LocalUsers = &inventoryv1.LocalUsers{Status: capacity}
	}
	if details.Flatpak.Status == success {
		details.Flatpak = &inventoryv1.ApplicationDetails{Status: capacity}
	}
	if details.Snap.Status == success {
		details.Snap = &inventoryv1.ApplicationDetails{Status: capacity}
	}
	if details.Platform != nil && details.Platform.Repositories.Status == success {
		details.Platform.Repositories = &inventoryv1.RepositoryObservation{Status: capacity}
	}
	return nil
}
