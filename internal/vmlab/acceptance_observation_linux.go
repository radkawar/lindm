// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
)

// AcceptanceObservation keeps local collection and accepted server publication
// distinct. Host and Packages are the installed root collector's raw observation;
// Detail is independently read through the authenticated browser owner's API.
// All contain private machine facts and belong only in protected evidence files.
type AcceptanceObservation struct {
	DeviceID     string                          `json:"device_id"`
	Host         *inventoryv1.HostObservation    `json:"host"`
	Packages     *inventoryv1.PackageObservation `json:"packages"`
	Detail       *adminv1.GetDeviceResponse      `json:"detail"`
	Publication  *vmInventoryEvidence            `json:"publication"`
	NativeBefore *inventoryv1.NativeDetails      `json:"native_before"`
	NativeAfter  *inventoryv1.NativeDetails      `json:"native_after"`
}

// SaveFailureDiagnostics writes the installed units' status, journals, kernel
// and audit records to the caller's private work directory. The returned error
// names that file; guest output never enters public evidence.
func (g *AcceptanceGuest) SaveFailureDiagnostics(ctx context.Context) error {
	if g.vm == nil {
		return nil
	}
	return saveLifecycleFailure(ctx, g.vm, g.diagnostics)
}

// Observe compares every installed package (including duplicate multiplicity)
// and host identity against independent native queries, then waits for the same
// complete snapshot through the real control plane. Native mutation is a failure,
// not permission to mask timers, drop rows, or retry a mutation until it passes.
func (g *AcceptanceGuest) Observe(ctx context.Context, owner *devlab.OwnerSession) (*AcceptanceObservation, error) {
	if g.closed || g.vm == nil || !g.enrolled || owner == nil {
		return nil, errors.New("acceptance observation requires an enrolled live guest and authenticated owner")
	}
	before, err := collectVMTruth(ctx, g.vm, manifestRelease(g.manifest))
	if err != nil {
		return nil, err
	}
	architecture, _, err := inspectArchitecture(g.manifest.Architecture)
	if err != nil {
		return nil, err
	}
	if before.host[0] != g.manifest.Distribution || before.host[1] != g.manifest.Version || before.host[2] != architecture {
		return nil, errors.New("acceptance native OS identity differs from the authenticated image manifest")
	}
	data, err := g.vm.run(ctx, "sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C "+packaging.BinaryPath+" inspect", nil, maxGuestOutput, 3*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("installed native collector: %w", err)
	}
	observation := new(inventoryv1.NativeObservation)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, observation); err != nil {
		return nil, errors.New("installed collector did not return strict NativeObservation protobuf JSON")
	}
	if err := protovalidate.Validate(observation); err != nil {
		return nil, errors.New("installed collector observation violates its protobuf contract")
	}
	result := &AcceptanceObservation{
		DeviceID: g.evidence.DeviceID, Host: observation.Host, Packages: observation.Packages,
		NativeBefore: before.details,
	}
	after, err := collectVMTruth(ctx, g.vm, manifestRelease(g.manifest))
	if err != nil {
		return result, err
	}
	result.NativeAfter = after.details
	if err := stableVMTruth(before, after); err != nil {
		return result, err
	}
	comparisonErr := errors.Join(
		compareVMObservation(before, observation),
		compareVMDetails(before.release(), before.host[2], before.details, after.details, observation.GetHost().GetDetails()),
	)
	control := &vmControlPlane{session: owner}
	publication, err := control.WaitSnapshot(ctx, g.evidence.DeviceID, after, nil, 10*time.Minute)
	if err != nil {
		return result, errors.Join(comparisonErr, err, g.SaveFailureDiagnostics(ctx))
	}
	result.Publication = publication
	detail, err := owner.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: g.evidence.DeviceID}))
	if err != nil {
		return result, errors.Join(comparisonErr, vmControlPlaneError("read accepted acceptance inventory", err))
	}
	result.Detail = detail.Msg
	if detail.Msg.GetCurrentSnapshot().GetSnapshotId() != publication.SnapshotID {
		return result, errors.Join(comparisonErr, errors.New("acceptance publication changed before evidence capture"))
	}
	if err := vmCompareHost(after, detail.Msg.GetHost().GetObservation()); err != nil {
		return result, errors.Join(comparisonErr, err)
	}
	if err := g.observeTopology(ctx); err != nil {
		return result, errors.Join(comparisonErr, err)
	}
	return result, comparisonErr
}
