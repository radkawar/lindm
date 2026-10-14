// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/devlab"
)

// vmControlPlane is a sequential laboratory client, not an authentication or
// inventory implementation. All authority and observations use the public API.
type vmControlPlane struct {
	session      *devlab.OwnerSession
	approver     *devlab.ApprovalSession
	openOwner    func(context.Context) (*devlab.OwnerSession, error)
	openApprover func(context.Context) (*devlab.ApprovalSession, error)
	fixture      *devlab.AgentFixture
	grants       []*vmCreatedGrant
	devices      map[string]*vmTrackedDevice
	closed       bool
}

type vmCreatedGrant struct {
	request *adminv1.CreateEnrollmentGrantRequest
	id      string
	revoked bool
}

type vmTrackedDevice struct {
	request  *adminv1.RevokeDeviceRequest
	approval *adminv1.Approval
	revoked  bool
}

// vmBootstrapMaterial must only be transferred through private SSH stdin. Clear
// GrantSecret after transfer; never include this structure in diagnostics.
type vmBootstrapMaterial struct {
	ExecutionRootJSON []byte
	BootstrapEnvelope []byte
	GrantSecret       []byte
	GrantID           string
	ExpiresAt         time.Time
}

// vmInventoryEvidence keeps device collection clocks distinct from server
// receipt clocks. None of these fields imply live presence or compliance.
type vmInventoryEvidence struct {
	DeviceID             string
	EnrollmentGeneration string
	HostSequence         uint64
	AttemptSequence      uint64
	SnapshotSequence     uint64
	SnapshotID           string
	PackageCount         uint32
	Status               inventoryv1.CollectionStatus
	HostStartedAt        time.Time
	HostFinishedAt       time.Time
	HostReceivedAt       time.Time
	AttemptStartedAt     time.Time
	AttemptFinishedAt    time.Time
	AttemptReceivedAt    time.Time
	SnapshotCreatedAt    time.Time
	SnapshotStartedAt    time.Time
	SnapshotFinishedAt   time.Time
	SnapshotReceivedAt   time.Time
	SnapshotCommittedAt  time.Time
	FirstPageToken       string
	CursorExpiresAt      time.Time
	packages             map[nativePackage]int
}

type vmPackageSnapshot struct {
	SnapshotID      string
	Sequence        uint64
	PackageCount    uint32
	FirstPageToken  string
	CursorExpiresAt time.Time
	packages        map[nativePackage]int
}

func openVMControlPlane(ctx context.Context, repoRoot string, isolated *devlab.AuthorityFixture) (*vmControlPlane, error) {
	var fixture *devlab.AgentFixture
	var err error
	if isolated == nil {
		fixture, err = devlab.ReadAgentFixture(ctx, repoRoot)
	} else {
		fixture, err = isolated.ReadAgentFixture(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("read control-plane-bound agent fixture: %w", err)
	}
	openOwner := func(ctx context.Context) (*devlab.OwnerSession, error) {
		if isolated == nil {
			return devlab.OpenOwnerSession(ctx, repoRoot)
		}
		return isolated.OpenOwnerSession(ctx)
	}
	session, err := openOwner(ctx)
	if err != nil {
		return nil, err
	}
	// The independent human is unused until cleanup. Authenticating here would
	// consume its idle-session lifetime during long native scenarios.
	return &vmControlPlane{
		session: session, openOwner: openOwner, fixture: fixture, devices: make(map[string]*vmTrackedDevice),
		openApprover: func(ctx context.Context) (*devlab.ApprovalSession, error) {
			return devlab.OpenApprovalSession(ctx, repoRoot, isolated)
		},
	}, nil
}

func (c *vmControlPlane) BootstrapMaterial(ctx context.Context) (*vmBootstrapMaterial, error) {
	if c.closed {
		return nil, errors.New("laboratory control plane is closed")
	}
	grant := &vmCreatedGrant{request: &adminv1.CreateEnrollmentGrantRequest{RequestId: uuid.NewString(), LifetimeSeconds: 900, Reason: "native VM lifecycle laboratory provisioning"}}
	// Preserve the request before sending. Cleanup can recover the grant ID by
	// replaying this same idempotent request if its first response is lost.
	c.grants = append(c.grants, grant)
	response, err := c.session.Admin.CreateEnrollmentGrant(ctx, connect.NewRequest(grant.request))
	if err != nil {
		return nil, vmControlPlaneError("create enrollment grant", err)
	}
	message := response.Msg
	grant.id = message.GetGrantId()
	secret := message.GetSecret()
	message.Secret = ""
	if !vmValidID(grant.id) || message.GetSecretDeliveryUnknown() || len(secret) < 32 || len(secret) > 256 || !vmValidTime(message.GetExpiresAt()) || !message.GetExpiresAt().AsTime().After(time.Now()) {
		return nil, errors.New("enrollment grant response did not deliver usable authority")
	}
	return &vmBootstrapMaterial{ExecutionRootJSON: c.fixture.ExecutionRootJSON, BootstrapEnvelope: c.fixture.BootstrapEnvelope, GrantSecret: []byte(secret), GrantID: grant.id, ExpiresAt: message.GetExpiresAt().AsTime()}, nil
}

// TrackDevice accepts only the ID validated in this lab's guest issuance
// evidence or protected status, before any operation can activate the device.
// It never discovers and revokes arbitrary preexisting fleet members.
func (c *vmControlPlane) TrackDevice(deviceID string) error {
	if c.closed || !vmValidID(deviceID) {
		return errors.New("invalid laboratory device registration")
	}
	if _, tracked := c.devices[deviceID]; !tracked {
		c.devices[deviceID] = &vmTrackedDevice{request: &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: deviceID, Reason: "native VM lifecycle laboratory device revocation"}}
	}
	return nil
}

func (c *vmControlPlane) GetDevice(ctx context.Context, deviceID string) (*adminv1.GetDeviceResponse, error) {
	if c.closed || !vmValidID(deviceID) {
		return nil, errors.New("invalid laboratory device query")
	}
	response, err := c.session.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: deviceID}))
	if err != nil {
		return nil, vmControlPlaneError("get device", err)
	}
	if response.Msg.GetDevice().GetId() != deviceID {
		return nil, errors.New("device response does not bind the requested device")
	}
	return response.Msg, nil
}

// ReadSnapshot traverses the complete, unfiltered multiset under one immutable
// cursor. A saved FirstPageToken can reread an older retained snapshot after a
// new publication; the token must belong to the same owner session and device.
func (c *vmControlPlane) ReadSnapshot(ctx context.Context, deviceID, cursor string) (*vmPackageSnapshot, error) {
	if c.closed || !vmValidID(deviceID) {
		return nil, errors.New("invalid laboratory snapshot query")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	result := &vmPackageSnapshot{packages: make(map[nativePackage]int)}
	seen := make(map[string]bool)
	for page := 0; page <= 100000; page++ {
		response, err := c.session.Admin.ListDevicePackages(ctx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: deviceID, PageSize: 200, PageToken: cursor}))
		if err != nil {
			return nil, vmControlPlaneError("list device packages", err)
		}
		message := response.Msg
		if !vmValidID(message.GetSnapshotId()) || message.GetSequence() == 0 || message.GetPageToken() == "" || !vmValidTime(message.GetCursorExpiresAt()) || (cursor != "" && message.GetPageToken() != cursor) {
			return nil, errors.New("invalid immutable package cursor response")
		}
		if page == 0 {
			result.SnapshotID, result.Sequence = message.GetSnapshotId(), message.GetSequence()
			result.FirstPageToken, result.CursorExpiresAt = message.GetPageToken(), message.GetCursorExpiresAt().AsTime()
		} else if message.GetSnapshotId() != result.SnapshotID || message.GetSequence() != result.Sequence || !message.GetCursorExpiresAt().AsTime().Equal(result.CursorExpiresAt) {
			return nil, errors.New("package pagination changed snapshot, sequence or fixed expiry")
		}
		if seen[message.GetPageToken()] || len(message.GetPackages()) > 200 {
			return nil, errors.New("package pagination repeated a cursor or exceeded page size")
		}
		seen[message.GetPageToken()] = true
		for _, pkg := range message.GetPackages() {
			if pkg == nil || pkg.GetPosition() != result.PackageCount || pkg.GetName() == "" || pkg.GetVersion() == "" || pkg.GetManager() == "" || result.PackageCount >= 100000 {
				return nil, errors.New("package pagination has incomplete positions or invalid records")
			}
			result.packages[nativePackage{name: pkg.GetName(), version: pkg.GetVersion(), architecture: pkg.GetArchitecture(), manager: pkg.GetManager(), sourceName: pkg.GetSourceName(), sourceVersion: pkg.GetSourceVersion(), module: nativeModuleIdentity(pkg.GetModule())}]++
			result.PackageCount++
		}
		cursor = message.GetNextPageToken()
		if cursor == "" {
			return result, nil
		}
		if len(message.GetPackages()) == 0 {
			return nil, errors.New("package pagination made no progress")
		}
	}
	return nil, errors.New("package pagination exceeded complete inventory bound")
}

// WaitSnapshot requires a publication newer than previous, then compares every
// native row (including epochs and duplicate multiplicity) and host boot.
// While previous is current, its comparison cursor can be refreshed; once
// superseded, that cursor and its expiry remain fixed. No collection is triggered.
func (c *vmControlPlane) WaitSnapshot(ctx context.Context, deviceID string, truth *vmTruth, previous *vmInventoryEvidence, timeout time.Duration) (*vmInventoryEvidence, error) {
	if truth == nil || len(truth.packages) == 0 {
		return nil, errors.New("native truth is required for the control-plane oracle")
	}
	var afterSequence uint64
	if previous != nil {
		if previous.DeviceID != deviceID {
			return nil, errors.New("previous inventory belongs to a different device")
		}
		afterSequence = previous.SnapshotSequence
	}
	return c.waitInventory(ctx, deviceID, timeout, func(ctx context.Context, detail *adminv1.GetDeviceResponse) (*vmInventoryEvidence, error) {
		if previous != nil && detail.GetCurrentSnapshot().GetSnapshotId() == previous.SnapshotID && time.Until(previous.CursorExpiresAt) < 5*time.Minute {
			if err := c.refreshComparisonCursor(ctx, deviceID, previous); err != nil {
				return nil, err
			}
		}
		evidence, err := vmCanonicalEvidence(detail)
		if err != nil {
			return nil, err
		}
		if evidence.SnapshotSequence <= afterSequence || evidence.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || evidence.AttemptSequence != evidence.SnapshotSequence || detail.GetPackageAttempt().GetSnapshotId() != evidence.SnapshotID {
			return nil, errors.New("new successful package publication has not arrived")
		}
		if detail.GetPackageAttempt().GetBackend() != truth.manager || detail.GetCurrentSnapshot().GetBackend() != truth.manager {
			return nil, errors.New("published package backend differs from native truth")
		}
		if err := vmCompareHost(truth, detail.GetHost().GetObservation()); err != nil {
			return nil, err
		}
		packages, err := c.ReadSnapshot(ctx, deviceID, "")
		if err != nil {
			return nil, err
		}
		if packages.SnapshotID != evidence.SnapshotID || packages.Sequence != evidence.SnapshotSequence || packages.PackageCount != evidence.PackageCount {
			return nil, errors.New("snapshot changed between canonical detail and package cursor")
		}
		if !sameVMPackages(truth.packages, packages.packages) {
			return nil, errors.New("complete published package multiset differs from native truth")
		}
		evidence.FirstPageToken, evidence.CursorExpiresAt, evidence.packages = packages.FirstPageToken, packages.CursorExpiresAt, packages.packages
		return evidence, nil
	})
}

func (c *vmControlPlane) refreshComparisonCursor(ctx context.Context, deviceID string, previous *vmInventoryEvidence) error {
	response, err := c.session.Admin.ListDevicePackages(ctx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: deviceID, PageSize: 1}))
	if err != nil {
		return vmControlPlaneError("refresh baseline snapshot cursor", err)
	}
	page := response.Msg
	// Publication may race the head read. Never repin the baseline to it.
	if page.GetSnapshotId() != previous.SnapshotID {
		return nil
	}
	if page.GetSequence() != previous.SnapshotSequence || page.GetPageToken() == "" || !vmValidTime(page.GetCursorExpiresAt()) {
		return errors.New("invalid baseline snapshot cursor")
	}
	previous.FirstPageToken = page.GetPageToken()
	previous.CursorExpiresAt = page.GetCursorExpiresAt().AsTime()
	return nil
}

// WaitFailedAttempt proves a new canonical failure did not replace the last
// successful snapshot or its retained rows. A host-only update is not a failure.
func (c *vmControlPlane) WaitFailedAttempt(ctx context.Context, deviceID string, before *vmInventoryEvidence, status inventoryv1.CollectionStatus, timeout time.Duration) (*vmInventoryEvidence, error) {
	if before == nil || before.DeviceID != deviceID || before.SnapshotID == "" || before.packages == nil || status < inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE || status > inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE {
		return nil, errors.New("a published baseline and explicit failure status are required")
	}
	return c.waitInventory(ctx, deviceID, timeout, func(ctx context.Context, detail *adminv1.GetDeviceResponse) (*vmInventoryEvidence, error) {
		evidence, err := vmCanonicalEvidence(detail)
		if err != nil {
			return nil, err
		}
		if evidence.AttemptSequence <= before.AttemptSequence {
			return nil, errors.New("expected later failed package attempt has not arrived")
		}
		if evidence.Status != status {
			// The public enum identifies a different native failure than the
			// lane induced; the deadline reports it instead of "not arrived".
			return nil, fmt.Errorf("later package attempt %d reported %s, want %s", evidence.AttemptSequence, evidence.Status, status)
		}
		if evidence.EnrollmentGeneration != before.EnrollmentGeneration || evidence.HostSequence < before.HostSequence || evidence.SnapshotID != before.SnapshotID || evidence.SnapshotSequence != before.SnapshotSequence || evidence.PackageCount != before.PackageCount || !evidence.SnapshotReceivedAt.Equal(before.SnapshotReceivedAt) || !evidence.SnapshotCommittedAt.Equal(before.SnapshotCommittedAt) || evidence.AttemptReceivedAt.Before(before.AttemptReceivedAt) || detail.GetPackageAttempt().GetSnapshotId() != "" {
			return nil, errors.New("failed attempt did not preserve the previous successful snapshot")
		}
		if !evidence.SnapshotCreatedAt.Equal(before.SnapshotCreatedAt) || !evidence.SnapshotStartedAt.Equal(before.SnapshotStartedAt) || !evidence.SnapshotFinishedAt.Equal(before.SnapshotFinishedAt) {
			return nil, errors.New("failed attempt changed the last successful collection timestamps")
		}
		packages, err := c.ReadSnapshot(ctx, deviceID, "")
		if err != nil {
			return nil, err
		}
		if packages.SnapshotID != before.SnapshotID || packages.Sequence != before.SnapshotSequence || packages.PackageCount != before.PackageCount || !sameVMPackages(before.packages, packages.packages) {
			return nil, errors.New("failed attempt changed the retained successful package multiset")
		}
		evidence.FirstPageToken, evidence.CursorExpiresAt, evidence.packages = packages.FirstPageToken, packages.CursorExpiresAt, packages.packages
		return evidence, nil
	})
}

func (c *vmControlPlane) waitInventory(ctx context.Context, deviceID string, timeout time.Duration, inspect func(context.Context, *adminv1.GetDeviceResponse) (*vmInventoryEvidence, error)) (*vmInventoryEvidence, error) {
	if timeout <= 0 || timeout > 30*time.Minute {
		return nil, errors.New("inventory polling requires a positive timeout of at most 30 minutes")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last error
	for {
		detail, err := c.GetDevice(ctx, deviceID)
		if err == nil {
			var evidence *vmInventoryEvidence
			evidence, err = inspect(ctx, detail)
			if err == nil {
				return evidence, nil
			}
		}
		// A call cut off by this wait's own deadline says nothing about the
		// device; keep the last observed mismatch as the failure diagnosis.
		if last == nil || ctx.Err() == nil {
			last = err
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(errors.New("bounded control-plane inventory wait ended"), ctx.Err(), last)
		case <-ticker.C:
		}
	}
}

func vmCanonicalEvidence(detail *adminv1.GetDeviceResponse) (*vmInventoryEvidence, error) {
	device, host, attempt, snapshot := detail.GetDevice(), detail.GetHost(), detail.GetPackageAttempt(), detail.GetCurrentSnapshot()
	observation := host.GetObservation()
	if device == nil || host == nil || attempt == nil || snapshot == nil || observation == nil || !vmValidID(device.GetId()) || !vmValidID(device.GetEnrollmentGeneration()) || !vmValidID(snapshot.GetSnapshotId()) || device.GetLifecycleState() != adminv1.DeviceState_DEVICE_STATE_ACTIVE || host.GetSequence() == 0 || attempt.GetSequence() == 0 || snapshot.GetSequence() == 0 || device.GetHostSequence() != host.GetSequence() || device.GetPackageSequence() < attempt.GetSequence() || device.GetPublishedSnapshotSequence() != snapshot.GetSequence() || attempt.GetSequence() < snapshot.GetSequence() || snapshot.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_COMMITTED || !snapshot.GetPackagesAvailable() || snapshot.GetSupersededAt() != nil {
		return nil, errors.New("canonical device detail does not describe a coherent active publication")
	}
	if attempt.GetStatus() < inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || attempt.GetStatus() > inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE {
		return nil, errors.New("canonical package attempt has an unknown status")
	}
	for _, timestamp := range []*timestamppb.Timestamp{device.GetEnrolledAt(), device.GetLastSeenAt(), device.GetHostReceivedAt(), device.GetPackageAttemptReceivedAt(), device.GetSnapshotReceivedAt(), host.GetReceivedAt(), observation.GetStartedAt(), observation.GetFinishedAt(), attempt.GetStartedAt(), attempt.GetFinishedAt(), attempt.GetReceivedAt(), snapshot.GetCreatedAt(), snapshot.GetStartedAt(), snapshot.GetFinishedAt(), snapshot.GetReceivedAt(), snapshot.GetCommittedAt()} {
		if !vmValidTime(timestamp) {
			return nil, errors.New("canonical inventory omitted a valid collection or receipt timestamp")
		}
	}
	if observation.GetFinishedAt().AsTime().Before(observation.GetStartedAt().AsTime()) || attempt.GetFinishedAt().AsTime().Before(attempt.GetStartedAt().AsTime()) || snapshot.GetFinishedAt().AsTime().Before(snapshot.GetStartedAt().AsTime()) || snapshot.GetCommittedAt().AsTime().Before(snapshot.GetReceivedAt().AsTime()) || !device.GetHostReceivedAt().AsTime().Equal(host.GetReceivedAt().AsTime()) || !device.GetPackageAttemptReceivedAt().AsTime().Equal(attempt.GetReceivedAt().AsTime()) || !device.GetSnapshotReceivedAt().AsTime().Equal(snapshot.GetReceivedAt().AsTime()) {
		return nil, errors.New("canonical collection and server receipt metadata are inconsistent")
	}
	// Deliberately do not order a device collection time against a server time:
	// their clocks are independent, even when the lab normally synchronizes them.
	if attempt.GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		if attempt.GetSequence() != snapshot.GetSequence() || attempt.GetSnapshotId() != snapshot.GetSnapshotId() || attempt.GetBackend() != snapshot.GetBackend() || !attempt.GetStartedAt().AsTime().Equal(snapshot.GetStartedAt().AsTime()) || !attempt.GetFinishedAt().AsTime().Equal(snapshot.GetFinishedAt().AsTime()) || !attempt.GetReceivedAt().AsTime().Equal(snapshot.GetReceivedAt().AsTime()) {
			return nil, errors.New("successful attempt does not bind the published snapshot metadata")
		}
	} else if attempt.GetSequence() <= snapshot.GetSequence() || attempt.GetSnapshotId() != "" {
		return nil, errors.New("failed attempt incorrectly binds or replaces the successful snapshot")
	}
	for _, field := range []*inventoryv1.ObservedString{observation.GetOsId(), observation.GetOsVersion(), observation.GetArchitecture(), observation.GetKernelRelease(), observation.GetHostname(), observation.GetBootId(), observation.GetHardwareVendor(), observation.GetHardwareModel(), observation.GetHardwareSerial()} {
		if field == nil || field.GetStatus() < inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || field.GetStatus() > inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE || (field.GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS) != (field.GetValue() != "") {
			return nil, errors.New("canonical host field has an invalid observation status or value")
		}
	}
	for _, field := range []struct {
		observed *inventoryv1.ObservedString
		summary  string
	}{{observation.GetOsId(), device.GetOsId()}, {observation.GetOsVersion(), device.GetOsVersion()}, {observation.GetArchitecture(), device.GetArchitecture()}, {observation.GetHostname(), device.GetHostname()}} {
		if field.observed.GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS && field.observed.GetValue() != field.summary {
			return nil, errors.New("canonical successful host field differs from device summary")
		}
	}
	return &vmInventoryEvidence{
		DeviceID: device.GetId(), EnrollmentGeneration: device.GetEnrollmentGeneration(),
		HostSequence: host.GetSequence(), AttemptSequence: attempt.GetSequence(),
		SnapshotSequence: snapshot.GetSequence(), SnapshotID: snapshot.GetSnapshotId(),
		PackageCount: snapshot.GetPackageCount(), Status: attempt.GetStatus(),
		HostStartedAt: observation.GetStartedAt().AsTime(), HostFinishedAt: observation.GetFinishedAt().AsTime(),
		HostReceivedAt:   host.GetReceivedAt().AsTime(),
		AttemptStartedAt: attempt.GetStartedAt().AsTime(), AttemptFinishedAt: attempt.GetFinishedAt().AsTime(),
		AttemptReceivedAt: attempt.GetReceivedAt().AsTime(),
		SnapshotCreatedAt: snapshot.GetCreatedAt().AsTime(),
		SnapshotStartedAt: snapshot.GetStartedAt().AsTime(), SnapshotFinishedAt: snapshot.GetFinishedAt().AsTime(),
		SnapshotReceivedAt: snapshot.GetReceivedAt().AsTime(), SnapshotCommittedAt: snapshot.GetCommittedAt().AsTime(),
	}, nil
}

func vmCompareHost(truth *vmTruth, host *inventoryv1.HostObservation) error {
	names := [6]string{"os_id", "os_version", "architecture", "kernel_release", "hostname", "boot_id"}
	for i, field := range vmHostFields(host) {
		if !vmHostFieldMatches(truth, i, field) {
			return fmt.Errorf("published successful host fields or boot ID differ from native truth (%s)", names[i])
		}
	}
	return nil
}

func (c *vmControlPlane) RevokeDevice(ctx context.Context, deviceID string) error {
	device, tracked := c.devices[deviceID]
	if c.closed || !tracked {
		return errors.New("refusing to revoke a device not tracked by this laboratory run")
	}
	if device.revoked {
		return nil
	}
	if device.request.GetApprovalId() == "" {
		if c.approver == nil {
			approver, err := c.openApprover(ctx)
			if err != nil {
				return vmControlPlaneError("authenticate laboratory device revocation approver", err)
			}
			c.approver = approver
		}
		approval, err := c.approver.Approve(ctx, c.session, &adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RevokeDevice{RevokeDevice: device.request}})
		if err != nil {
			return vmControlPlaneError("approve laboratory device revocation", err)
		}
		device.approval = approval
		device.request.ApprovalId = approval.GetId()
	}
	_, err := c.session.Admin.RevokeDevice(ctx, connect.NewRequest(device.request))
	if err != nil {
		return vmControlPlaneError("revoke laboratory device", err)
	}
	device.revoked = true
	return nil
}

// RevokeGrant revokes only authority created by this run. The server also
// revokes a pending device bound to the grant, but not an already-active device.
// Active devices require explicit tracking and revocation; records remain.
func (c *vmControlPlane) RevokeGrant(ctx context.Context, grantID string) error {
	if c.closed || !vmValidID(grantID) {
		return errors.New("invalid laboratory grant revocation")
	}
	for _, grant := range c.grants {
		if grant.id != grantID {
			continue
		}
		if grant.revoked {
			return nil
		}
		_, err := c.session.Admin.RevokeEnrollmentGrant(ctx, connect.NewRequest(&adminv1.RevokeEnrollmentGrantRequest{RequestId: uuid.NewString(), GrantId: grantID, Reason: "native VM lifecycle laboratory authority cleanup"}))
		if err != nil {
			return vmControlPlaneError("revoke laboratory enrollment grant", err)
		}
		grant.revoked = true
		return nil
	}
	return errors.New("refusing to revoke a grant not created by this laboratory run")
}

// refreshOwner completes a real login before cleanup after a long native wait.
// It cannot switch the run's actor or relax session/approval security lifetimes.
func (c *vmControlPlane) refreshOwner(ctx context.Context) error {
	fresh, err := c.openOwner(ctx)
	if err != nil {
		return vmControlPlaneError("authenticate laboratory cleanup owner", err)
	}
	if fresh.AccountID == "" || fresh.AccountID != c.session.AccountID {
		return errors.Join(errors.New("laboratory cleanup owner identity changed"), fresh.Close(ctx))
	}
	previous := c.session
	c.session = fresh
	// Close already distinguishes expired/revoked sessions (HTTP 401) from
	// logout failures. The new session, not the old cookie, authorizes cleanup.
	return previous.Close(ctx)
}

// Close revokes grants (including their pending bound devices) and explicitly
// tracked devices, then the real SSO session. Server records remain for audit.
// Cleanup is detached from a canceled scenario and each phase is bounded.
func (c *vmControlPlane) Close(ctx context.Context) error {
	if c == nil || c.closed {
		return nil
	}
	base := context.WithoutCancel(ctx)
	authenticate, cancelAuthenticate := context.WithTimeout(base, 45*time.Second)
	result := c.refreshOwner(authenticate)
	cancelAuthenticate()
	cleanup, cancel := context.WithTimeout(base, 45*time.Second)
	for _, grant := range c.grants {
		if grant.revoked {
			continue
		}
		if grant.id == "" {
			response, err := c.session.Admin.CreateEnrollmentGrant(cleanup, connect.NewRequest(grant.request))
			if err != nil {
				result = errors.Join(result, vmControlPlaneError("recover laboratory grant for revocation", err))
				continue
			}
			grant.id = response.Msg.GetGrantId()
			response.Msg.Secret = ""
		}
		result = errors.Join(result, c.RevokeGrant(cleanup, grant.id))
	}
	for deviceID := range c.devices {
		result = errors.Join(result, c.RevokeDevice(cleanup, deviceID))
	}
	cancel()
	logout, cancelLogout := context.WithTimeout(base, 15*time.Second)
	defer cancelLogout()
	result = errors.Join(result, c.session.Close(logout))
	result = errors.Join(result, c.approver.Close(base))
	c.closed = true
	return result
}

func vmControlPlaneError(operation string, err error) error {
	// A successful call stays successful: callers return this unconditionally
	// (setDevicePolicy reported every successful update as "unknown",
	// layers-fedora44-tier3-05).
	if err == nil {
		return nil
	}
	// Do not propagate server-controlled messages or request/response bodies.
	return connect.NewError(connect.CodeOf(err), errors.New(operation+" failed"))
}

func vmValidID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func vmValidTime(value *timestamppb.Timestamp) bool {
	return value != nil && value.CheckValid() == nil
}
