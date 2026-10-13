//go:build integration

package device

import (
	"testing"
	"time"

	"lindm/internal/device/inventory"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func TestDeviceAgentVersionSignedProjectionAndScope(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	reader := scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}})
	ctx := identity.WithPrincipal(f.ctx, reader)
	check := func(release string, protocol uint32, accepted *timestamppb.Timestamp) {
		t.Helper()
		detail, err := f.svc.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
		if err != nil {
			t.Fatal(err)
		}
		page := deviceProjectionPage(t, f.svc, ctx, &adminv1.ListDevicesRequest{Filter: &adminv1.DeviceFilter{AgentRelease: release}})
		if len(page.GetDevices()) != 1 {
			t.Fatalf("release filter: %v", page)
		}
		for _, device := range []*adminv1.Device{detail.Msg.GetDevice(), page.GetDevices()[0]} {
			if device.GetAgentRelease() != release || device.GetAgentProtocolVersion() != protocol || !proto.Equal(device.GetAgentVersionAcceptedAt(), accepted) {
				t.Fatalf("signed version projection: %v", device)
			}
		}
	}
	initial, err := devicedb.New(f.svc.Pool).GetDeviceReleaseReport(f.ctx, f.principal.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	check("", 0, core.ProtoTime(initial.ReportedAt))
	claim := &agentv1.SessionAcquisition{DeploymentId: f.svc.DeploymentID.String(), DeviceId: f.deviceID, EnrollmentGeneration: f.generation, RequestId: uuid.NewString(), PredecessorEpoch: 1, Incarnation: uuid.NewString(), BootId: uuid.NewString(), InstallationId: f.deviceID, AgentRelease: "1.3.7", AgentProtocolVersion: 2}
	sign := func() *devicev1.AcquireSessionRequest {
		t.Helper()
		proof, err := f.svc.Authority.Sign(f.ctx, claim, f.key)
		if err != nil {
			t.Fatal(err)
		}
		return &devicev1.AcquireSessionRequest{AuthorityProof: proof}
	}
	first := sign()
	accepted, err := f.svc.AcquireSession(f.deviceCtx(), connect.NewRequest(first))
	if err != nil {
		t.Fatal(err)
	}
	check("1.3.7", 2, accepted.Msg.GetServerTime())
	f.now = f.now.Add(time.Second)
	claim.RequestId, claim.PredecessorEpoch, claim.AgentRelease = uuid.NewString(), 2, "1.4.0"
	second, err := f.svc.AcquireSession(f.deviceCtx(), connect.NewRequest(sign()))
	if err != nil {
		t.Fatal(err)
	}
	// Retrying a previously accepted acquisition must not roll the projection back.
	if _, err := f.svc.AcquireSession(f.deviceCtx(), connect.NewRequest(first)); err != nil {
		t.Fatal(err)
	}
	check("1.4.0", 2, second.Msg.GetServerTime())
	claim.RequestId, claim.PredecessorEpoch, claim.AgentRelease = uuid.NewString(), 99, "unaccepted"
	if _, err := f.svc.AcquireSession(f.deviceCtx(), connect.NewRequest(sign())); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("future predecessor admitted: %v", err)
	}
	check("1.4.0", 2, second.Msg.GetServerTime())
	page := deviceProjectionPage(t, f.svc, ctx, &adminv1.ListDevicesRequest{Filter: &adminv1.DeviceFilter{AgentRelease: "1.3.7"}})
	if len(page.GetDevices()) != 0 {
		t.Fatal("previous release still matched")
	}
	current := deviceProjectionPage(t, f.svc, ctx, &adminv1.ListDevicesRequest{Filter: &adminv1.DeviceFilter{AgentRelease: "1.4.0"}})
	if _, err := f.svc.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageToken: current.GetPageToken(), Filter: &adminv1.DeviceFilter{AgentRelease: "1.3.7"}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("release filter cursor binding lost: %v", err)
	}
	hidden := identity.WithPrincipal(f.ctx, scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}}))
	if _, err := f.svc.GetDevice(hidden, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("release leaked outside scope: %v", err)
	}
	if got := deviceProjectionPage(t, f.svc, hidden, &adminv1.ListDevicesRequest{Filter: &adminv1.DeviceFilter{AgentRelease: "1.4.0"}}); len(got.GetDevices()) != 0 {
		t.Fatal("release filter bypassed scope")
	}
	// Generation replacement must not borrow the retired generation's report.
	q := devicedb.New(f.svc.Pool)
	next := uuid.New()
	if err := q.InsertEnrollmentGeneration(f.ctx, devicedb.InsertEnrollmentGenerationParams{ID: next, DeviceID: f.principal.DeviceID, CreatedAt: core.Timestamptz(f.now)}); err != nil {
		t.Fatal(err)
	}
	if err := q.SetDeviceGeneration(f.ctx, devicedb.SetDeviceGenerationParams{ID: f.principal.DeviceID, CurrentGenerationID: &next}); err != nil {
		t.Fatal(err)
	}
	check("", 0, nil)
	if got := deviceProjectionPage(t, f.svc, ctx, &adminv1.ListDevicesRequest{Filter: &adminv1.DeviceFilter{AgentRelease: "1.4.0"}}); len(got.GetDevices()) != 0 {
		t.Fatal("retired generation matched release filter")
	}
}

func TestDeviceSessionAndRouteFactsInventoryScope(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	ok := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	missing := inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	report := hostObservation(f.generation, 1, "device-facts")
	details := nativeDetailsFixture()
	report.Observation.Details = details
	details.Sessions.ActiveSessions = &inventoryv1.ActiveSessions{Status: ok, Sessions: []*inventoryv1.ActiveSession{{UserName: observed(ok, "alice"), SessionClass: observed(ok, "user"), SessionType: observed(ok, "tty"), Seat: observed(missing, ""), Remote: &inventoryv1.ObservedBool{Status: ok, Value: true}}}}
	details.Network = &inventoryv1.NetworkDetails{Status: ok, Interfaces: []*inventoryv1.NetworkInterface{{Name: "eth0", Mac: observed(missing, ""), Link: observed(ok, "up"), Addresses: &inventoryv1.ObservedStrings{Status: ok}, DefaultRouteIpv4: &inventoryv1.ObservedBool{Status: ok, Value: true}, DefaultRouteIpv6: &inventoryv1.ObservedBool{Status: missing}}}}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	ctx := identity.WithPrincipal(f.ctx, scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}}))
	read := func() *inventoryv1.NativeDetails {
		t.Helper()
		response, err := f.svc.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
		if err != nil {
			t.Fatal(err)
		}
		return response.Msg.GetHost().GetObservation().GetDetails()
	}
	if !proto.Equal(read(), details) {
		t.Fatal("native session/route facts changed during persistence")
	}
	denied := scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}})
	if _, err := f.svc.GetDevice(identity.WithPrincipal(f.ctx, denied), connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("personal data escaped device scope: %v", err)
	}
	denied.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionReadAudit)}}}
	if _, err := f.svc.GetDevice(identity.WithPrincipal(f.ctx, denied), connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("personal data escaped fleet-read permission: %v", err)
	}
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	report.Sequence = 2
	details.Sessions.ActiveSessions = &inventoryv1.ActiveSessions{Status: missing}
	details.Network.Interfaces[0].DefaultRouteIpv4 = &inventoryv1.ObservedBool{Status: missing}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(read(), details) {
		t.Fatal("failed current observation retained stale personal or route data")
	}
}
