package orgapply

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
)

func devices(ctx context.Context, client adminv1connect.AdminServiceClient) ([]*adminv1.Device, error) {
	return pages(func(token string) ([]*adminv1.Device, string, error) {
		r, e := client.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 200, PageToken: token}))
		if e != nil {
			return nil, "", e
		}
		return r.Msg.GetDevices(), r.Msg.GetNextPageToken(), nil
	})
}

func (p *ChangePlan) exceptions(ctx context.Context, client adminv1connect.AdminServiceClient) error {
	if len(p.spec.GetAdvisoryExceptions()) == 0 {
		return nil
	}
	fleet, err := devices(ctx, client)
	if err != nil {
		return fmt.Errorf("list exception devices: %w", err)
	}
	byHostname := make(map[string][]*adminv1.Device, len(fleet))
	for _, d := range fleet {
		byHostname[d.GetHostname()] = append(byHostname[d.GetHostname()], d)
	}
	// A real device lists tens of thousands of findings. Scan every page but
	// retain only declared identities, so the catalog cap bounds matches.
	declared := make(map[string]bool, len(p.spec.GetAdvisoryExceptions()))
	for _, e := range p.spec.GetAdvisoryExceptions() {
		declared[findingKey(e.GetHostname(), e.GetAdvisoryId(), e.GetPackageName())] = true
	}
	findings := make(map[string][]*adminv1.AdvisoryFinding)
	for _, e := range p.spec.GetAdvisoryExceptions() {
		name := e.GetHostname() + "/" + e.GetAdvisoryId() + "/" + e.GetPackageName()
		candidates := byHostname[e.GetHostname()]
		if len(candidates) != 1 {
			detail := "device not found"
			if len(candidates) > 1 {
				detail = "ambiguous device hostname"
			}
			p.add("advisory_exception", name, "", "pending", detail, nil)
			continue
		}
		deviceID := candidates[0].GetId()
		items, ok := findings[deviceID]
		if !ok {
			hostname, scanned := e.GetHostname(), 0
			items, err = pages(func(token string) ([]*adminv1.AdvisoryFinding, string, error) {
				if scanned++; scanned > maxFindingPages {
					return nil, "", errors.New("orgapply: device findings exceed the scan bound")
				}
				r, e := client.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: deviceID, PageSize: 200, PageToken: token}))
				if e != nil {
					return nil, "", e
				}
				var matches []*adminv1.AdvisoryFinding
				for _, f := range r.Msg.GetFindings() {
					if declared[findingKey(hostname, f.GetAdvisoryId(), f.GetPackageName())] {
						matches = append(matches, f)
					}
				}
				return matches, r.Msg.GetNextPageToken(), nil
			})
			if err != nil {
				return fmt.Errorf("list exception findings: %w", err)
			}
			findings[deviceID] = items
		}
		var match *adminv1.AdvisoryFinding
		count := 0
		for _, f := range items {
			if f.GetAdvisoryId() == e.GetAdvisoryId() && f.GetPackageName() == e.GetPackageName() {
				match = f
				count++
			}
		}
		if count != 1 {
			detail := "finding not found"
			if count > 1 {
				detail = "ambiguous finding identity"
			}
			p.add("advisory_exception", name, "", "pending", detail, nil)
			continue
		}
		// Compare the database's canonical microsecond expiry, not an arbitrary
		// tolerance. The original desired payload remains exact for approval.
		expires := e.GetRequest().GetExpiresAt().AsTime().Truncate(time.Microsecond)
		if match.GetException() != nil && match.GetException().GetReason() == e.GetRequest().GetReason() && match.GetException().GetExpiresAt().AsTime().Equal(expires) {
			p.add("advisory_exception", name, match.GetId(), "unchanged", "", nil)
			continue
		}
		if match.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED && match.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED {
			p.add("advisory_exception", name, match.GetId(), "pending", "finding is not currently affected", nil)
			continue
		}
		request := proto.CloneOf(e.GetRequest())
		request.DeviceId = deviceID
		request.FindingId = match.GetId()
		if e.GetProposeApproval() {
			p.add("advisory_exception", name, match.GetId(), "pending", "independent approval required; review and accept in the approval inbox", &adminv1.CreateApprovalRequest{
				LifetimeSeconds: 3600,
				Payload:         &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request},
			})
			continue
		}
		status := "created"
		if match.GetException() != nil {
			status = "updated"
		}
		p.add("advisory_exception", name, match.GetId(), status, "", request)
	}
	return nil
}

// maxFindingPages bounds one device's scan at 1,000,000 findings of 200 per
// page: ten findings for each of the 100,000 packages an inventory may report.
const maxFindingPages = 5000

func findingKey(hostname, advisoryID, packageName string) string {
	return hostname + "\x00" + advisoryID + "\x00" + packageName
}
