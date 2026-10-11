package orgapply

import (
	"context"
	"fmt"

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
			items, err = pages(func(token string) ([]*adminv1.AdvisoryFinding, string, error) {
				r, e := client.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: deviceID, PageSize: 200, PageToken: token}))
				if e != nil {
					return nil, "", e
				}
				return r.Msg.GetFindings(), r.Msg.GetNextPageToken(), nil
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
		if match.GetException() != nil && match.GetException().GetReason() == e.GetRequest().GetReason() && proto.Equal(match.GetException().GetExpiresAt(), e.GetRequest().GetExpiresAt()) {
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
		status := "created"
		if match.GetException() != nil {
			status = "updated"
		}
		p.add("advisory_exception", name, match.GetId(), status, "", request)
	}
	return nil
}
