// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"context"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

// ListApprovedReferences lists the approved home roots or package sources that
// in-scope devices report, so a profile names them by path or repository
// rather than by identifier. Names match an ASCII case-insensitive literal
// prefix and sort by (lowercase name, name, reference ID); each page resumes
// strictly after the previous page's last row.
func (s *Service) ListApprovedReferences(ctx context.Context, req *connect.Request[adminv1.ListApprovedReferencesRequest]) (*connect.Response[adminv1.ListApprovedReferencesResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_argument")
	}
	msg := req.Msg
	unrestricted, scopes, err := core.DeviceScopeFilter(actor, identity.PermissionReadFleet)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	limit := int32(defaultSuggestionPage)
	if size := msg.GetPageSize(); size > 0 {
		limit = int32(min(size, maxSuggestionPage))
	}
	// The exclusive start key is the later of (prefix, "", "") and the cursor.
	prefix := asciiLower(msg.GetPrefix())
	startLower, startName, startReference := prefix, "", ""
	if after := msg.GetAfterName(); after != "" {
		if lower := asciiLower(after); lower >= prefix {
			startLower, startName, startReference = lower, after, msg.GetAfterReferenceId()
		}
	}
	end, bounded := prefixEnd(prefix)
	var rows []devicedb.ListApprovedReferencesRow
	err = s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		var listErr error
		rows, listErr = q.ListApprovedReferences(ctx, devicedb.ListApprovedReferencesParams{
			Kind: int16(msg.GetKind()), StartLower: startLower, StartName: startName, StartReference: startReference,
			Unbounded: !bounded, PrefixEnd: end, ScopeUnrestricted: unrestricted, Scopes: scopes, RowLimit: limit + 1,
		})
		return listErr
	})
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.ListApprovedReferencesResponse{}
	for _, row := range rows[:min(len(rows), int(limit))] {
		response.References = append(response.References, &adminv1.ApprovedReference{
			ReferenceId: row.ReferenceID, Name: row.Name, Format: row.Format, Location: row.Location,
			DeviceCount: uint64(max(row.DeviceCount, 0)),
		})
	}
	if len(rows) > int(limit) {
		last := response.References[limit-1]
		response.NextAfterName, response.NextAfterReferenceId = last.GetName(), last.GetReferenceId()
	}
	return core.NoStore(response), nil
}
