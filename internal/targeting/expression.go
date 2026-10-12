package targeting

import (
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/targeting/targetingdb"
)

const (
	included = policyv1.TargetMatch_TARGET_MATCH_INCLUDED
	excluded = policyv1.TargetMatch_TARGET_MATCH_EXCLUDED
	unknown  = policyv1.TargetMatch_TARGET_MATCH_UNKNOWN
)

// Edge ordering and rank are semantic graph invariants; scalar/count bounds live
// in protobuf. A rank decreases on every edge, bounding evaluation depth to eight.
func validateExpression(e *adminv1.TargetExpression) error {
	for i, n := range e.Nodes {
		var children []uint32
		switch v := n.Node.(type) {
		case *adminv1.TargetNode_All:
			children = v.All.Indices
		case *adminv1.TargetNode_Any:
			children = v.Any.Indices
		case *adminv1.TargetNode_NotIndex:
			children = []uint32{v.NotIndex}
		}
		for _, child := range children {
			if int(child) >= i || e.Nodes[child].Depth >= n.Depth {
				return ErrRejected
			}
		}
	}
	return nil
}
func negate(m policyv1.TargetMatch) policyv1.TargetMatch {
	if m == included {
		return excluded
	}
	if m == excluded {
		return included
	}
	return unknown
}
func evaluate(e *adminv1.TargetExpression, d targetingdb.TargetingDeviceRow, metadata *adminv1.DeviceMetadata, now time.Time) policyv1.TargetMatch {
	var values [64]policyv1.TargetMatch
	for i, n := range e.Nodes {
		switch v := n.Node.(type) {
		case *adminv1.TargetNode_Predicate:
			values[i] = predicate(v.Predicate, d, metadata, now, time.Duration(e.InventoryMaxAgeSeconds)*time.Second)
		case *adminv1.TargetNode_StaticGroupId:
			values[i] = excluded
			if slices.Contains(d.Groups, uuid.MustParse(v.StaticGroupId).String()) {
				values[i] = included
			}
		case *adminv1.TargetNode_NotIndex:
			values[i] = negate(values[v.NotIndex])
		case *adminv1.TargetNode_All:
			values[i] = included
			for _, j := range v.All.Indices {
				if values[j] == excluded {
					values[i] = excluded
					break
				}
				if values[j] == unknown {
					values[i] = unknown
				}
			}
		case *adminv1.TargetNode_Any:
			values[i] = excluded
			for _, j := range v.Any.Indices {
				if values[j] == included {
					values[i] = included
					break
				}
				if values[j] == unknown {
					values[i] = unknown
				}
			}
		}
	}
	return values[len(e.Nodes)-1]
}
func predicate(f *adminv1.DeviceFilter, d targetingdb.TargetingDeviceRow, m *adminv1.DeviceMetadata, now time.Time, maxAge time.Duration) policyv1.TargetMatch {
	inventory := f.OsId != "" || f.OsVersion != "" || f.NamePrefix != ""
	if inventory && (!d.HostReceivedAt.Valid || !now.Before(d.HostReceivedAt.Time.Add(maxAge))) {
		return unknown
	}
	// The summary columns retain last successful values. Only matching-sequence
	// native observations, with successful status for every referenced field, are
	// admissible inputs; a newly received failed observation is not fresh evidence.
	if f.OsId != "" && d.OsIDStatus != 1 {
		return unknown
	}
	if f.OsVersion != "" && d.OsVersionStatus != 1 {
		return unknown
	}
	if f.NamePrefix != "" && d.HostnameStatus != 1 {
		return unknown
	}
	for _, label := range f.Labels {
		if !slices.Contains(d.Labels, label) {
			return excluded
		}
	}
	for key, want := range f.Attributes {
		if !proto.Equal(m.Attributes[key], want) {
			return excluded
		}
	}
	if f.OsId != "" && f.OsId != d.OsID {
		return excluded
	}
	if f.OsVersion != "" && f.OsVersion != d.OsVersion {
		return excluded
	}
	if !strings.HasPrefix(d.Hostname, f.NamePrefix) {
		return excluded
	}
	if lastSeenDependent(f) {
		if !d.LastSeenAt.Valid {
			return unknown
		}
		if f.LastSeenFrom != nil && d.LastSeenAt.Time.Before(f.LastSeenFrom.AsTime()) {
			return excluded
		}
		if f.LastSeenUntil != nil && d.LastSeenAt.Time.After(f.LastSeenUntil.AsTime()) {
			return excluded
		}
		if f.LastSeenWithinSeconds > 0 && d.LastSeenAt.Time.Before(now.Add(-lastSeenWindow(f))) {
			return excluded
		}
	}
	return included
}

// lastSeenDependent reports whether membership depends on the device's last
// contact, which heartbeats move without any inventory or membership change.
func lastSeenDependent(f *adminv1.DeviceFilter) bool {
	return f.LastSeenFrom != nil || f.LastSeenUntil != nil || f.LastSeenWithinSeconds > 0
}
func lastSeenWindow(f *adminv1.DeviceFilter) time.Duration {
	return time.Duration(f.LastSeenWithinSeconds) * time.Second
}
