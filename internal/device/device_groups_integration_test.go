//go:build integration

package device

import (
	"slices"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// A saved selection (an account's scope group, a rollout target) must be
// nameable even when the group is not on the first page of the ID-ordered list.
func TestDeviceGroupLookupNamesGroupsBeyondTheFirstPage(t *testing.T) {
	f := newEnrolled(t, 0)
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	slices.Sort(ids)
	for index, id := range ids {
		members := []string{}
		if index == len(ids)-1 {
			members = []string{f.deviceID}
		}
		request := &adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: id, Name: "lookup " + id[:8], DeviceIds: members, Reason: "group lookup test"}
		if _, err := f.svc.SetDeviceGroup(f.ownerCtx, connect.NewRequest(request)); err != nil {
			t.Fatal(err)
		}
	}
	first, err := f.svc.ListDeviceGroups(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{PageSize: 1}))
	if err != nil {
		t.Fatal(err)
	}
	last := ids[len(ids)-1]
	if len(first.Msg.GetGroups()) != 1 || first.Msg.GetGroups()[0].GetId() == last || first.Msg.GetNextPageToken() == "" {
		t.Fatalf("first page should hold one other group and continue: %v", first.Msg)
	}

	missing := uuid.NewString()
	found, err := f.svc.ListDeviceGroups(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{GroupIds: []string{missing, last}}))
	if err != nil {
		t.Fatal(err)
	}
	groups := found.Msg.GetGroups()
	if len(groups) != 1 || groups[0].GetId() != last || groups[0].GetName() != "lookup "+last[:8] ||
		!slices.Equal(groups[0].GetDeviceIds(), []string{f.deviceID}) || found.Msg.GetNextPageToken() != "" {
		t.Fatalf("lookup did not return exactly the saved group with its members: %v", found.Msg)
	}

	for name, request := range map[string]*adminv1.ListDeviceGroupsRequest{
		"paged lookup":   {GroupIds: []string{last}, PageToken: first.Msg.GetNextPageToken()},
		"sized lookup":   {GroupIds: []string{last}, PageSize: 10},
		"not a group ID": {GroupIds: []string{"not-a-uuid"}},
	} {
		if _, err := f.svc.ListDeviceGroups(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%s admitted: %v", name, err)
		}
	}
}
