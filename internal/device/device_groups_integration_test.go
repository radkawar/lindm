//go:build integration

package device

import (
	"slices"
	"strings"
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
		"paged lookup":    {GroupIds: []string{last}, PageToken: first.Msg.GetNextPageToken()},
		"sized lookup":    {GroupIds: []string{last}, PageSize: 10},
		"searched lookup": {GroupIds: []string{last}, NameSearch: "lookup"},
		"not a group ID":  {GroupIds: []string{"not-a-uuid"}},
	} {
		if _, err := f.svc.ListDeviceGroups(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%s admitted: %v", name, err)
		}
	}
}

// A picker finds a group by any part of its name in any case, past the first
// page; a % or _ is literal, and a page token continues only its own search.
func TestDeviceGroupNameSearchPagesAcrossTheList(t *testing.T) {
	f := newEnrolled(t, 0)
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	slices.Sort(ids)
	names := []string{"Lab racks A", "Office laptops", "lab_racks 50%", "Labxracks", "LAB RACKS b"}
	for index, id := range ids {
		request := &adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: id, Name: names[index], DeviceIds: []string{}, Reason: "group search test"}
		if _, err := f.svc.SetDeviceGroup(f.ownerCtx, connect.NewRequest(request)); err != nil {
			t.Fatal(err)
		}
	}
	list := func(request *adminv1.ListDeviceGroupsRequest) ([]string, string) {
		t.Helper()
		response, err := f.svc.ListDeviceGroups(f.ownerCtx, connect.NewRequest(request))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, group := range response.Msg.GetGroups() {
			got = append(got, group.GetName())
		}
		return got, response.Msg.GetNextPageToken()
	}

	var got []string
	token := ""
	for {
		page, next := list(&adminv1.ListDeviceGroupsRequest{PageSize: 1, PageToken: token, NameSearch: "lab RACKS"})
		got = append(got, page...)
		if next == "" {
			break
		}
		token = next
	}
	if !slices.Equal(got, []string{"Lab racks A", "LAB RACKS b"}) {
		t.Fatalf("paged search = %q", got)
	}
	if got, _ := list(&adminv1.ListDeviceGroupsRequest{NameSearch: "b_r"}); !slices.Equal(got, []string{"lab_racks 50%"}) {
		t.Fatalf("underscore was a wildcard: %q", got)
	}
	if got, _ := list(&adminv1.ListDeviceGroupsRequest{NameSearch: "0%"}); !slices.Equal(got, []string{"lab_racks 50%"}) {
		t.Fatalf("percent was a wildcard: %q", got)
	}
	if got, _ := list(&adminv1.ListDeviceGroupsRequest{NameSearch: "nothing like it"}); len(got) != 0 {
		t.Fatalf("unmatched search = %q", got)
	}

	_, searched := list(&adminv1.ListDeviceGroupsRequest{PageSize: 1, NameSearch: "lab"})
	_, unsearched := list(&adminv1.ListDeviceGroupsRequest{PageSize: 1})
	for name, request := range map[string]*adminv1.ListDeviceGroupsRequest{
		"searched token, other search": {PageSize: 1, PageToken: searched, NameSearch: "office"},
		"searched token, no search":    {PageSize: 1, PageToken: searched},
		"unsearched token with search": {PageSize: 1, PageToken: unsearched, NameSearch: "lab"},
		"over-long search":             {NameSearch: strings.Repeat("a", 129)},
		"NUL in search":                {NameSearch: "a\x00b"},
	} {
		if _, err := f.svc.ListDeviceGroups(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%s admitted: %v", name, err)
		}
	}
}
