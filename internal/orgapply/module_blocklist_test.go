package orgapply

import (
	"testing"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestApplyKernelModuleTemplateRevision(t *testing.T) {
	spec := organizationFixture()
	path := "/etc/modprobe.d/99-lindm-blocklist.conf"
	item := spec.Profiles[0].Spec.Resources[0]
	item.Desired = &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: path}, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: path, Presence: resourcev1.Presence_PRESENCE_PRESENT, KernelModuleBlocklist: &resourcev1.KernelModuleBlocklist{Modules: []string{"usb_storage", "uas"}}}}}
	client := newFakeAdmin()
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	published := client.profiles[profileID].GetSpec().GetResources()[0].GetDesired().GetManagedFile()
	if len(published.GetKernelModuleBlocklist().GetModules()) != 2 || published.Content != nil {
		t.Fatal("apply lost typed modules or substituted arbitrary file content")
	}
	mutations := len(client.requests)
	plan, err = Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != mutations {
		t.Fatal("unchanged module template published another revision")
	}
	item.Desired.GetManagedFile().KernelModuleBlocklist.Modules = []string{"usb_storage", "uas", "floppy"}
	plan, err = Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	if client.profiles[profileID].GetRevisionNumber() != 2 {
		t.Fatal("module change did not advance profile revision")
	}
}
