package resource

import (
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestRollingSnapshotSignedPolicyValidation(t *testing.T) {
	base := desiredJSON(t, updateJSON())
	base.GetOsUpdate().Selection = resourcev1.UpdateSelection_UPDATE_SELECTION_ALL
	base.GetOsUpdate().DeferralDays = 0
	base.GetOsUpdate().RollingSnapshot = &resourcev1.RollingUpdateSnapshot{Date: "2026-10-07"}
	if err := ValidateDesired(base); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*resourcev1.OSUpdateDesired){
		func(d *resourcev1.OSUpdateDesired) {
			d.Selection = resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY
		},
		func(d *resourcev1.OSUpdateDesired) { d.DeferralDays = 1 },
		func(d *resourcev1.OSUpdateDesired) { d.RollingSnapshot.Date = "../../latest" },
		func(d *resourcev1.OSUpdateDesired) { d.RollingSnapshot.RepositoryUrl = "https://archive.example/oss/" },
		func(d *resourcev1.OSUpdateDesired) { d.RollingSnapshot.MetadataSha256 = make([]byte, 32) },
		func(d *resourcev1.OSUpdateDesired) {
			d.RollingSnapshot.RepositoryUrl = "https://archive.example/oss/\n[untrusted]\n"
			d.RollingSnapshot.MetadataSha256 = make([]byte, 32)
		},
		func(d *resourcev1.OSUpdateDesired) {
			d.RollingSnapshot.RepositoryUrl = "http://archive.example/oss/"
			d.RollingSnapshot.MetadataSha256 = make([]byte, 32)
		},
	} {
		desired := proto.CloneOf(base)
		mutate(desired.GetOsUpdate())
		if err := ValidateDesired(desired); err == nil {
			t.Fatalf("accepted unsafe signed rolling policy: %v", desired)
		}
	}
}
