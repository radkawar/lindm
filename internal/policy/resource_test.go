package policy

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func groupResource(resourceID, name string) *policyv1.ProfileResource {
	item := resource(resourceID, "unused.service", runtimeActive(), enablementUnmanaged(), nil)
	item.Desired = &resourcev1.ResourceDesiredState{
		Ref:   &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: name},
		State: &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: &resourcev1.LocalGroupDesired{Name: name, Presence: resourcev1.Presence_PRESENCE_PRESENT}},
	}
	return item
}

func TestResolveHeterogeneousComplementaryDimensions(t *testing.T) {
	left := groupResource(resourceA, "operators")
	left.Desired.GetLocalGroup().Gid = proto.Uint32(1500)
	right := groupResource(resourceB, "operators")
	right.Desired.GetLocalGroup().Members = &resourcev1.MemberSet{Mode: resourcev1.SetMode_SET_MODE_ADDITIVE, LocalUserNames: []string{"alice"}}
	service := resource(resourceC, "app.service", runtimeActive(), enablementUnmanaged(), nil)
	service.DependsOn = []*policyv1.ResourceDependency{{Ref: proto.CloneOf(left.Desired.Ref), Condition: policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_PRESENT}}
	assignments := []Assignment{
		{ProfileID: profileLow, RevisionID: revisionLow, Spec: spec("left", left, service)},
		{ProfileID: profileHigh, RevisionID: revisionHi, Spec: spec("right", right)},
	}
	before := cloneAssignments(assignments)
	got, err := Resolve(t.Context(), assignments)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("resources=%d", len(got))
	}
	for _, item := range got {
		if item.State != ResolutionReady || item.Resource == nil {
			t.Fatalf("resolution=%v", item)
		}
		if item.Ref.GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP {
			group := item.Desired.GetLocalGroup()
			if group.GetGid() != 1500 || len(group.GetMembers().GetLocalUserNames()) != 1 {
				t.Fatalf("merged group=%v", group)
			}
			group.Members.LocalUserNames[0] = "changed"
		}
	}
	if !assignmentsEqual(before, assignments) {
		t.Fatal("merged nested data aliases an assignment")
	}
}

func TestResolveExplicitOptionalDisagreementAndMetadataAuthority(t *testing.T) {
	for _, dimension := range []string{"gid", "ownership", "verification", "dependency condition"} {
		t.Run(dimension, func(t *testing.T) {
			left := groupResource(resourceA, "operators")
			right := groupResource(resourceB, "operators")
			left.Desired.GetLocalGroup().Gid = proto.Uint32(0)
			right.Desired.GetLocalGroup().Gid = proto.Uint32(0)
			leftSpec, rightSpec := spec("left", left), spec("right", right)
			switch dimension {
			case "gid":
				right.Desired.GetLocalGroup().Gid = proto.Uint32(1500)
			case "ownership":
				right.Ownership.Release = resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN
			case "verification":
				right.Verification.MaxAgeSeconds = 600
			case "dependency condition":
				dep := resource(resourceC, "base.service", runtimeActive(), enablementUnmanaged(), nil)
				leftSpec.Resources = append(leftSpec.Resources, dep)
				rightSpec.Resources = append(rightSpec.Resources, proto.CloneOf(dep))
				left.DependsOn = []*policyv1.ResourceDependency{{Ref: proto.CloneOf(dep.Desired.Ref), Condition: policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED}}
				right.DependsOn = []*policyv1.ResourceDependency{{Ref: proto.CloneOf(dep.Desired.Ref), Condition: policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_ACTIVE}}
			}
			got, err := Resolve(t.Context(), []Assignment{{ProfileID: profileLow, RevisionID: revisionLow, Spec: leftSpec}, {ProfileID: profileHigh, RevisionID: revisionHi, Spec: rightSpec}})
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range got {
				if item.Ref.GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP && (item.State != ResolutionConflict || item.Reason != ReasonEqualPriority || item.Desired != nil || item.Resource != nil) {
					t.Fatalf("authority disagreement=%v", item)
				}
			}
		})
	}
}

func TestCanonicalProfileIdentityAndDependencyDigest(t *testing.T) {
	group := groupResource(resourceA, "operators")
	service := resource(resourceB, "app.service", runtimeActive(), enablementUnmanaged(), nil)
	service.DependsOn = []*policyv1.ResourceDependency{{Ref: proto.CloneOf(group.Desired.Ref), Condition: policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_PRESENT}}
	original := spec("mixed", service, group)
	reordered := proto.CloneOf(original)
	reordered.Resources[0], reordered.Resources[1] = reordered.Resources[1], reordered.Resources[0]
	_, first, err := CanonicalSpec(t.Context(), original)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := CanonicalSpec(t.Context(), reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first[:], second[:]) {
		t.Fatal("resource order changes canonical digest")
	}
	reordered.Resources[1].DependsOn[0].Condition = policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED
	_, changed, err := CanonicalSpec(t.Context(), reordered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[:], changed[:]) {
		t.Fatal("dependency condition absent from immutable digest")
	}
	invalid := proto.CloneOf(original)
	invalid.Resources[1].Desired.Ref.CanonicalKey = "other"
	if err := Validate(t.Context(), invalid); err == nil {
		t.Fatal("accepted forged canonical resource identity")
	}
}

func TestMergeManagedEmptySetIsNotUnmanaged(t *testing.T) {
	left := groupResource(resourceA, "operators")
	right := groupResource(resourceB, "operators")
	left.Desired.GetLocalGroup().Members = &resourcev1.MemberSet{Mode: resourcev1.SetMode_SET_MODE_EXACT}
	right.Desired.GetLocalGroup().Members = &resourcev1.MemberSet{Mode: resourcev1.SetMode_SET_MODE_EXACT, LocalUserNames: []string{"alice"}}
	if mergeDesired(left.Desired, right.Desired) {
		t.Fatal("merged explicitly empty set into populated set")
	}
}

func TestResolveRepeatedProfileTargets(t *testing.T) {
	base := Assignment{ProfileID: profileLow, RevisionID: revisionLow, Spec: spec("base", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil))}
	higher := base
	higher.Priority = 10
	next := higher
	next.RevisionID = revisionHi
	next.Spec = spec("next", resource(resourceB, "app.service", runtimeInactive(), enablementUnmanaged(), nil))
	next.Priority = 20
	resolved, err := Resolve(t.Context(), []Assignment{base, base, higher, next})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].State != ResolutionReady || len(resolved[0].Contributors) != 1 || len(resolved[0].Overridden) != 2 || resolved[0].Desired.GetSystemdService().GetRuntime() != runtimeInactive() {
		t.Fatalf("repeated targeting result=%v", resolved)
	}
}

func TestResolveCrossKindClaimsBlockDependents(t *testing.T) {
	group := groupResource(resourceA, "operators")
	group.Ownership.CompleteMembershipDimension = true
	group.Desired.GetLocalGroup().Members = &resourcev1.MemberSet{Mode: resourcev1.SetMode_SET_MODE_EXACT, LocalUserNames: []string{"alice"}}
	user := groupResource(resourceB, "unused")
	user.Desired = &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "bob"},
		State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: &resourcev1.LocalUserDesired{
			Name: "bob", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			SupplementaryGroups: &resourcev1.MemberSet{Mode: resourcev1.SetMode_SET_MODE_ADDITIVE, LocalUserNames: []string{"operators"}},
		}},
	}
	service := resource(resourceC, "app.service", runtimeActive(), enablementUnmanaged(), nil)
	service.DependsOn = []*policyv1.ResourceDependency{{Ref: proto.CloneOf(group.Desired.Ref), Condition: policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED}}
	resolved, err := Resolve(t.Context(), []Assignment{
		{ProfileID: profileLow, RevisionID: revisionLow, Priority: 1, Spec: spec("group", group, service)},
		{ProfileID: profileHigh, RevisionID: revisionHi, Priority: 10, Spec: spec("user", user)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 3 {
		t.Fatalf("resolution count=%d", len(resolved))
	}
	for _, item := range resolved {
		if item.Ref.GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE {
			if item.State != ResolutionBlocked || item.Reason != ReasonDependencyConflict || item.Desired == nil {
				t.Fatalf("claim dependent=%v", item)
			}
		} else if item.State != ResolutionConflict || item.Reason != ReasonClaimConflict || item.Desired != nil || item.Resource != nil {
			t.Fatalf("cross-kind claim conflict=%v", item)
		}
	}
}

func TestCanonicalSetPermutationDigestAndMerge(t *testing.T) {
	group := groupResource(resourceA, "operators")
	group.Ownership.CompleteMembershipDimension = true
	group.Desired.GetLocalGroup().Members = &resourcev1.MemberSet{
		Mode: resourcev1.SetMode_SET_MODE_EXACT, LocalUserNames: []string{"bob", "alice"},
	}
	group.Verification.Checks = []resourcev1.HealthCheck{
		resourcev1.HealthCheck_HEALTH_CHECK_AUTHENTICATION, resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE,
	}
	group.Applicability = &resourcev1.Applicability{Products: []*resourcev1.PlatformProduct{
		{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"},
		{OsId: "debian", Product: "Debian", Version: "13", Architecture: "x86_64"},
	}}
	left := spec("sets", group)
	right := proto.CloneOf(left)
	other := right.Resources[0]
	other.Desired.GetLocalGroup().Members.LocalUserNames = []string{"alice", "bob"}
	other.Verification.Checks[0], other.Verification.Checks[1] = other.Verification.Checks[1], other.Verification.Checks[0]
	other.Applicability.Products[0], other.Applicability.Products[1] = other.Applicability.Products[1], other.Applicability.Products[0]
	beforeLeft, beforeRight := proto.CloneOf(left), proto.CloneOf(right)
	canonicalLeft, first, err := CanonicalSpec(t.Context(), left)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRight, second, err := CanonicalSpec(t.Context(), right)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !proto.Equal(canonicalLeft, canonicalRight) {
		t.Fatal("membership or metadata set permutation changed immutable identity")
	}
	assignments := []Assignment{
		{ProfileID: profileLow, RevisionID: revisionLow, Spec: left},
		{ProfileID: profileHigh, RevisionID: revisionHi, Spec: right},
	}
	for _, input := range [][]Assignment{assignments, {assignments[1], assignments[0]}} {
		resolved, err := Resolve(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		if len(resolved) != 1 || resolved[0].State != ResolutionReady || !proto.Equal(resolved[0].Resource, canonicalLeft.Resources[0]) {
			t.Fatalf("set permutation did not merge canonically: %v", resolved)
		}
	}
	if !proto.Equal(left, beforeLeft) || !proto.Equal(right, beforeRight) {
		t.Fatal("set normalization mutated caller-owned profiles")
	}
}

func TestModuleBlocklistSetPermutationDigestAndMerge(t *testing.T) {
	item := groupResource(resourceA, "unused")
	item.Desired = &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: "/etc/modprobe.d/99-lindm-blocklist.conf"},
		State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{
			Path: "/etc/modprobe.d/99-lindm-blocklist.conf", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			KernelModuleBlocklist: &resourcev1.KernelModuleBlocklist{Modules: []string{"usb_storage", "uas"}},
		}},
	}
	left := spec("module set", item)
	right := proto.CloneOf(left)
	right.Resources[0].Desired.GetManagedFile().KernelModuleBlocklist.Modules = []string{"uas", "usb_storage"}
	beforeLeft, beforeRight := proto.CloneOf(left), proto.CloneOf(right)
	canonical, first, err := CanonicalSpec(t.Context(), left)
	if err != nil {
		t.Fatal(err)
	}
	other, second, err := CanonicalSpec(t.Context(), right)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !proto.Equal(canonical, other) {
		t.Fatal("module order changed immutable profile identity")
	}
	assignments := []Assignment{{ProfileID: profileLow, RevisionID: revisionLow, Spec: left}, {ProfileID: profileHigh, RevisionID: revisionHi, Spec: right}}
	for _, input := range [][]Assignment{assignments, {assignments[1], assignments[0]}} {
		resolved, err := Resolve(t.Context(), input)
		if err != nil || len(resolved) != 1 || resolved[0].State != ResolutionReady || !proto.Equal(resolved[0].Resource, canonical.Resources[0]) {
			t.Fatalf("equal-priority module permutation conflict: %v %v", resolved, err)
		}
	}
	if !proto.Equal(left, beforeLeft) || !proto.Equal(right, beforeRight) {
		t.Fatal("module canonicalization mutated caller profiles")
	}
}

func dnsResource(resourceID string) *policyv1.ProfileResource {
	item := groupResource(resourceID, "unused")
	item.Desired = &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_DNS, CanonicalKey: "system"},
		State: &resourcev1.ResourceDesiredState_Dns{Dns: &resourcev1.DNSDesired{
			Scope: &resourcev1.DNSDesired_System{System: &resourcev1.SystemScope{}},
		}},
	}
	return item
}

func TestResolveDNSOptionalServersAndManagedEmpty(t *testing.T) {
	for _, empty := range []bool{false, true} {
		left, right := dnsResource(resourceA), dnsResource(resourceB)
		left.Desired.GetDns().Dnssec = resourcev1.DNSSECMode_DNSSEC_MODE_REQUIRED.Enum()
		right.Desired.GetDns().Servers = &resourcev1.DNSServerList{}
		if !empty {
			right.Desired.GetDns().Servers.Servers = []*resourcev1.DNSServer{{Address: "192.0.2.53"}}
		}
		leftSpec, rightSpec := spec("dnssec", left), spec("servers", right)
		beforeLeft, beforeRight := proto.CloneOf(leftSpec), proto.CloneOf(rightSpec)
		resolved, err := Resolve(t.Context(), []Assignment{
			{ProfileID: profileLow, RevisionID: revisionLow, Spec: leftSpec},
			{ProfileID: profileHigh, RevisionID: revisionHi, Spec: rightSpec},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(resolved) != 1 || resolved[0].State != ResolutionReady {
			t.Fatalf("DNS server presence merge empty=%v: %v", empty, resolved)
		}
		dns := resolved[0].Desired.GetDns()
		if dns.GetDnssec() != resourcev1.DNSSECMode_DNSSEC_MODE_REQUIRED || dns.Servers == nil || !proto.Equal(dns.Servers, right.Desired.GetDns().Servers) {
			t.Fatalf("DNS dimensions lost: %v", dns)
		}
		if !proto.Equal(leftSpec, beforeLeft) || !proto.Equal(rightSpec, beforeRight) {
			t.Fatal("DNS merge mutated an assignment")
		}
	}
	empty, populated := dnsResource(resourceA), dnsResource(resourceB)
	empty.Desired.GetDns().Servers = &resourcev1.DNSServerList{}
	populated.Desired.GetDns().Servers = &resourcev1.DNSServerList{Servers: []*resourcev1.DNSServer{{Address: "192.0.2.53"}}}
	resolved, err := Resolve(t.Context(), []Assignment{
		{ProfileID: profileLow, RevisionID: revisionLow, Spec: spec("clear", empty)},
		{ProfileID: profileHigh, RevisionID: revisionHi, Spec: spec("set", populated)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].State != ResolutionConflict || resolved[0].Reason != ReasonEqualPriority {
		t.Fatalf("explicit DNS clear was treated as unmanaged: %v", resolved)
	}
}

func TestCanonicalProfilePreservesOrderedDNSLists(t *testing.T) {
	item := dnsResource(resourceA)
	item.Desired.GetDns().Servers = &resourcev1.DNSServerList{Servers: []*resourcev1.DNSServer{
		{Address: "192.0.2.53"}, {Address: "192.0.2.54"},
	}}
	item.Desired.GetDns().SearchDomains = &resourcev1.DomainList{Names: []string{"a.example", "b.example"}}
	original := spec("ordered DNS", item)
	for _, dimension := range []string{"servers", "search domains"} {
		reordered := proto.CloneOf(original)
		dns := reordered.Resources[0].Desired.GetDns()
		if dimension == "servers" {
			dns.Servers.Servers[0], dns.Servers.Servers[1] = dns.Servers.Servers[1], dns.Servers.Servers[0]
		} else {
			dns.SearchDomains.Names[0], dns.SearchDomains.Names[1] = dns.SearchDomains.Names[1], dns.SearchDomains.Names[0]
		}
		canonical, first, err := CanonicalSpec(t.Context(), original)
		if err != nil {
			t.Fatal(err)
		}
		_, second, err := CanonicalSpec(t.Context(), reordered)
		if err != nil {
			t.Fatal(err)
		}
		if first == second || !proto.Equal(canonical.Resources[0].Desired, item.Desired) {
			t.Fatalf("canonicalization discarded ordered %s", dimension)
		}
	}
}
