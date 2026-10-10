//go:build linux

package nativehelper

import (
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

const nativeTestAction = "a2bca405-36e9-4a43-b5b5-d0b82a05e551"

// unitValue requires an exact D-Bus property type rather than panicking.
func unitValue[T any](t *testing.T, values map[string]any, name string) T {
	t.Helper()
	value, ok := values[name].(T)
	if !ok {
		t.Fatalf("unit property %s has type %T", name, values[name])
	}
	return value
}

func unitValues(t *testing.T, directory string, plan *resourcev1.ResourcePlan, before, target *agentv1.ResourceOwnershipSnapshot) map[string]any {
	t.Helper()
	properties, err := resourceProperties(directory, &agentv1.NativeResourceTransactionRequest{ActionId: nativeTestAction, Plan: plan, Before: before, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]any, len(properties))
	for _, property := range properties {
		values[property.Name] = property.Value.Value()
	}
	commands := unitValue[[]unitExec](t, values, "ExecStart")
	if len(commands) != 1 || commands[0].Path != helperExecutable || !slices.Equal(commands[0].Arguments, []string{helperExecutable, "resource-transaction", "-transaction", nativeTestAction}) {
		t.Fatal("native helper changed fixed executable or exposed desired material in argv")
	}
	if values["ProtectSystem"] != "strict" || values["NoNewPrivileges"] != true || values["Restart"] != "no" {
		t.Fatal("native helper lost its one-use confined boundary")
	}
	return values
}

func TestNetSysctlReadsHostNamespaceWithoutWriteAuthority(t *testing.T) {
	directory := "/var/lib/lindm/executor/resource-transactions/" + nativeTestAction
	plan := &resourcev1.ResourcePlan{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: "net.ipv4.ip_forward"}, Plan: &resourcev1.ResourcePlan_Sysctl{Sysctl: &resourcev1.SysctlPlan{Desired: &resourcev1.SysctlDesired{Key: "net.ipv4.ip_forward"}}}}
	snapshot := func(value string) *agentv1.ResourceOwnershipSnapshot {
		return &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_Sysctl{Sysctl: &resourcev1.SysctlObservation{Value: &value}}}}
	}
	values := unitValues(t, directory, plan, snapshot("0"), snapshot("0"))
	if values["PrivateNetwork"] != false || values["ProtectKernelTunables"] != true {
		t.Fatal("no-change net sysctl read was isolated from host or received write scope")
	}
	caps := unitValue[uint64](t, values, "CapabilityBoundingSet")
	if caps&(uint64(1)<<unix.CAP_SYS_ADMIN|uint64(1)<<unix.CAP_NET_ADMIN) != 0 {
		t.Fatal("observation received sysctl mutation capabilities")
	}
	if slices.Contains(unitValue[[]string](t, values, "ReadWritePaths"), "/proc/sys/net/ipv4/ip_forward") {
		t.Fatal("observation received writable proc sysctl")
	}
	values = unitValues(t, directory, plan, snapshot("0"), snapshot("1"))
	// SELinux refuses a bind mount of the procfs file itself, so a runtime
	// change gets writable /proc/sys and the helper writes only the planned key.
	if values["ProtectKernelTunables"] != false || unitValue[uint64](t, values, "CapabilityBoundingSet")&(uint64(1)<<unix.CAP_NET_ADMIN) == 0 || slices.Contains(unitValue[[]string](t, values, "ReadWritePaths"), "/proc/sys/net/ipv4/ip_forward") {
		t.Fatal("approved runtime change missing host sysctl authority or binds the procfs file")
	}
}

func TestManagedFileHelperOnlyReceivesSelectedParent(t *testing.T) {
	directory := "/var/lib/lindm/executor/resource-transactions/" + nativeTestAction
	plan := &resourcev1.ResourcePlan{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: "/etc/lindm-resource-lab/created"}, Plan: &resourcev1.ResourcePlan_ManagedFile{ManagedFile: &resourcev1.ManagedFilePlan{Desired: &resourcev1.ManagedFileDesired{Path: "/etc/lindm-resource-lab/created"}}}}
	values := unitValues(t, directory, plan, nil, nil)
	if !slices.Equal(unitValue[[]string](t, values, "ReadWritePaths"), []string{directory, "/etc/lindm-resource-lab"}) || values["PrivateNetwork"] != true {
		t.Fatal("managed file helper widened native write or network scope")
	}
	if unitValue[uint64](t, values, "CapabilityBoundingSet")&(uint64(1)<<unix.CAP_SYS_ADMIN|uint64(1)<<unix.CAP_NET_ADMIN) != 0 {
		t.Fatal("managed file helper inherited package privileges")
	}
}

func TestLocalAccountHelperUsesExplicitIsolatedPrefix(t *testing.T) {
	directory := "/var/lib/lindm/executor/resource-transactions/" + nativeTestAction
	plan := &resourcev1.ResourcePlan{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "lindm-native-test"}, Plan: &resourcev1.ResourcePlan_LocalUser{LocalUser: &resourcev1.LocalUserPlan{Desired: &resourcev1.LocalUserDesired{Name: "lindm-native-test"}}}}
	values := unitValues(t, directory, plan, nil, nil)
	if !slices.Equal(unitValue[[]string](t, values, "ReadWritePaths"), []string{directory, filepath.Join(directory, "account-root", "etc")}) || values["ProtectHome"] != "read-only" {
		t.Fatal("native account manager received host home/database write scope instead of the pinned prefix")
	}
	bindings := unitValue[[]struct {
		Source        string
		Destination   string
		IgnoreMissing bool
		Flags         uint64
	}](t, values, "BindPaths")
	if len(bindings) != 1 || bindings[0].Source != "/etc" || bindings[0].Destination != filepath.Join(directory, "account-root", "etc") || bindings[0].IgnoreMissing {
		t.Fatal("native account database bind was not exact and mandatory")
	}
}
