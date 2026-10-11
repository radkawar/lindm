//go:build linux

package nativehelper

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/accountprovider"
	"lindm/internal/agent/fileprovider"
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
	kind, err := effectKind(plan.GetRef().GetKind())
	if err != nil {
		t.Fatal(err)
	}
	properties, err := resourceProperties(kind, directory, &agentv1.NativeResourceTransactionRequest{ActionId: nativeTestAction, Plan: plan, Before: before, Target: target})
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

func TestModuleHelpersExposeReadOnlyMetadataWithoutModuleAuthority(t *testing.T) {
	directory := "/var/lib/lindm/executor/resource-transactions/" + nativeTestAction
	desired := &resourcev1.ManagedFileDesired{Path: fileprovider.ModuleBlocklistPath, Presence: resourcev1.Presence_PRESENCE_PRESENT, KernelModuleBlocklist: &resourcev1.KernelModuleBlocklist{Modules: []string{"usb_storage"}}}
	ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: desired.Path}
	plan := &resourcev1.ResourcePlan{Ref: ref, Backend: &resourcev1.BackendSelection{Product: &resourcev1.PlatformProduct{OsId: "fedora", Version: "44"}}, Plan: &resourcev1.ResourcePlan_ManagedFile{ManagedFile: &resourcev1.ManagedFilePlan{Desired: desired}}}
	effect := unitValues(t, directory, plan, nil, nil)
	request := &agentv1.NativeResourceObservationRequest{ObservationId: nativeTestAction, Desired: &resourcev1.ResourceDesiredState{Ref: ref, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: desired}}}
	properties, err := observationProperties(t.Context(), directory, request)
	if err != nil {
		t.Fatal(err)
	}
	observation := make(map[string]any, len(properties))
	for _, property := range properties {
		observation[property.Name] = property.Value.Value()
	}
	for _, values := range []map[string]any{effect, observation} {
		if values["ProtectKernelModules"] != false || values["ProtectSystem"] != "strict" || !slices.Equal(unitValue[[]string](t, values, "ReadOnlyPaths"), []string{"/lib/modules"}) {
			t.Fatal("module metadata is hidden or writable")
		}
		if unitValue[uint64](t, values, "CapabilityBoundingSet")&(uint64(1)<<unix.CAP_SYS_MODULE|uint64(1)<<unix.CAP_SYS_ADMIN) != 0 {
			t.Fatal("module observer received load/unload or namespace authority")
		}
		filter := unitValue[struct {
			AllowList bool
			Syscalls  []string
		}](t, values, "SystemCallFilter")
		if filter.AllowList || !slices.Equal(filter.Syscalls, []string{"@module"}) {
			t.Fatal("module syscalls were not denied independently of capabilities")
		}
	}
	if !slices.Equal(unitValue[[]string](t, observation, "ReadWritePaths"), []string{directory}) {
		t.Fatal("read-only observer received host write scope")
	}
	if !slices.Equal(unitValue[[]string](t, effect, "ReadWritePaths"), []string{directory, "/etc/modprobe.d", "/boot"}) {
		t.Fatal("template effect escaped its fixed file and registry boot-image scope")
	}
	request.Desired.GetManagedFile().KernelModuleBlocklist = nil
	if _, err := observationProperties(t.Context(), directory, request); err == nil {
		t.Fatal("raw managed file acquired module metadata observer")
	}
}

func TestModuleStateWritePathDoesNotCreateBeforePermit(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "vendor-state")
	if got, err := moduleStateWritePath(directory); err != nil || got != parent {
		t.Fatalf("missing state directory: path=%q err=%v", got, err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sandbox preparation created host state: %v", err)
	}
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := moduleStateWritePath(directory); err != nil || got != directory {
		t.Fatalf("existing state directory: path=%q err=%v", got, err)
	}
	link := filepath.Join(parent, "state-link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if _, err := moduleStateWritePath(link); !errors.Is(err, fileprovider.ErrUnsupported) {
		t.Fatalf("symlink state directory accepted: %v", err)
	}
	if _, err := moduleStateWritePath(filepath.Join(parent, "absent", "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing parent widened scope recursively: %v", err)
	}
}

func TestSSHBannerHelperHasNoAuthenticationOrNetworkAdministrationAuthority(t *testing.T) {
	directory := "/var/lib/lindm/executor/resource-transactions/" + nativeTestAction
	plan := &resourcev1.ResourcePlan{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}, Plan: &resourcev1.ResourcePlan_SshServer{SshServer: &resourcev1.SSHServerPlan{Desired: &resourcev1.SSHServerDesired{}}}}
	values := unitValues(t, directory, plan, nil, nil)
	if !slices.Equal(unitValue[[]string](t, values, "ReadWritePaths"), []string{directory, "/etc"}) || values["PrivateNetwork"] != false {
		t.Fatal("banner atomic siblings or fresh host-namespace connection scope changed")
	}
	if unitValue[uint64](t, values, "CapabilityBoundingSet")&(uint64(1)<<unix.CAP_SYS_ADMIN|uint64(1)<<unix.CAP_NET_ADMIN|uint64(1)<<unix.CAP_SYS_CHROOT|uint64(1)<<unix.CAP_SETUID) != 0 {
		t.Fatal("banner helper inherited unrelated capabilities")
	}
}

func TestOSUpdateHelperOnlyReceivesOwnedConfigurationParents(t *testing.T) {
	directory := "/var/lib/lindm/executor/resource-transactions/" + nativeTestAction
	for _, test := range []struct {
		os, version string
		backend     resourcev1.OSUpdateBackend
		paths       []string
	}{
		{"ubuntu", "24.04", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES, []string{directory, "/etc/lindm/os-update", "/etc/systemd/system", "/etc/apt/apt.conf.d"}},
		{"fedora", "44", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC, []string{directory, "/etc/lindm/os-update", "/etc/systemd/system", "/etc/dnf"}},
		{"rhel", "9.8", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC, []string{directory, "/etc/lindm/os-update", "/etc/systemd/system"}},
		{"rhel", "10.2", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC, []string{directory, "/etc/lindm/os-update", "/etc/systemd/system"}},
	} {
		plan := &resourcev1.ResourcePlan{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY, CanonicalKey: "system"}, Backend: &resourcev1.BackendSelection{Product: &resourcev1.PlatformProduct{OsId: test.os, Version: test.version}}, Plan: &resourcev1.ResourcePlan_OsUpdate{OsUpdate: &resourcev1.OSUpdatePlan{Desired: &resourcev1.OSUpdateDesired{}, Backend: test.backend}}}
		values := unitValues(t, directory, plan, nil, nil)
		if !slices.Equal(unitValue[[]string](t, values, "ReadWritePaths"), test.paths) || values["PrivateNetwork"] != true {
			t.Fatalf("%s update policy helper widened native write or network scope", test.os)
		}
		if unitValue[uint64](t, values, "CapabilityBoundingSet")&(uint64(1)<<unix.CAP_SYS_ADMIN|uint64(1)<<unix.CAP_NET_ADMIN) != 0 {
			t.Fatal("update policy helper inherited package privileges")
		}
	}
	plan := &resourcev1.ResourcePlan{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY, CanonicalKey: "system"}, Backend: &resourcev1.BackendSelection{Product: &resourcev1.PlatformProduct{OsId: "arch"}}, Plan: &resourcev1.ResourcePlan_OsUpdate{OsUpdate: &resourcev1.OSUpdatePlan{Desired: &resourcev1.OSUpdateDesired{}}}}
	kind, err := effectKind(plan.GetRef().GetKind())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resourceProperties(kind, directory, &agentv1.NativeResourceTransactionRequest{ActionId: nativeTestAction, Plan: plan}); err == nil {
		t.Fatal("unsupported product received native update policy write scope")
	}
}

func TestLocalAccountHelperUsesExplicitIsolatedPrefix(t *testing.T) {
	directory := "/var/lib/lindm/executor/resource-transactions/" + nativeTestAction
	root := filepath.Join(directory, accountprovider.NativeRootDirectory)
	for _, tc := range []struct {
		product *resourcev1.PlatformProduct
		chroot  bool
	}{
		{&resourcev1.PlatformProduct{OsId: "ubuntu", Version: "24.04"}, false},
		{&resourcev1.PlatformProduct{OsId: "fedora", Version: "44"}, false},
		{&resourcev1.PlatformProduct{OsId: "almalinux", Version: "9.8"}, true},
		{&resourcev1.PlatformProduct{OsId: "rhel", Version: "9.8"}, true},
		{&resourcev1.PlatformProduct{OsId: "almalinux", Version: "10.2"}, true},
	} {
		plan := &resourcev1.ResourcePlan{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "lindm-native-test"}, Backend: &resourcev1.BackendSelection{Product: tc.product}, Plan: &resourcev1.ResourcePlan_LocalUser{LocalUser: &resourcev1.LocalUserPlan{Desired: &resourcev1.LocalUserDesired{Name: "lindm-native-test"}}}}
		values := unitValues(t, directory, plan, nil, nil)
		if !slices.Equal(unitValue[[]string](t, values, "ReadWritePaths"), []string{directory, filepath.Join(root, "etc")}) || values["ProtectHome"] != "read-only" || values["ProtectKernelTunables"] != true {
			t.Fatalf("%s: native account manager received host home/database write scope instead of the pinned root", tc.product.GetOsId())
		}
		want := []bindPath{{"/etc", filepath.Join(root, "etc"), false, 0}}
		if tc.chroot {
			// Non-recursive host procfs and selinuxfs binds for the chrooted
			// shadow tools, with the kernel tunables kept read-only inside.
			want = append(want, bindPath{"/proc", filepath.Join(root, "proc"), false, 0}, bindPath{"/sys/fs/selinux", filepath.Join(root, "sys/fs/selinux"), false, 0})
			readOnly := unitValue[[]string](t, values, "ReadOnlyPaths")
			if !slices.Contains(readOnly, "-"+filepath.Join(root, "proc/sys")) || !slices.Contains(readOnly, "-"+filepath.Join(root, "proc/sysrq-trigger")) || !slices.Equal(unitValue[[]string](t, values, "InaccessiblePaths"), []string{"-" + filepath.Join(root, "proc/kmsg")}) {
				t.Fatalf("%s: bound procfs exposes writable kernel tunables or logs", tc.product.GetOsId())
			}
			if !slices.Equal(unitValue[[]bindPath](t, values, "BindReadOnlyPaths"), []bindPath{{"/usr", filepath.Join(root, "usr"), false, 0}}) {
				t.Fatalf("%s: host /usr was not bound read-only for the tools' shell check", tc.product.GetOsId())
			}
		} else if _, ok := values["ReadOnlyPaths"]; ok {
			t.Fatalf("%s: prefix product received chroot-only mounts", tc.product.GetOsId())
		} else if _, ok := values["BindReadOnlyPaths"]; ok {
			t.Fatalf("%s: prefix product received chroot-only mounts", tc.product.GetOsId())
		}
		if !slices.Equal(unitValue[[]bindPath](t, values, "BindPaths"), want) {
			t.Fatalf("%s: native account binds were not exact and mandatory: %v", tc.product.GetOsId(), values["BindPaths"])
		}
	}
}

// The root helper's registry is the only kind dispatch: read-only compliance
// kinds and unknown kinds never reach an effect unit, and only kinds the
// executor cannot read itself get a native observer.
func TestNativeKindRegistryIsClosed(t *testing.T) {
	for _, kind := range []resourcev1.ResourceKind{resourcev1.ResourceKind_RESOURCE_KIND_UNSPECIFIED, resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE, resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE} {
		if _, err := effectKind(kind); err == nil {
			t.Errorf("%s has a native effect", kind)
		}
	}
	for _, kind := range []resourcev1.ResourceKind{resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION, resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY, resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE} {
		if _, err := observedKind(kind); err == nil {
			t.Errorf("%s gained a native observer the executor does not need", kind)
		}
	}
	for _, kind := range []resourcev1.ResourceKind{resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE} {
		if _, err := effectKind(kind); err != nil {
			t.Errorf("%s lost its native effect: %v", kind, err)
		}
		if _, err := observedKind(kind); err != nil {
			t.Errorf("%s lost its native observer: %v", kind, err)
		}
	}
}
