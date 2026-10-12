//go:build linux

package capabilitypolicy

import (
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestRequiredCapability(t *testing.T) {
	host := testHost(t, "ubuntu-24.04")
	derived := derive(t, &agentv1.AgentConfig{}, testRecord(true, remoteCapabilities...), host).Config
	empty := &agentv1.AgentConfig{}
	local := &agentv1.AgentConfig{FileProvider: &agentv1.NativeFileProviderConfig{AllowedRoots: []string{"/srv/managed"}}, PasswordProvider: &agentv1.NativePasswordProviderConfig{}}
	ref := func(kind resourcev1.ResourceKind) *resourcev1.ResourceRef {
		return &resourcev1.ResourceRef{Kind: kind}
	}
	file := func(path string) *resourcev1.ResourceDesiredState {
		return &resourcev1.ResourceDesiredState{Ref: ref(resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE), State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: path}}}
	}
	modules := &resourcev1.ResourceDesiredState{Ref: ref(resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE), State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: "/etc/modprobe.d/99-lindm-blocklist.conf", KernelModuleBlocklist: &resourcev1.KernelModuleBlocklist{Modules: []string{"usb_storage"}}}}}
	pkg := func(key string) *resourcev1.ResourceDesiredState {
		return &resourcev1.ResourceDesiredState{Ref: ref(resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE), State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: key}}}}
	}
	sysctl := func(key string) *resourcev1.ResourceDesiredState {
		return &resourcev1.ResourceDesiredState{Ref: ref(resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL), State: &resourcev1.ResourceDesiredState_Sysctl{Sysctl: &resourcev1.SysctlDesired{Key: key}}}
	}
	kind := func(k resourcev1.ResourceKind) *resourcev1.ResourceDesiredState {
		return &resourcev1.ResourceDesiredState{Ref: ref(k)}
	}
	ubuntuArchive := "apt/8053e72a-44e8-53fc-9472-825c068cf9b5"
	for name, tc := range map[string]struct {
		desired *resourcev1.ResourceDesiredState
		config  *agentv1.AgentConfig
		want    agentv1.ManagementCapability
	}{
		"package without provider":     {pkg(ubuntuArchive), empty, capPackages},
		"package from vendor archive":  {pkg(ubuntuArchive), derived, 0},
		"package from unknown archive": {pkg("apt/55555555-5555-4555-8555-555555555555"), derived, capPackages},
		"package with wrong ecosystem": {pkg("rpm/8053e72a-44e8-53fc-9472-825c068cf9b5"), derived, capPackages},
		"standard root file":           {file("/etc/motd.d/10-lindm"), empty, capFiles},
		"standard root file granted":   {file("/etc/motd.d/10-lindm"), derived, 0},
		"standard root itself":         {file("/etc/motd.d"), derived, capCustom},
		"custom root file":             {file("/srv/managed/app.conf"), derived, capCustom},
		"custom root file local":       {file("/srv/managed/app.conf"), local, 0},
		"module template":              {modules, empty, capModules},
		"module template granted":      {modules, derived, 0},
		"user":                         {kind(resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER), empty, capAccounts},
		"group granted":                {kind(resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP), derived, 0},
		"firewall":                     {kind(resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE), empty, capFirewall},
		"firewall granted":             {kind(resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE), derived, 0},
		"os update":                    {kind(resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY), empty, capUpdates},
		"os update granted":            {kind(resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY), derived, 0},
		"sysctl granted key":           {sysctl("net.ipv4.ip_forward"), derived, 0},
		"sysctl other key":             {sysctl("vm.swappiness"), derived, capSysctl},
		"password":                     {kind(resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY), derived, capPassword},
		"password local":               {kind(resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY), local, 0},
		"service needs nothing":        {kind(resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE), empty, 0},
		"definition needs nothing":     {kind(resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION), empty, 0},
		"encryption needs nothing":     {kind(resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE), empty, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := RequiredCapability(tc.desired, tc.config, host); got != tc.want {
				t.Fatalf("RequiredCapability = %s, want %s", got, tc.want)
			}
		})
	}
}
