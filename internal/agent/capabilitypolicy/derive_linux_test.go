// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capabilitypolicy

import (
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
)

const (
	capPackages = agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES
	capFiles    = agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES
	capModules  = agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_MODULE_BLOCKLIST
	capAccounts = agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_LOCAL_ACCOUNTS
	capFirewall = agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL
	capUpdates  = agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_OS_UPDATES
	capSysctl   = agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_SETTINGS
	capPassword = agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PASSWORD_POLICY
	capCustom   = agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_CUSTOM_FILE_ROOTS

	statusNotEnabled  = agentv1.CapabilityStatus_CAPABILITY_STATUS_NOT_ENABLED
	statusEnabled     = agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED
	statusLocal       = agentv1.CapabilityStatus_CAPABILITY_STATUS_LOCAL
	statusUnavailable = agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE
)

var remoteCapabilities = []agentv1.ManagementCapability{capPackages, capFiles, capModules, capAccounts, capFirewall, capUpdates, capSysctl}

func TestDeriveUbuntuGrantsEveryRemoteCapability(t *testing.T) {
	local := &agentv1.AgentConfig{StateDirectory: "/var/lib/lindm/executor"}
	before := clone(local)
	effective := derive(t, local, testRecord(true, remoteCapabilities...), testHost(t, "ubuntu-24.04"))
	if !proto.Equal(local, before) {
		t.Fatal("derivation modified the local configuration")
	}
	for _, c := range remoteCapabilities {
		wantStatus(t, effective, c, statusEnabled, "")
	}
	wantStatus(t, effective, capPassword, statusNotEnabled, "")
	wantStatus(t, effective, capCustom, statusNotEnabled, "")
	for i, observed := range effective.Status {
		if observed.GetCapability() != agentv1.ManagementCapability(i+1) {
			t.Fatalf("status %d is %s, want catalogue order", i, observed.GetCapability())
		}
	}
	cfg := effective.Config

	sources := cfg.GetPackageProvider().GetSources()
	if len(sources) != 1 {
		t.Fatalf("package sources = %d", len(sources))
	}
	apt := sources[0].GetRepository().GetApt()
	if sources[0].GetRepository().GetRepositoryId() != "8053e72a-44e8-53fc-9472-825c068cf9b5" || apt.GetUri() != "https://archive.ubuntu.com/ubuntu" || apt.GetSuite() != "noble" ||
		!slices.Equal(apt.GetAdditionalSuites(), []string{"noble-updates", "noble-security"}) || !slices.Equal(apt.GetComponents(), []string{"main", "universe"}) ||
		!slices.Equal(apt.GetArchitectures(), []string{"amd64"}) || sources[0].GetSigningKeyFile() != "/usr/share/keyrings/ubuntu-archive-keyring.gpg" ||
		apt.GetSigningKey().GetSizeBytes() != uint64(len(testKey)) || string(apt.GetSigningKey().GetSha256()) != string(sources[0].GetSigningKeySha256()) {
		t.Fatalf("ubuntu source = %v", sources[0])
	}
	if !slices.Equal(cfg.GetFileProvider().GetAllowedRoots(), []string{"/etc/issue.d", "/etc/motd.d"}) || !cfg.GetFileProvider().GetKernelModuleBlocklist() {
		t.Fatalf("file provider = %v", cfg.GetFileProvider())
	}
	accounts := cfg.GetAccountProvider()
	if accounts.GetMinUid() != 1000 || accounts.GetMaxUid() != 59999 || accounts.GetMinGid() != 1000 || accounts.GetMaxGid() != 59999 ||
		len(accounts.GetApprovedHomeRoots()) != 1 || accounts.GetApprovedHomeRoots()[0].GetPath() != "/home" || accounts.GetApprovedHomeRoots()[0].GetRootId() != "f0047cfe-68c5-5850-a2b5-b9adc55d4f43" {
		t.Fatalf("account provider = %v", accounts)
	}
	if !cfg.GetOsUpdateProvider().GetEnabled() {
		t.Fatal("os update provider not derived")
	}
	// kernel.sysrq is kernel authority the sysctl provider refuses; it is
	// dropped instead of disabling the provider.
	if !slices.Equal(cfg.GetSysctlProvider().GetAllowedKeys(), []string{"net.ipv4.ip_forward"}) {
		t.Fatalf("sysctl keys = %v", cfg.GetSysctlProvider().GetAllowedKeys())
	}
	firewall := cfg.GetFirewallProvider()
	var names []string
	for _, selector := range firewall.GetAllowedInterfaces() {
		names = append(names, selector.GetIfname()+"="+selector.GetPermanentMac())
	}
	if !slices.Equal(names, []string{"enp1s0=02:00:00:00:00:01", "wlp2s0=02:00:00:00:00:02"}) {
		t.Fatalf("firewall interfaces = %v", names)
	}
	settings := firewallSettings()
	if !proto.Equal(firewall.GetManagementEndpoints()[0], settings.GetManagementEndpoints()[0]) || !slices.Equal(firewall.GetDnsServers(), settings.GetDnsServers()) || !proto.Equal(cfg.GetConnectivityGuard(), settings.GetConnectivityGuard()) {
		t.Fatalf("firewall settings = %v guard %v", firewall, cfg.GetConnectivityGuard())
	}
}

func TestDeriveArchitectureSelectsVendorURI(t *testing.T) {
	host := testHost(t, "ubuntu-24.04")
	host.Architecture = "aarch64"
	effective := derive(t, &agentv1.AgentConfig{}, testRecord(true, capPackages), host)
	apt := effective.Config.GetPackageProvider().GetSources()[0].GetRepository().GetApt()
	if apt.GetUri() != "https://ports.ubuntu.com/ubuntu-ports" || !slices.Equal(apt.GetArchitectures(), []string{"arm64"}) {
		t.Fatalf("arm64 source = %v", apt)
	}
}

func TestDeriveFedoraMetalinkSource(t *testing.T) {
	effective := derive(t, &agentv1.AgentConfig{}, testRecord(true, capPackages), testHost(t, "fedora-44"))
	wantStatus(t, effective, capPackages, statusEnabled, "")
	source := effective.Config.GetPackageProvider().GetSources()[0]
	rpm := source.GetRepository().GetRpm()
	if source.GetRepository().GetRepositoryId() != "12e3a0eb-c710-58d9-bd79-a491c614754c" || rpm.GetNativeId() != "fedora" ||
		rpm.GetMetalink() != "https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64" || rpm.GetRequireMetadataSignature() || !rpm.GetRequirePackageSignature() ||
		len(rpm.GetAdditionalRepositories()) != 1 || rpm.GetAdditionalRepositories()[0].GetNativeId() != "updates" ||
		rpm.GetAdditionalRepositories()[0].GetMetalink() != "https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64" ||
		source.GetSigningKeyFile() != "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary" || source.GetRpmSigningKeyFingerprint() != "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6" {
		t.Fatalf("fedora source = %v", source)
	}
}

// EL rebuilds sign repomd.xml: BaseOS and AppStream are one source of HTTPS
// base URLs with metadata and package signatures both required.
func TestDeriveELSignedBaseURLSource(t *testing.T) {
	host := testHost(t, "rocky-9")
	host.Architecture = "aarch64"
	effective := derive(t, &agentv1.AgentConfig{}, testRecord(true, capPackages, capFiles, capAccounts), host)
	for _, c := range []agentv1.ManagementCapability{capPackages, capFiles, capAccounts} {
		wantStatus(t, effective, c, statusEnabled, "")
	}
	source := effective.Config.GetPackageProvider().GetSources()[0]
	rpm := source.GetRepository().GetRpm()
	additional := rpm.GetAdditionalRepositories()
	if source.GetRepository().GetRepositoryId() != "12e3a0eb-c710-58d9-bd79-a491c614754c" || rpm.GetNativeId() != "baseos" || rpm.GetMetalink() != "" ||
		!slices.Equal(rpm.GetBaseUrls().GetUrls(), []string{"https://dl.rockylinux.org/pub/rocky/9/BaseOS/aarch64/os/"}) ||
		!rpm.GetRequireMetadataSignature() || !rpm.GetRequirePackageSignature() || len(additional) != 1 || additional[0].GetNativeId() != "appstream" ||
		!slices.Equal(additional[0].GetBaseUrls().GetUrls(), []string{"https://dl.rockylinux.org/pub/rocky/9/AppStream/aarch64/os/"}) ||
		source.GetSigningKeyFile() != "/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9" || source.GetRpmSigningKeyFingerprint() != "21CB256AE16FC54C6E652949702D426D350D275D" {
		t.Fatalf("rocky source = %v", source)
	}
	accounts := effective.Config.GetAccountProvider()
	if !slices.Equal(effective.Config.GetFileProvider().GetAllowedRoots(), []string{"/etc/issue.d", "/etc/motd.d"}) || accounts.GetMinUid() != 1000 || accounts.GetMaxUid() != 59999 {
		t.Fatalf("rocky files %v accounts %v", effective.Config.GetFileProvider(), accounts)
	}
}

// AlmaLinux 10's x86_64_v2 build reports uname x86_64; the x86-64-v3 tree
// must not become its package source.
func TestDeriveAlmaLinux10VariantMarker(t *testing.T) {
	for name, tc := range map[string]struct {
		present func(string) bool
		status  agentv1.CapabilityStatus
		detail  string
	}{
		"x86-64-v3 build": {func(string) bool { return false }, statusEnabled, ""},
		"x86_64_v2 build": {func(path string) bool { return path == "/etc/rpm/macros.x86_64_v2" }, statusUnavailable, DetailPlatformNotQualified},
		"unobservable":    {nil, statusUnavailable, DetailPlatformNotQualified},
	} {
		t.Run(name, func(t *testing.T) {
			host := testHost(t, "almalinux-10")
			host.PathPresent = tc.present
			effective := derive(t, &agentv1.AgentConfig{}, testRecord(true, capPackages), host)
			wantStatus(t, effective, capPackages, tc.status, tc.detail)
			if tc.status == statusEnabled && !slices.Equal(effective.Config.GetPackageProvider().GetSources()[0].GetRepository().GetRpm().GetBaseUrls().GetUrls(), []string{"https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/"}) {
				t.Fatalf("alma source = %v", effective.Config.GetPackageProvider())
			}
		})
	}
}

func TestDeriveUbuntu2204Suites(t *testing.T) {
	effective := derive(t, &agentv1.AgentConfig{}, testRecord(true, capPackages), testHost(t, "ubuntu-22.04"))
	apt := effective.Config.GetPackageProvider().GetSources()[0].GetRepository().GetApt()
	if apt.GetSuite() != "jammy" || !slices.Equal(apt.GetAdditionalSuites(), []string{"jammy-updates", "jammy-security"}) || apt.GetUri() != "https://archive.ubuntu.com/ubuntu" ||
		apt.GetSigningKey().GetArtifactId() != "d74a0281-9d25-5f2c-ac6b-9d4bfa1e8c2e" {
		t.Fatalf("jammy source = %v", apt)
	}
}

func TestDeriveUnavailable(t *testing.T) {
	for name, tc := range map[string]struct {
		host       func(*Host)
		capability agentv1.ManagementCapability
		detail     string
	}{
		"unknown key bytes": {func(h *Host) {
			h.ReadVendorKey = func(string) ([]byte, error) { return []byte("replaced"), nil }
		}, capPackages, DetailVendorKeyUnrecognized},
		"absent key": {func(h *Host) {
			h.ReadVendorKey = func(string) ([]byte, error) { return nil, errors.New("absent") }
		}, capPackages, DetailVendorKeyUnrecognized},
		"unknown architecture":  {func(h *Host) { h.Architecture = "riscv64" }, capPackages, DetailPlatformNotQualified},
		"restore unit disabled": {func(h *Host) { h.FirewallRestoreReady = func() bool { return false } }, capFirewall, DetailFirewallRestoreUnitDisable},
		"no permanent interface": {func(h *Host) {
			h.Interfaces = func() ([]Interface, error) { return []Interface{{Name: "lo", Loopback: true}, {Name: "veth0"}}, nil }
		}, capFirewall, DetailNoPermanentInterface},
		"interface listing fails": {func(h *Host) {
			h.Interfaces = func() ([]Interface, error) { return nil, errors.New("sysfs") }
		}, capFirewall, DetailNoPermanentInterface},
		"unqualified release accounts": {func(h *Host) { h.Release = platform.Identify(platform.OSRelease{ID: "plan9"}) }, capAccounts, DetailPlatformNotQualified},
		"unqualified release files":    {func(h *Host) { h.Release = platform.Identify(platform.OSRelease{ID: "plan9"}) }, capFiles, DetailPlatformNotQualified},
		"unqualified release modules":  {func(h *Host) { h.Release = platform.Identify(platform.OSRelease{ID: "plan9"}) }, capModules, DetailPlatformNotQualified},
		"unqualified release sysctl":   {func(h *Host) { h.Release = platform.Identify(platform.OSRelease{ID: "plan9"}) }, capSysctl, DetailPlatformNotQualified},
		"unqualified release updates":  {func(h *Host) { h.Release = platform.Identify(platform.OSRelease{ID: "plan9"}) }, capUpdates, DetailPlatformNotQualified},
		"unqualified release firewall": {func(h *Host) { h.Release = platform.Identify(platform.OSRelease{ID: "plan9"}) }, capFirewall, DetailPlatformNotQualified},
		// Debian 12 gates OS updates; Debian's security pocket has its own
		// archive root, so no vendor archive is derived.
		"debian os update gate": {func(h *Host) { h.Release = testRelease(t, "debian-12") }, capUpdates, DetailPlatformNotQualified},
		"debian packages":       {func(h *Host) { h.Release = testRelease(t, "debian-12") }, capPackages, DetailPlatformNotQualified},
		"debian 13 packages":    {func(h *Host) { h.Release = testRelease(t, "debian-13") }, capPackages, DetailPlatformNotQualified},
		// RHEL repositories need entitlement certificates.
		"rhel packages": {func(h *Host) { h.Release = testRelease(t, "rhel-9") }, capPackages, DetailPlatformNotQualified},
		// Fedora 43's dnf5 is below the package provider floor.
		"fedora 43 packages": {func(h *Host) { h.Release = testRelease(t, "fedora-43") }, capPackages, DetailPlatformNotQualified},
	} {
		t.Run(name, func(t *testing.T) {
			host := testHost(t, "ubuntu-24.04")
			tc.host(&host)
			effective := derive(t, &agentv1.AgentConfig{}, testRecord(true, remoteCapabilities...), host)
			wantStatus(t, effective, tc.capability, statusUnavailable, tc.detail)
		})
	}
}

func TestDeriveProtectedSysctlKeysOnly(t *testing.T) {
	record := testRecord(true, capSysctl)
	record.Policy.SysctlKeys = []string{"kernel.sysrq", "vm.drop_caches"}
	effective := derive(t, &agentv1.AgentConfig{}, record, testHost(t, "ubuntu-24.04"))
	wantStatus(t, effective, capSysctl, statusUnavailable, DetailSysctlKeysProtected)
	if effective.Config.GetSysctlProvider() != nil {
		t.Fatal("protected keys produced a sysctl provider")
	}
}

func TestDeriveLocalOnly(t *testing.T) {
	local := &agentv1.AgentConfig{
		FileProvider:     &agentv1.NativeFileProviderConfig{AllowedRoots: []string{"/srv/managed"}},
		PasswordProvider: &agentv1.NativePasswordProviderConfig{},
		SysctlProvider:   &agentv1.NativeSysctlProviderConfig{AllowedKeys: []string{"vm.swappiness"}},
	}
	host := testHost(t, "ubuntu-24.04")
	for name, record := range map[string]*agentv1.CapabilityPolicyRecord{
		"absent":   nil,
		"inactive": testRecord(false, remoteCapabilities...),
	} {
		t.Run(name, func(t *testing.T) {
			effective := derive(t, local, record, host)
			if !proto.Equal(effective.Config, local) {
				t.Fatalf("local-only derivation changed providers: %v", effective.Config)
			}
			for _, c := range []agentv1.ManagementCapability{capPackages, capFiles, capModules, capAccounts, capFirewall, capUpdates} {
				wantStatus(t, effective, c, statusNotEnabled, "")
			}
			wantStatus(t, effective, capSysctl, statusLocal, "")
			wantStatus(t, effective, capPassword, statusLocal, "")
			wantStatus(t, effective, capCustom, statusLocal, "")
		})
	}
	refusing := clone(local)
	refusing.CapabilityPolicy = &agentv1.CapabilityPolicyConfig{RefuseRemote: true}
	effective := derive(t, refusing, testRecord(true, remoteCapabilities...), host)
	if !proto.Equal(effective.Config, refusing) {
		t.Fatal("refuse_remote admitted remote providers")
	}
	wantStatus(t, effective, capPackages, statusNotEnabled, "")
}

func TestDeriveLocalWins(t *testing.T) {
	localAccounts := &agentv1.NativeAccountProviderConfig{MinUid: 2000, MaxUid: 2999, MinGid: 2000, MaxGid: 2999}
	localSource := &agentv1.NativePackageSource{Repository: &resourcev1.RepositoryDesired{RepositoryId: "55555555-5555-4555-8555-555555555555"}}
	local := &agentv1.AgentConfig{
		AccountProvider: localAccounts,
		FileProvider:    &agentv1.NativeFileProviderConfig{AllowedRoots: []string{"/etc/motd.d", "/srv/managed"}},
		SysctlProvider:  &agentv1.NativeSysctlProviderConfig{AllowedKeys: []string{"vm.swappiness"}},
		PackageProvider: &agentv1.NativePackageProviderConfig{Sources: []*agentv1.NativePackageSource{localSource}},
	}
	_, err := Derive(local, testRecord(true, capAccounts, capFiles, capSysctl, capPackages), testHost(t, "ubuntu-24.04"))
	// The minimal local source is not a valid approved source, so validation
	// of the merged package provider must fail closed.
	if err == nil {
		t.Fatal("invalid local package source passed merged validation")
	}
	local.PackageProvider = nil
	effective := derive(t, local, testRecord(true, capAccounts, capFiles, capSysctl), testHost(t, "ubuntu-24.04"))
	if !proto.Equal(effective.Config.GetAccountProvider(), localAccounts) {
		t.Fatal("remote accounts replaced local account ranges")
	}
	wantStatus(t, effective, capAccounts, statusLocal, "")
	if !slices.Equal(effective.Config.GetFileProvider().GetAllowedRoots(), []string{"/etc/motd.d", "/srv/managed", "/etc/issue.d"}) {
		t.Fatalf("merged roots = %v", effective.Config.GetFileProvider().GetAllowedRoots())
	}
	wantStatus(t, effective, capFiles, statusEnabled, "")
	wantStatus(t, effective, capCustom, statusLocal, "")
	if !slices.Equal(effective.Config.GetSysctlProvider().GetAllowedKeys(), []string{"vm.swappiness", "net.ipv4.ip_forward"}) {
		t.Fatalf("merged keys = %v", effective.Config.GetSysctlProvider().GetAllowedKeys())
	}
	wantStatus(t, effective, capSysctl, statusLocal, "")
}

func TestDeriveDeterministic(t *testing.T) {
	host := testHost(t, "ubuntu-24.04")
	record := testRecord(true, remoteCapabilities...)
	first := derive(t, &agentv1.AgentConfig{}, record, host)
	for range 5 {
		next := derive(t, &agentv1.AgentConfig{}, record, host)
		if !proto.Equal(first.Config, next.Config) || len(first.Status) != len(next.Status) {
			t.Fatal("derivation is not deterministic")
		}
		for i := range first.Status {
			if !proto.Equal(first.Status[i], next.Status[i]) {
				t.Fatal("status is not deterministic")
			}
		}
	}
}

func TestDeriveRejectsInvalidRecord(t *testing.T) {
	record := testRecord(true, capFirewall)
	record.Policy.Firewall = nil
	if _, err := Derive(&agentv1.AgentConfig{}, record, testHost(t, "ubuntu-24.04")); !errors.Is(err, ErrRecord) {
		t.Fatalf("invalid record err = %v", err)
	}
}
