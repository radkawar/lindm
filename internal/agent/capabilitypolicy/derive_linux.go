//go:build linux

// Package capabilitypolicy derives the executor's effective provider
// configuration from the root-owned local configuration and the executor's
// accepted signed capability policy record. A policy carries only catalogue
// capabilities, sysctl key names and firewall endpoint/guard settings; every
// path, repository, key and account range comes from the platform registry
// compiled into the agent, and only where the running release qualifies it.
// Local settings always win. The package neither verifies signatures (the
// executor does before it stores a record) nor relaxes any provider's own
// deny lists, protected paths or custody checks.
package capabilitypolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/sysctlprovider"
	"lindm/internal/platform"
)

// Closed UNAVAILABLE details.
const (
	DetailPlatformNotQualified       = "platform_not_qualified"
	DetailVendorKeyUnrecognized      = "vendor_key_unrecognized"
	DetailFirewallSettingsMissing    = "firewall_settings_missing"
	DetailFirewallRestoreUnitDisable = "firewall_restore_unit_disabled"
	DetailNoPermanentInterface       = "no_permanent_interface"
	DetailTooManyInterfaces          = "too_many_interfaces"
	DetailSysctlKeysProtected        = "sysctl_keys_protected"
	DetailTooManySources             = "too_many_package_sources"
	DetailProtectedPathOverlap       = "protected_path_overlap"
)

const (
	maxPackageSources     = 32
	maxFirewallInterfaces = 64
	maxSysctlKeys         = 128
)

// Effective is the merged provider configuration and the per-capability
// status the executor reports.
type Effective struct {
	Config *agentv1.AgentConfig
	// Status has one entry per catalogue value 1-9, in catalogue order.
	Status []*agentv1.CapabilityObservation
	// Document is set by Effect and LoadEffectiveExecutorConfig: the loaded
	// executor document whose Proto is Config and whose ProtectedPaths cover
	// the merged providers.
	Document *config.Document
}

var configValidator = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(&agentv1.AgentConfig{}, &agentv1.CapabilityObservation{}), protovalidate.WithDisableLazy())
})

// Derive merges providers derived from an active record into local. A nil or
// inactive record, or a local capability_policy (refuse_remote), yields the
// local configuration only. The result is deterministic for the same inputs
// and host observations; local is not modified.
func Derive(local *agentv1.AgentConfig, record *agentv1.CapabilityPolicyRecord, host Host) (*Effective, error) {
	if local == nil {
		return nil, errors.New("capability derivation requires the local configuration")
	}
	if record != nil {
		if err := validateRecord(record); err != nil {
			return nil, err
		}
	}
	d := &derivation{local: local, merged: proto.CloneOf(local), host: host}
	if record.GetActive() && local.GetCapabilityPolicy() == nil {
		d.policy = record.GetPolicy()
	}
	effective := &Effective{Config: d.merged}
	for value := agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES; value <= agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_CUSTOM_FILE_ROOTS; value++ {
		effective.Status = append(effective.Status, d.capability(value))
	}
	validator, err := configValidator()
	if err != nil {
		return nil, fmt.Errorf("compile capability derivation rules: %w", err)
	}
	for _, message := range []proto.Message{d.merged.GetPackageProvider(), d.merged.GetFileProvider(), d.merged.GetSysctlProvider(), d.merged.GetAccountProvider(), d.merged.GetFirewallProvider(), d.merged.GetConnectivityGuard(), d.merged.GetOsUpdateProvider()} {
		if message.ProtoReflect().IsValid() {
			if err := validator.Validate(message); err != nil {
				return nil, fmt.Errorf("derived provider configuration: %w", err)
			}
		}
	}
	for _, status := range effective.Status {
		if err := validator.Validate(status); err != nil {
			return nil, fmt.Errorf("capability status: %w", err)
		}
	}
	return effective, nil
}

type derivation struct {
	local  *agentv1.AgentConfig
	merged *agentv1.AgentConfig
	policy *agentv1.AgentCapabilityPolicy
	host   Host
}

func (d *derivation) granted(c agentv1.ManagementCapability) bool {
	return d.policy != nil && slices.Contains(d.policy.GetCapabilities(), c)
}

func status(c agentv1.ManagementCapability, s agentv1.CapabilityStatus, detail string) *agentv1.CapabilityObservation {
	return &agentv1.CapabilityObservation{Capability: c, Status: s, Detail: detail}
}

// capability merges one capability; local settings win and are never removed.
func (d *derivation) capability(c agentv1.ManagementCapability) *agentv1.CapabilityObservation {
	local := d.localGrant(c)
	if !d.granted(c) {
		if local {
			return status(c, agentv1.CapabilityStatus_CAPABILITY_STATUS_LOCAL, "")
		}
		return status(c, agentv1.CapabilityStatus_CAPABILITY_STATUS_NOT_ENABLED, "")
	}
	detail := d.derive(c, local)
	switch {
	case local:
		return status(c, agentv1.CapabilityStatus_CAPABILITY_STATUS_LOCAL, "")
	case detail != "":
		return status(c, agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE, detail)
	default:
		return status(c, agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED, "")
	}
}

// localGrant reports whether executor.json itself grants the capability.
func (d *derivation) localGrant(c agentv1.ManagementCapability) bool {
	l := d.local
	switch c {
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES:
		return l.GetPackageProvider() != nil
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES:
		roots := d.release().StandardFileRoots
		return len(roots) > 0 && !slices.ContainsFunc(roots, func(root string) bool { return !coveredRoot(l.GetFileProvider().GetAllowedRoots(), root) })
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_MODULE_BLOCKLIST:
		return l.GetFileProvider().GetKernelModuleBlocklist()
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_LOCAL_ACCOUNTS:
		return l.GetAccountProvider() != nil
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL:
		return l.GetFirewallProvider() != nil
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_OS_UPDATES:
		return l.GetOsUpdateProvider() != nil
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_SETTINGS:
		return l.GetSysctlProvider() != nil
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PASSWORD_POLICY:
		return l.GetPasswordProvider() != nil
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_CUSTOM_FILE_ROOTS:
		standard := d.release().StandardFileRoots
		return slices.ContainsFunc(l.GetFileProvider().GetAllowedRoots(), func(root string) bool { return !coveredRoot(standard, root) })
	}
	return false
}

func (d *derivation) release() *platform.Release {
	if d.host.Release == nil {
		return platform.Identify(platform.OSRelease{})
	}
	return d.host.Release
}

// qualified reports whether the release implements the platform capability on
// this architecture.
func (d *derivation) qualified(c platform.Capability) bool {
	return d.release().GateReasonOn(c, d.host.Architecture) == ""
}

// derive fills the merged providers for a granted capability and returns the
// UNAVAILABLE detail, or "" when derived. A local grant keeps local settings;
// only additive capabilities (packages, files, kernel settings) merge.
func (d *derivation) derive(c agentv1.ManagementCapability, local bool) string {
	switch c {
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES:
		return d.packages()
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES:
		return d.files()
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_MODULE_BLOCKLIST:
		return d.moduleBlocklist(local)
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_LOCAL_ACCOUNTS:
		return d.accounts(local)
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL:
		return d.firewall(local)
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_OS_UPDATES:
		return d.osUpdates(local)
	case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_SETTINGS:
		return d.sysctl()
	}
	// Local-only capabilities are never granted by a validated policy.
	return DetailPlatformNotQualified
}

func (d *derivation) files() string {
	roots := d.release().StandardFileRoots
	if len(roots) == 0 || !d.qualified(platform.Dispatch) {
		return DetailPlatformNotQualified
	}
	provider := d.fileProvider()
	for _, root := range roots {
		if !coveredRoot(provider.AllowedRoots, root) {
			provider.AllowedRoots = append(provider.AllowedRoots, root)
		}
	}
	return ""
}

func (d *derivation) moduleBlocklist(local bool) string {
	tools := d.release().ModuleBlocklist
	if tools.Rebuild == "" || tools.Modprobe == "" || !d.qualified(platform.Dispatch) {
		return DetailPlatformNotQualified
	}
	if !local {
		d.fileProvider().KernelModuleBlocklist = true
	}
	return ""
}

func (d *derivation) fileProvider() *agentv1.NativeFileProviderConfig {
	if d.merged.FileProvider == nil {
		d.merged.FileProvider = &agentv1.NativeFileProviderConfig{}
	}
	return d.merged.FileProvider
}

func (d *derivation) accounts(local bool) string {
	defaults := d.release().Accounts
	if defaults.HomeRootID == "" || defaults.HomeRoot == "" || !d.qualified(platform.Accounts) {
		return DetailPlatformNotQualified
	}
	if !local {
		d.merged.AccountProvider = &agentv1.NativeAccountProviderConfig{
			ApprovedHomeRoots: []*agentv1.NativeApprovedHomeRoot{{RootId: defaults.HomeRootID, Path: defaults.HomeRoot}},
			MinUid:            defaults.MinUID, MaxUid: defaults.MaxUID, MinGid: defaults.MinGID, MaxGid: defaults.MaxGID,
		}
	}
	return ""
}

func (d *derivation) osUpdates(local bool) string {
	if !d.qualified(platform.OSUpdate) {
		return DetailPlatformNotQualified
	}
	if !local {
		d.merged.OsUpdateProvider = &agentv1.NativeOSUpdateProviderConfig{Enabled: true}
	}
	return ""
}

// sysctl unions the policy's keys into the allowed keys. Keys the provider
// refuses as kernel authority are dropped so they cannot disable the provider.
func (d *derivation) sysctl() string {
	if !d.qualified(platform.Sysctl) {
		return DetailPlatformNotQualified
	}
	var keys []string
	for _, key := range d.policy.GetSysctlKeys() {
		if !sysctlprovider.AuthorityKey(key) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return DetailSysctlKeysProtected
	}
	provider := d.merged.GetSysctlProvider()
	if provider == nil {
		provider = &agentv1.NativeSysctlProviderConfig{}
		d.merged.SysctlProvider = provider
	}
	for _, key := range keys {
		if !slices.Contains(provider.AllowedKeys, key) && len(provider.AllowedKeys) < maxSysctlKeys {
			provider.AllowedKeys = append(provider.AllowedKeys, key)
		}
	}
	return ""
}

// firewall derives the zone provider and connectivity guard from the policy's
// deployment settings and the host's permanent interfaces.
func (d *derivation) firewall(local bool) string {
	if local {
		return ""
	}
	settings := d.policy.GetFirewall()
	if settings == nil {
		return DetailFirewallSettingsMissing
	}
	if !d.qualified(platform.Firewall) {
		return DetailPlatformNotQualified
	}
	if d.host.FirewallRestoreReady == nil || !d.host.FirewallRestoreReady() {
		return DetailFirewallRestoreUnitDisable
	}
	if d.host.Interfaces == nil {
		return DetailNoPermanentInterface
	}
	interfaces, err := d.host.Interfaces()
	if err != nil {
		return DetailNoPermanentInterface
	}
	var selectors []*resourcev1.InterfaceSelector
	for _, item := range interfaces {
		if item.Loopback || item.PermanentMAC == "" {
			continue
		}
		selectors = append(selectors, &resourcev1.InterfaceSelector{Identity: &resourcev1.InterfaceSelector_PermanentMac{PermanentMac: item.PermanentMAC}, Ifname: proto.String(item.Name)})
	}
	if len(selectors) == 0 {
		return DetailNoPermanentInterface
	}
	if len(selectors) > maxFirewallInterfaces {
		return DetailTooManyInterfaces
	}
	slices.SortFunc(selectors, func(a, b *resourcev1.InterfaceSelector) int { return strings.Compare(a.GetIfname(), b.GetIfname()) })
	d.merged.FirewallProvider = &agentv1.NativeFirewallProviderConfig{
		AllowedInterfaces:   selectors,
		ManagementEndpoints: cloneAll(settings.GetManagementEndpoints()),
		DnsServers:          slices.Clone(settings.GetDnsServers()),
	}
	if d.merged.ConnectivityGuard == nil {
		d.merged.ConnectivityGuard = proto.CloneOf(settings.GetConnectivityGuard())
	}
	return ""
}

func cloneAll[T proto.Message](items []T) []T {
	result := make([]T, 0, len(items))
	for _, item := range items {
		result = append(result, proto.CloneOf(item))
	}
	return result
}

// packages appends the release's vendor archives as approved sources; a local
// source with the same repository identity wins.
func (d *derivation) packages() string {
	release := d.release()
	if len(release.VendorRepositories) == 0 || !d.qualified(platform.Packages) {
		return DetailPlatformNotQualified
	}
	var sources []*agentv1.NativePackageSource
	for _, vendor := range release.VendorRepositories {
		source, detail := d.vendorSource(release, vendor)
		if detail != "" {
			return detail
		}
		sources = append(sources, source)
	}
	provider := d.merged.GetPackageProvider()
	if provider == nil {
		provider = &agentv1.NativePackageProviderConfig{}
		d.merged.PackageProvider = provider
	}
	for _, source := range sources {
		if slices.ContainsFunc(provider.Sources, func(existing *agentv1.NativePackageSource) bool {
			return existing.GetRepository().GetRepositoryId() == source.GetRepository().GetRepositoryId()
		}) {
			continue
		}
		if len(provider.Sources) == maxPackageSources {
			return DetailTooManySources
		}
		provider.Sources = append(provider.Sources, source)
	}
	return ""
}

func (d *derivation) vendorSource(release *platform.Release, vendor platform.VendorRepository) (*agentv1.NativePackageSource, string) {
	if vendor.DB != release.Native().Packages.Backend.PackageDB() || vendor.KeyFile == "" || vendor.KeyArtifactID == "" {
		return nil, DetailPlatformNotQualified
	}
	for _, marker := range vendor.VariantMarkers {
		if d.host.PathPresent == nil || d.host.PathPresent(marker) {
			return nil, DetailPlatformNotQualified
		}
	}
	if d.host.ReadVendorKey == nil {
		return nil, DetailVendorKeyUnrecognized
	}
	key, err := d.host.ReadVendorKey(vendor.KeyFile)
	if err != nil || len(key) == 0 {
		return nil, DetailVendorKeyUnrecognized
	}
	digest := sha256.Sum256(key)
	if !slices.Contains(vendor.KeySHA256, hex.EncodeToString(digest[:])) {
		return nil, DetailVendorKeyUnrecognized
	}
	artifact := &resourcev1.ArtifactRef{Sha256: digest[:], SizeBytes: uint64(len(key)), ArtifactId: vendor.KeyArtifactID}
	repository := &resourcev1.RepositoryDesired{RepositoryId: vendor.RepositoryID, Presence: resourcev1.Presence_PRESENCE_PRESENT}
	source := &agentv1.NativePackageSource{Repository: repository, SigningKeyFile: filepath.Clean(vendor.KeyFile), SigningKeySha256: digest[:]}
	switch vendor.DB {
	case platform.PackageDBDpkg:
		uri := vendor.ArchiveURIs[d.host.Architecture]
		architecture := debianArchitecture(d.host.Architecture)
		if uri == "" || architecture == "" || len(vendor.Suites) == 0 {
			return nil, DetailPlatformNotQualified
		}
		repository.Source = &resourcev1.RepositoryDesired_Apt{Apt: &resourcev1.AptRepository{
			Uri: uri, Suite: vendor.Suites[0], AdditionalSuites: slices.Clone(vendor.Suites[1:]),
			Components: slices.Clone(vendor.Components), Architectures: []string{architecture}, SigningKey: artifact,
		}}
	case platform.PackageDBRPM:
		if len(vendor.NativeRepositories) == 0 || vendor.RPMFingerprint == "" {
			return nil, DetailPlatformNotQualified
		}
		rpm := &resourcev1.RpmRepository{SigningKeys: []*resourcev1.ArtifactRef{artifact}, RequireMetadataSignature: !vendor.MetadataUnsigned, RequirePackageSignature: true}
		for i, native := range vendor.NativeRepositories {
			// Base URLs only with signed metadata; metalinks only where the
			// release pins their host (checked below).
			var urls *resourcev1.RepositoryURLs
			metalink := native.Metalinks[d.host.Architecture]
			if base := native.BaseURLs[d.host.Architecture]; len(base) != 0 && !vendor.MetadataUnsigned {
				urls, metalink = &resourcev1.RepositoryURLs{Urls: slices.Clone(base)}, ""
			}
			if urls == nil && metalink == "" {
				return nil, DetailPlatformNotQualified
			}
			switch {
			case i == 0 && urls != nil:
				rpm.NativeId, rpm.Location = native.ID, &resourcev1.RpmRepository_BaseUrls{BaseUrls: urls}
			case i == 0:
				rpm.NativeId, rpm.Location = native.ID, &resourcev1.RpmRepository_Metalink{Metalink: metalink}
			case urls != nil:
				rpm.AdditionalRepositories = append(rpm.AdditionalRepositories, &resourcev1.RpmAdditionalRepository{NativeId: native.ID, Location: &resourcev1.RpmAdditionalRepository_BaseUrls{BaseUrls: urls}})
			default:
				rpm.AdditionalRepositories = append(rpm.AdditionalRepositories, &resourcev1.RpmAdditionalRepository{NativeId: native.ID, Location: &resourcev1.RpmAdditionalRepository_Metalink{Metalink: metalink}})
			}
		}
		if !config.RPMMetadataTrusted(release, rpm) {
			return nil, DetailPlatformNotQualified
		}
		repository.Source = &resourcev1.RepositoryDesired_Rpm{Rpm: rpm}
		source.RpmSigningKeyFingerprint = vendor.RPMFingerprint
	default:
		return nil, DetailPlatformNotQualified
	}
	return source, ""
}

func debianArchitecture(machine string) string {
	switch machine {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	}
	return ""
}

// coveredRoot reports whether path is one of roots or inside one of them.
func coveredRoot(roots []string, path string) bool {
	return slices.ContainsFunc(roots, func(root string) bool { return within(path, root) })
}

func within(path, root string) bool { return path == root || strings.HasPrefix(path, root+"/") }
