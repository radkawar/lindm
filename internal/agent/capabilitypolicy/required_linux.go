// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capabilitypolicy

import (
	"slices"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// RequiredCapability names the capability a desired resource needs that the
// effective configuration does not provide, or UNSPECIFIED (0) when its
// provider is effective. It only selects a refusal; providers still apply
// their own deny lists and preconditions. Kinds that need no capability
// (services, systemd definitions, encryption compliance, SSH banner) return 0.
func RequiredCapability(desired *resourcev1.ResourceDesiredState, effective *agentv1.AgentConfig, host Host) agentv1.ManagementCapability {
	switch desired.GetRef().GetKind() {
	case resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE:
		repository := desired.GetNativePackage().GetRepository()
		if !slices.ContainsFunc(effective.GetPackageProvider().GetSources(), func(source *agentv1.NativePackageSource) bool {
			return repository.GetCanonicalKey() == sourceKey(source)
		}) {
			return agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE:
		file := desired.GetManagedFile()
		if file.GetKernelModuleBlocklist() != nil {
			if !effective.GetFileProvider().GetKernelModuleBlocklist() {
				return agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_MODULE_BLOCKLIST
			}
			return 0
		}
		path := file.GetPath()
		if slices.ContainsFunc(effective.GetFileProvider().GetAllowedRoots(), func(root string) bool { return path != root && within(path, root) }) {
			return 0
		}
		if host.Release != nil && slices.ContainsFunc(host.Release.StandardFileRoots, func(root string) bool { return path != root && within(path, root) }) {
			return agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES
		}
		return agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_CUSTOM_FILE_ROOTS
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP:
		if effective.GetAccountProvider() == nil {
			return agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_LOCAL_ACCOUNTS
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE:
		if effective.GetFirewallProvider() == nil {
			return agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY:
		if effective.GetOsUpdateProvider() == nil {
			return agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_OS_UPDATES
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL:
		if !slices.Contains(effective.GetSysctlProvider().GetAllowedKeys(), desired.GetSysctl().GetKey()) {
			return agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_SETTINGS
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY:
		if effective.GetPasswordProvider() == nil {
			return agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PASSWORD_POLICY
		}
	}
	return 0
}

// sourceKey is the package repository canonical key of an approved source.
func sourceKey(source *agentv1.NativePackageSource) string {
	repository := source.GetRepository()
	switch {
	case repository.GetApt() != nil:
		return "apt/" + repository.GetRepositoryId()
	case repository.GetRpm() != nil:
		return "rpm/" + repository.GetRepositoryId()
	case repository.GetAlpm() != nil:
		return "alpm/" + repository.GetRepositoryId()
	}
	return ""
}
