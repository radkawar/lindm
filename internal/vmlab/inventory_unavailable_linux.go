//go:build linux

package vmlab

import (
	"slices"

	"lindm/internal/platform"
)

// This is the maintained not-applicable allowlist, not an error suppression list.
// Every entry names an exact schema field, the native package databases it
// applies to (nil: every registry release with a native backend) and a reason.
// Repeated paths apply only to that field of each item, never its siblings.
// Capability predicates prevent missing LUKS metadata, installed application
// backends and present TPMs from being mistaken for absent optional features.
// New distros and fields fail closed until reviewed here. No failure status other
// than UNAVAILABLE is eligible, even when all independent observations agree.
var inventoryUnavailableRules = []struct {
	dbs    []platform.PackageDB
	path   string
	reason string
	when   func(inventoryHealthContext) bool
}{
	{nil, "host.hardware_serial", "QEMU SMBIOS may omit a system serial; this is not disk targeting identity.", func(c inventoryHealthContext) bool {
		return c.host.GetHardwareVendor().GetStatus() == truthSuccess && c.host.GetHardwareVendor().GetValue() == "QEMU"
	}},
	{nil, "host.os_version", "Rolling os-release without VERSION_ID does not define a version.", func(c inventoryHealthContext) bool { return c.release.Version.Rule == platform.VersionAbsent }},
	{nil, "host.details.cpu.x86_64_level", "The x86-64 feature level is inapplicable to an aarch64 CPU.", func(c inventoryHealthContext) bool { return c.host.GetArchitecture().GetValue() == "aarch64" }},
	{nil, "host.details.firmware.secure_boot", "Legacy BIOS has no UEFI SecureBoot variable.", func(c inventoryHealthContext) bool { return c.details.GetFirmware().GetMode().GetValue() == "bios" }},
	{nil, "host.details.tpm.version", "No TPM version exists when a successful presence observation is false.", func(c inventoryHealthContext) bool {
		return c.details.GetTpm().GetPresent().GetStatus() == truthSuccess && !c.details.GetTpm().GetPresent().GetValue()
	}},
	{nil, "host.details.flatpak", "The Flatpak application inventory is inapplicable when its backend is not installed.", func(c inventoryHealthContext) bool {
		return c.details.GetBackends().GetFlatpak().GetStatus() == truthSuccess && !c.details.GetBackends().GetFlatpak().GetValue()
	}},
	{nil, "host.details.snap", "The Snap application inventory is inapplicable when its backend is not installed.", func(c inventoryHealthContext) bool {
		return c.details.GetBackends().GetSnap().GetStatus() == truthSuccess && !c.details.GetBackends().GetSnap().GetValue()
	}},
	{inventoryNonRPM, "host.details.platform.cpe", "Non-RPM stock os-release files need not publish CPE_NAME.", nil},
	{nil, "host.details.platform.releasever_lock", "A releasever override is optional; absence does not imply a native repository read failure.", nil},
	{nil, "host.details.platform.repositories", "The RPM/DNF repository capability is inapplicable to a native non-RPM or zypper system.", inventoryNonDNFPlatform},
	{nil, "host.details.platform.releasever", "An effective DNF releasever is inapplicable to a native non-RPM or zypper system.", inventoryNonDNFPlatform},
	{[]platform.PackageDB{platform.PackageDBDpkg}, "packages.packages.module", "dpkg packages have no RPM MODULARITYLABEL.", func(c inventoryHealthContext) bool { return c.pkg.GetManager() == "dpkg" }},
	{[]platform.PackageDB{platform.PackageDBPacman}, "packages.packages.module", "pacman packages have no RPM MODULARITYLABEL.", func(c inventoryHealthContext) bool { return c.pkg.GetManager() == "pacman" }},
	{[]platform.PackageDB{platform.PackageDBRPM, platform.PackageDBPacman}, "packages.packages.origin", "RPM and pacman packages have no APT index origin evidence.", func(c inventoryHealthContext) bool {
		return c.pkg.GetManager() == "rpm" || c.pkg.GetManager() == "pacman"
	}},
	{nil, "host.details.storage.devices.parent", "Whole disks and virtual devices without a parent have no parent name.", func(c inventoryHealthContext) bool { return c.block.GetType().GetValue() != "part" }},
	{nil, "host.details.storage.devices.filesystem", "Unformatted media and partition-table containers have no filesystem type.", nil},
	{nil, "host.details.storage.devices.mountpoint", "Unmounted media and backing devices are not mounted filesystems.", nil},
	{nil, "host.details.storage.devices.identity.transport", "Loop, device-mapper and virtual devices need not expose a transport.", nil},
	{nil, "host.details.storage.devices.identity.model", "virtio-blk and software devices do not require a hardware model.", nil},
	{nil, "host.details.storage.devices.identity.serial", "Stock virtio-blk disks need not have a configured serial; targeting must use a separate supported identity basis.", nil},
	{nil, "host.details.storage.devices.identity.firmware", "virtio-blk and software devices do not expose drive firmware revisions.", nil},
	{nil, "host.details.storage.devices.identity.wwn", "virtio-blk disks do not provide SCSI WWNs.", nil},
	{nil, "host.details.storage.devices.identity.eui", "Non-NVMe devices need not provide an IEEE EUI.", nil},
	{nil, "host.details.storage.devices.identity.partition_uuid", "Whole disks and non-GPT partitions need not have a partition UUID.", nil},
	{nil, "host.details.storage.devices.identity.partition_type", "Whole disks and non-GPT partitions need not have a GPT partition type.", nil},
	{nil, "host.details.storage.devices.identity.gpt_disk_guid", "Non-GPT media and devices without a unique GPT backing disk have no disk GUID.", nil},
	{nil, "host.details.storage.devices.identity.filesystem_uuid", "Unformatted media and LUKS containers have no filesystem UUID.", nil},
	{nil, "host.details.storage.devices.identity.luks_uuid", "Non-LUKS devices have no LUKS UUID.", inventoryNotLUKS},
	{nil, "host.details.storage.devices.identity.luks_version", "Non-LUKS devices have no LUKS version.", inventoryNotLUKS},
	{nil, "host.details.storage.devices.identity.luks_keyslot_count", "Non-LUKS devices have no keyslot metadata.", inventoryNotLUKS},
	{nil, "host.details.storage.devices.identity.luks_token_count", "Non-LUKS devices have no token metadata.", inventoryNotLUKS},
	{nil, "host.details.storage.devices.identity.luks_token_types", "No token type exists for non-LUKS devices or a successfully observed empty token set.", func(c inventoryHealthContext) bool {
		return inventoryNotLUKS(c) || (c.block.GetIdentity().GetLuksTokenCount().GetStatus() == truthSuccess && c.block.GetIdentity().GetLuksTokenCount().GetValue() == 0)
	}},
	{nil, "host.details.storage.devices.identity.backing_disk", "Loop and zram devices have no physical backing disk.", func(c inventoryHealthContext) bool {
		return c.block.GetType().GetValue() == "loop" || c.block.GetType().GetValue() == "zram"
	}},
	{nil, "host.details.storage.devices.identity.nvme", "NVMe sanitize scope is inapplicable to non-NVMe transport and non-disk devices.", func(c inventoryHealthContext) bool {
		return c.block.GetIdentity().GetTransport().GetValue() != "nvme" || c.block.GetType().GetValue() != "disk"
	}},
}

// These are os-release IDs, not distribution-family prefixes or wildcards.
var inventoryNonRPM = []platform.PackageDB{platform.PackageDBDpkg, platform.PackageDBPacman}

func inventoryNotLUKS(c inventoryHealthContext) bool {
	return c.block != nil && c.block.GetFilesystem().GetValue() != "crypto_LUKS" && c.block.GetIdentity().GetLuksUuid().GetStatus() != truthSuccess
}

func inventoryNonDNFPlatform(c inventoryHealthContext) bool {
	backends := c.details.GetBackends()
	switch c.release.Native().Packages.Backend {
	case platform.BackendAPT:
		return backends.GetDpkg().GetStatus() == truthSuccess && backends.GetDpkg().GetValue() && backends.GetRpm().GetStatus() == truthSuccess && !backends.GetRpm().GetValue()
	case platform.BackendPacman:
		return backends.GetPacman().GetStatus() == truthSuccess && backends.GetPacman().GetValue() && backends.GetRpm().GetStatus() == truthSuccess && !backends.GetRpm().GetValue()
	case platform.BackendZypper:
		return backends.GetZypper().GetStatus() == truthSuccess && backends.GetZypper().GetValue()
	default:
		return false
	}
}

func inventoryUnavailableReason(context inventoryHealthContext, path string) string {
	db := context.release.Native().Packages.Backend.PackageDB()
	if db == platform.PackageDBNone {
		return ""
	}
	for _, rule := range inventoryUnavailableRules {
		if rule.path == path && (rule.dbs == nil || slices.Contains(rule.dbs, db)) && (rule.when == nil || rule.when(context)) {
			return rule.reason
		}
	}
	return ""
}
