// SPDX-License-Identifier: Apache-2.0

//go:build linux

package fileprovider

import (
	"path/filepath"
	"slices"
	"strings"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
)

func allowedPath(config *agentv1.NativeFileProviderConfig, path string) error {
	if path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return ErrUnsafePath
	}
	// Local allowlists cannot delegate another typed provider's authority. Broad
	// native code, state, identity and credential namespaces are never file roots.
	for _, prefix := range []string{
		"/bin", "/sbin", "/lib", "/lib64", "/usr", "/boot", "/dev", "/proc", "/sys", "/run", "/root", "/home", "/tmp", "/var/tmp",
		"/etc/lindm", "/var/lib/lindm", "/var/cache/lindm", "/var/log/lindm", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid", "/etc/subgid", "/etc/security", "/etc/pam.d", "/etc/pam.conf", "/etc/authselect", "/etc/nsswitch.conf", "/etc/sssd", "/etc/krb5.conf", "/etc/krb5.conf.d", "/etc/krb5.keytab", "/etc/sudoers", "/etc/sudoers.d", "/etc/polkit-1", "/etc/ssh", "/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/ca-certificates.conf",
		"/etc/systemd", "/etc/init", "/etc/init.d", "/etc/rc.d", "/etc/rc.local", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/crontab", "/etc/at.allow", "/etc/at.deny", "/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh", "/etc/environment", "/etc/environment.d", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ld.so.preload",
		"/etc/apt", "/etc/dpkg", "/etc/dnf", "/etc/yum.conf", "/etc/yum.repos.d", "/etc/rpm", "/etc/pacman.conf", "/etc/pacman.d", "/etc/zypp", "/etc/nix", "/etc/nixos", "/etc/selinux", "/etc/apparmor", "/etc/apparmor.d", "/etc/audit", "/etc/udev", "/etc/modules", "/etc/modules-load.d", "/etc/modprobe.d", "/etc/sysctl.conf", "/etc/sysctl.d", "/etc/fstab", "/etc/crypttab", "/etc/default", "/etc/sysconfig", "/etc/NetworkManager", "/etc/network", "/etc/resolv.conf", "/etc/firewalld", "/etc/nftables.conf", "/etc/ufw",
		"/var/lib/dpkg", "/var/lib/rpm", "/var/lib/dnf", "/var/lib/apt", "/var/lib/pacman", "/var/lib/AccountsService", "/var/lib/sss", "/var/lib/systemd", "/var/lib/selinux", "/var/lib/polkit-1", "/var/spool", "/var/cache", "/var/log",
	} {
		if within(path, prefix) {
			return ErrUnsafePath
		}
	}
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") || strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".socket") || strings.HasSuffix(base, ".timer") || strings.HasSuffix(base, ".path") || strings.HasSuffix(base, ".mount") || strings.Contains(strings.ToLower(base), "private_key") {
		return ErrUnsafePath
	}
	for _, root := range config.GetAllowedRoots() {
		if root != "/" && root != "/etc" && root != "/var" && filepath.IsAbs(root) && filepath.Clean(root) == root && path != root && within(path, root) {
			return nil
		}
	}
	return ErrUnsafePath
}
func within(path, root string) bool { return path == root || strings.HasPrefix(path, root+"/") }

// creatableRoot returns the approved root the provider may create for path:
// only when path sits directly inside an entry of allowed_roots. A deeper
// file, or a root above an absent ancestor, is never created.
func creatableRoot(config *agentv1.NativeFileProviderConfig, desired *resourcev1.ManagedFileDesired) (string, bool) {
	if desired.GetKernelModuleBlocklist() != nil || allowedPath(config, desired.GetPath()) != nil {
		return "", false
	}
	directory := filepath.Dir(desired.GetPath())
	return directory, slices.Contains(config.GetAllowedRoots(), directory)
}

// releasedRecordedRoot names the directory a RESTORE_OWNED release that leaves
// the file absent may remove: the one the last-applied image recorded this
// resource created, which must be the file's own directory.
func releasedRecordedRoot(desired *resourcev1.ManagedFileDesired, ledger *agentv1.ResourceOwnershipLedger, target *agentv1.ResourceOwnershipSnapshot, operation resourcev1.ResourceOperation) (string, bool) {
	recorded := ledger.GetLastApplied().GetCreatedDirectory()
	if operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE || recorded == "" || ledger.GetOwner().GetPolicy().GetRelease() != resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED || target.GetObservation().GetManagedFile().GetExists() || desired.GetKernelModuleBlocklist() != nil {
		return "", false
	}
	return recorded, recorded == filepath.Dir(desired.GetPath())
}

// releasedCreatedRoot additionally requires the recorded directory to still
// be an approved root under the local configuration.
func releasedCreatedRoot(config *agentv1.NativeFileProviderConfig, desired *resourcev1.ManagedFileDesired, ledger *agentv1.ResourceOwnershipLedger, target *agentv1.ResourceOwnershipSnapshot, operation resourcev1.ResourceOperation) (string, bool) {
	recorded, ok := releasedRecordedRoot(desired, ledger, target, operation)
	if !ok {
		return "", false
	}
	root, ok := creatableRoot(config, desired)
	return root, ok && root == recorded
}

// EffectWritePaths is the transient effect unit's writable set. Normally only
// the file's directory is writable; the root's parent is granted only when
// the effect creates the absent root or releases one lindm recorded creating.
// The helper re-derives and checks the target before any write.
func EffectWritePaths(request *agentv1.NativeResourceTransactionRequest, desired *resourcev1.ManagedFileDesired) ([]string, error) {
	directory := filepath.Dir(desired.GetPath())
	if root := request.GetTarget().GetCreatedDirectory(); root != "" && request.GetPlan().GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && !request.GetBefore().GetObservation().GetManagedFile().GetExists() {
		if root != directory || desired.GetKernelModuleBlocklist() != nil {
			return nil, ErrConflict
		}
		_, absent, err := nativefile.DirectoryAbsent(root)
		if err != nil {
			return nil, err
		}
		if absent {
			return []string{filepath.Dir(root)}, nil
		}
	}
	if root, ok := releasedRecordedRoot(desired, request.GetOwnership(), request.GetTarget(), request.GetPlan().GetOperation()); ok {
		return []string{filepath.Dir(root)}, nil
	}
	return []string{directory}, nil
}
