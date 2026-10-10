//go:build linux

package fileprovider

import (
	"path/filepath"
	"strings"

	agentv1 "lindm/gen/lindm/agent/v1"
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
