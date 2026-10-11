//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// prepareRebootPrerequisite uses a real vendor package transaction when an
// up-to-date desktop has no pending reboot. It never writes a reboot marker or
// substitutes the oracle, and does not claim a newer/security version upgrade.
func prepareRebootPrerequisite(ctx context.Context, vm *guestVM, rpm resourcePackaging, proof *VMRebootPolicyResult) error {
	before, err := nativeRebootOracle(rpm)(ctx, vm)
	if err != nil {
		return err
	}
	before.Name = "before-reboot-prerequisite"
	proof.Prerequisite = append(proof.Prerequisite, before)
	proof.PrerequisiteBoundary = "Pre-existing native reboot requirement; no newer/security package upgrade is claimed by reboot qualification."
	if nativeRecordLine(before, "reboot-required ") == "reboot-required yes" {
		return nil
	}
	proof.PrerequisiteBoundary = "Native vendor-authenticated reinstallation of the exact installed running-kernel package set is used only to establish the reboot prerequisite. This is not a newer/security version upgrade or an EFI-signature qualification; no synthetic reboot marker or replacement oracle is used."
	result, err := vm.runResult(ctx, "sudo -n /bin/sh -eu -c "+nativeQuote(rebootKernelReinstallScript(rpm))+" 2>&1", nil, 4<<20, 15*time.Minute)
	if len(result.Stdout) != 0 {
		proof.Prerequisite = append(proof.Prerequisite, resourceNativeRecord("vendor-kernel-reinstallation", result.Stdout))
	}
	if err != nil {
		return fmt.Errorf("vendor kernel reinstallation prerequisite: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("vendor kernel reinstallation prerequisite exited %d", result.ExitCode)
	}
	after, err := nativeRebootOracle(rpm)(ctx, vm)
	if err != nil {
		return err
	}
	after.Name = "after-reboot-prerequisite"
	proof.Prerequisite = append(proof.Prerequisite, after)
	if nativeRecordLine(after, "reboot-required ") != "reboot-required yes" {
		return errors.New("real kernel reinstallation did not establish native reboot-required; qualification cannot proceed")
	}
	return nil
}

func rebootKernelReinstallScript(rpm resourcePackaging) string {
	if !rpm.rpm {
		return `export LC_ALL=C DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
kernel=$(uname -r)
image="/boot/vmlinuz-$kernel"
owner=$(dpkg-query --search "$image")
package=${owner%%: /*}
test "$owner" = "$package: $image"
version=$(dpkg-query -W -f '${Version}' "$package")
printf 'running-kernel %s\n' "$kernel"
dpkg-query -W -f 'before ${binary:Package} ${Version} ${Architecture}\n' "$package"
sha256sum "$image"
apt-get -q -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false -o Debug::Acquire::gpgv=true update
apt-cache policy "$package"
apt-cache show "$package=$version"
apt-get -y -q -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false -o Debug::pkgAcquire::Auth=true --reinstall install "$package=$version"
dpkg-query -W -f 'after ${binary:Package} ${Version} ${Architecture}\n' "$package"
sha256sum "$image"
`
	}
	dnf := "dnf5"
	if rpm.dnf4 {
		dnf = "dnf"
	}
	return `export LC_ALL=C
kernel=$(uname -r)
printf 'running-kernel %s\n' "$kernel"
if packages=$(` + dnf + ` -q repoquery --installed --whatprovides "kernel-uname-r = $kernel" --queryformat '%{name}-%{version}-%{release}.%{arch}\n'); then
  :
else
  printf 'installed running-kernel query failed:\n%s\n' "$packages"
  exit 1
fi
printf 'installed running-kernel providers:\n%s\n' "$packages"
test -n "$packages"
set --
while IFS= read -r package; do
  test -n "$package" || continue
  set -- "$@" "$package"
done <<PACKAGES
$packages
PACKAGES
test "$#" -gt 0
printf 'selinux '
getenforce
printf 'before native package identities/signatures\n'
rpm -qi "$@"
` + dnf + ` -q repoquery --info "$@"
private=$(mktemp -d /var/tmp/lindm-reboot-kernel-XXXXXX)
trap 'rm -rf -- "$private"' EXIT
` + dnf + ` -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 download --destdir "$private" "$@"
for archive in "$private"/*.rpm; do
  test -f "$archive"
  rpmkeys --checksig --verbose "$archive"
  sha256sum "$archive"
done
` + dnf + ` -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 reinstall "$private"/*.rpm
printf 'after native package identities/signatures\n'
rpm -qi "$@"
`
}
