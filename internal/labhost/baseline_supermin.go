// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// superminDirectory holds the private readable appliance kernel beneath a host
// work directory. Ubuntu installs /boot/vmlinuz-* root-only; libguestfs then
// cannot build its appliance as the lab user, and /boot must not be relaxed.
const superminDirectory = "supermin"

// BaselineSuperminKernel is the staged copy of the running kernel's own signed
// package payload. DpkgMD5 is dpkg's recorded digest of the installed /boot
// file; the copy is published only when its bytes match that record.
type BaselineSuperminKernel struct {
	Release     string `json:"release"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	DpkgMD5     string `json:"dpkg_md5"`
	ModulesPath string `json:"modules_path"`
}

// baselineSuperminScript downloads linux-image-<running release> at its exact
// installed version through the reviewed official source only (APT verifies the
// package against the signed index) and extracts only the kernel image. It runs
// as the unprivileged lab user, never reads /boot and never changes host files
// outside the private work directory. modulesRoot is /lib/modules on hosts.
func baselineSuperminScript(work, modulesRoot string) string {
	return "umask 077\nwork=" + baselineQuote(work) + "\nmodules_root=" + baselineQuote(modulesRoot) + "\nopts=(" + baselineAPTOptions + ")\n" + `rel=$(uname -r)
[[ $rel =~ ^[A-Za-z0-9._+~-]+$ ]] || { echo 'supermin kernel: unsupported kernel release name' >&2; exit 1; }
pkg=linux-image-$rel
read -r status version < <(dpkg-query -W -f='${db:Status-Status} ${Version}\n' -- "$pkg")
[[ $status == installed && -n $version ]] || { echo "supermin kernel: running kernel is not the installed package $pkg" >&2; exit 1; }
md5=$(dpkg-query --control-show "$pkg" md5sums | awk -v member="boot/vmlinuz-$rel" '$2 == member { print $1 }')
[[ $md5 =~ ^[0-9a-f]{32}$ ]] || { echo "supermin kernel: dpkg has no single digest for /boot/vmlinuz-$rel" >&2; exit 1; }
modules=$modules_root/$rel
[[ -d $modules && ! -L $modules ]] || { echo "supermin kernel: $modules is not an installed module directory" >&2; exit 1; }
dir=$work/` + superminDirectory + `
[[ -e $dir || -L $dir ]] || mkdir -m 0700 -- "$dir"
[[ -d $dir && ! -L $dir && -O $dir && $(stat -c %a -- "$dir") == 700 ]] || { echo 'supermin kernel directory must be a real run-user-owned mode-0700 directory' >&2; exit 1; }
stage=$(mktemp -d -- "$dir/.stage-XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
cd -- "$stage"
apt-get "${opts[@]}" download -- "$pkg=$version" >&2
debs=(./*.deb)
[[ ${#debs[@]} == 1 && -f ${debs[0]} && ! -L ${debs[0]} ]] || { echo 'supermin kernel: expected exactly one downloaded package' >&2; exit 1; }
dpkg-deb --fsys-tarfile "${debs[0]}" | tar -xOf - "./boot/vmlinuz-$rel" > vmlinuz
printf '%s  vmlinuz\n' "$md5" | md5sum --check --quiet --strict - >&2 || { echo "supermin kernel: downloaded payload differs from installed /boot/vmlinuz-$rel" >&2; exit 1; }
sha=$(sha256sum -- vmlinuz)
chmod 0600 vmlinuz
mv -f -- vmlinuz "$dir/vmlinuz-$rel"
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$rel" "$pkg" "$version" "$dir/vmlinuz-$rel" "${sha%% *}" "$md5" "$modules"
`
}

func parseBaselineSupermin(output []byte) (*BaselineSuperminKernel, error) {
	text, ok := strings.CutSuffix(string(output), "\n")
	fields := strings.Split(text, "\t")
	if !ok || len(fields) != 7 || strings.Contains(text, "\n") {
		return nil, errors.New("labhost: malformed supermin kernel staging result")
	}
	kernel := &BaselineSuperminKernel{Release: fields[0], Package: fields[1], Version: fields[2], Path: fields[3], SHA256: fields[4], DpkgMD5: fields[5], ModulesPath: fields[6]}
	if len(kernel.SHA256) != 64 || strings.Trim(kernel.SHA256, "0123456789abcdef") != "" || filepath.Base(kernel.Path) != "vmlinuz-"+kernel.Release {
		return nil, errors.New("labhost: invalid supermin kernel staging result")
	}
	return kernel, nil
}

// ExportSuperminEnvironment sets SUPERMIN_KERNEL/SUPERMIN_MODULES for this
// process and its children when the baseline staged a private copy of the
// running kernel under work. An operator-supplied override is left unchanged,
// and a stale copy for another release is never selected.
func ExportSuperminEnvironment(work string) error {
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return err
	}
	return exportSuperminEnvironment(work, strings.TrimSpace(string(release)), "/lib/modules")
}

func exportSuperminEnvironment(work, release, modulesRoot string) error {
	if os.Getenv("SUPERMIN_KERNEL") != "" || os.Getenv("SUPERMIN_MODULES") != "" {
		return nil
	}
	pairs, err := superminEnvironment(work, release, modulesRoot)
	if err != nil {
		return err
	}
	for _, pair := range pairs {
		name, value, _ := strings.Cut(pair, "=")
		if err := os.Setenv(name, value); err != nil {
			return err
		}
	}
	return nil
}

func superminEnvironment(work, release, modulesRoot string) ([]string, error) {
	if release == "" || strings.ContainsAny(release, "/\x00") || release == "." || release == ".." {
		return nil, errors.New("labhost: invalid running kernel release")
	}
	kernel := filepath.Join(work, superminDirectory, "vmlinuz-"+release)
	info, err := os.Lstat(kernel)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("labhost: staged supermin kernel %s must be a private regular file", kernel)
	}
	modules := filepath.Join(modulesRoot, release)
	if info, err := os.Stat(modules); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("labhost: staged supermin kernel %s has no installed module directory %s", release, modules)
	}
	return []string{"SUPERMIN_KERNEL=" + kernel, "SUPERMIN_MODULES=" + modules}, nil
}
