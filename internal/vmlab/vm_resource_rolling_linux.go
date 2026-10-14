// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Pacman repositories expose one version per package. Each phase selects an
// independently signed immutable fixture repository, not a made-up versionlock.
func selectALPMFixture(ctx context.Context, vm *guestVM, desired *resourcev1.ResourceDesiredState) error {
	pkg := desired.GetNativePackage()
	if pkg.GetPackage().GetEcosystem() != resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM || pkg.GetExact() == nil {
		return nil
	}
	version := pkg.GetExact().GetAlpm().GetPkgver()
	if version != "1.0" && version != "2.0" {
		return nil // The unavailable-version scenario must remain unavailable.
	}
	data, err := vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 128<<10, 15*time.Second)
	if err != nil {
		return err
	}
	config := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(data, config); err != nil {
		return err
	}
	sources := config.GetPackageProvider().GetSources()
	if len(sources) != 1 || sources[0].GetRepository().GetAlpm() == nil {
		return errors.New("ALPM fixture source missing")
	}
	repository := sources[0].GetRepository().GetAlpm()
	uri := "https://127.0.0.1:18449/" + version
	if repository.GetSnapshotUri() == uri {
		return nil
	}
	repository.SnapshotUri = uri
	data, err = protojson.Marshal(config)
	if err != nil {
		return err
	}
	_, err = vm.run(ctx, "sudo -n /bin/sh -eu -c 'umask 077; cat > /etc/lindm/resource-config.upload; install -o root -g root -m 0600 /etc/lindm/resource-config.upload /etc/lindm/executor.json; rm /etc/lindm/resource-config.upload; systemctl restart lindm-executor.service'", bytes.NewReader(data), 16384, time.Minute)
	if err != nil {
		return err
	}
	_, err = waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	return err
}

func rollingPackageOracle(rpm resourcePackaging, version string, present bool) string {
	if rpm.pacman {
		command := "pacman -Q " + resourceDependencyName + "; "
		if present {
			command += "test \"$(pacman -Q " + resourcePackageName + ")\" = " + nativeQuote(resourcePackageName+" "+version+"-1") + "; pacman -Qi " + resourcePackageName + "; pacman-conf IgnorePkg | grep -Fx " + resourcePackageName + "; cat /etc/pacman.conf; "
			other := "2.0"
			if version == "2.0" {
				other = "1.0"
			}
			archive := resourceFixtureRoot + "/repo/" + resourcePackageName + "-" + other + "-1-" + rpm.nativeArch() + ".pkg.tar.zst"
			command += nativeQuote(nativeGuestDir+"/lab-probe") + " guest alpm-lock-boundary " + nativeQuote(archive) + "; "
		} else {
			command += "if pacman -Q " + resourcePackageName + "; then exit 1; fi; if pacman-conf IgnorePkg | grep -Fx " + resourcePackageName + "; then exit 1; fi; "
		}
		return command
	}
	command := "rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\\n' " + resourceDependencyName + "; "
	if present {
		command += "test \"$(rpm -q --qf '%{VERSION}' " + resourcePackageName + ")\" = " + nativeQuote(version) + "; rpm -q " + resourcePackageName + "; " + zypperPinOracle(rpm, version)
	} else {
		command += "if rpm -q " + resourcePackageName + "; then exit 1; fi; if test -e /etc/zypp/locks && grep -F " + nativeQuote("# lindm:rpm/"+resourcePackageName+"/") + " /etc/zypp/locks; then exit 1; fi; "
	}
	return command
}

// Query libzypp's actual PoolQuery matches, including an authenticated universe
// containing alternate EVRs and noarch witnesses. Rendering bytes is not proof
// of a lock's native meaning.
func zypperPinOracle(packages resourcePackaging, version string) string {
	directory := resourceFixtureRoot + "/zypp-lock-oracle"
	repo := "[lindm-resource-lab]\nname=Disposable native lock oracle\nbaseurl=https://127.0.0.1:18449\nenabled=1\nautorefresh=0\ngpgcheck=1\nrepo_gpgcheck=1\npkg_gpgcheck=1\ngpgkey=file://" + resourceFixtureRoot + "/repository.asc\n"
	cli := "zypper --non-interactive --xmlout --reposd-dir " + nativeQuote(directory+"/repos") + " --cache-dir " + nativeQuote(directory+"/cache")
	other := "2.0"
	if version == "2.0" {
		other = "1.0"
	}
	probe := `import sys, xml.etree.ElementTree as ET
directory, name, dependency, arch, wanted, other = sys.argv[1:]
def read(name):
    root = ET.parse(directory + '/' + name).getroot()
    assert not [n for n in root.iter('message') if n.get('type') in ('error', 'warning')], 'incomplete native query'
    return root
def identity(node):
    return (node.get('name'), node.get('arch'), node.get('edition', '').removeprefix('0:'))
read('refresh.xml') # retain/check native refresh, omit timing-only progress from state comparison
universe = {identity(n) for n in read('universe.xml').iter('solvable')}
required = {(name, arch, wanted+'-1'), (name, arch, other+'-1'), (name, 'noarch', other+'-1'), (dependency, arch, other+'-1')}
assert required <= universe, ('incomplete signed native query universe', required-universe)
matches = {identity(n) for n in read('locks.xml').iter('match')}
assert (name, arch, other+'-1') in matches, 'alternate EVR is not locked'
assert (name, arch, wanted+'-1') not in matches, 'wanted EVR is locked'
assert not any(n == dependency and a == arch for n,a,v in matches), 'unrelated same-architecture package is locked'
assert not any(n == name and a == 'noarch' for n,a,v in matches), 'other architecture is locked'
print('native-zypp-lock-name-architecture-evr-conjunction')
`
	return "mkdir -p " + nativeQuote(directory+"/repos") + "; printf '%s' " + nativeQuote(repo) + " > " + nativeQuote(directory+"/repos/fixture.repo") + "; " +
		"if ! " + cli + " refresh --force > " + nativeQuote(directory+"/refresh.xml") + "; then cat " + nativeQuote(directory+"/refresh.xml") + "; exit 1; fi; " +
		cli + " --no-refresh search --details --match-exact " + resourcePackageName + " " + resourceDependencyName + " > " + nativeQuote(directory+"/universe.xml") + "; " +
		cli + " --no-refresh locks --solvables > " + nativeQuote(directory+"/locks.xml") + "; " +
		"python3 -I -c " + nativeQuote(probe) + " " + nativeQuote(directory) + " " + resourcePackageName + " " + resourceDependencyName + " " + nativeQuote(packages.nativeArch()) + " " + nativeQuote(version) + " " + nativeQuote(other) + "; " +
		"cat " + nativeQuote(directory+"/universe.xml") + " " + nativeQuote(directory+"/locks.xml") + " /etc/zypp/locks; "
}
