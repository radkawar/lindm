//go:build linux

package vmlab

import (
	"context"
	"time"
)

func resourceFixtureEvidence(ctx context.Context, packages *nativeGuestPackages) ([]VMResourceNativeRecord, error) {
	command := "cd " + resourceFixtureRoot + "; cat keys.colons; sha256sum repository.asc repository.gpg https.crt; "
	if packages.family == familyDNF {
		command += "gpgv --keyring " + resourceFixtureRoot + "/repository.gpg repo/repodata/repomd.xml.asc repo/repodata/repomd.xml; sha256sum repo/repodata/* repo/*.rpm; rpm --version; dnf5 --version; python3 -c 'import libdnf5; print(libdnf5.__file__)'"
	} else {
		command += "gpgv --keyring " + resourceFixtureRoot + "/repository.gpg repo/dists/stable/InRelease; sha256sum repo/dists/stable/InRelease repo/dists/stable/Release repo/dists/stable/Release.gpg repo/dists/stable/main/binary-*/Packages repo/*.deb; dpkg --version; apt-get --version"
	}
	record, err := resourceOracle(ctx, packages.vm, "native-signed-repository-toolchain", command)
	if err != nil {
		return nil, err
	}
	// This root-local protobuf config contains public source trust and allowed
	// roots, not keys or enrollment secrets. It is distinct from signed policy.
	config, err := packages.vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 128<<10, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return []VMResourceNativeRecord{record, resourceNativeRecord("root-provisioned-public-resource-config", config)}, nil
}
