// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIPackageHasNoServicesConfigurationOrLifecycle(t *testing.T) {
	requireNativeTools(t, "dpkg-deb")
	work := t.TempDir()
	p := cliProduct()
	payload, staged, digest := stageProductFixture(t, work, p)
	artifact, err := buildDEB(t.Context(), work, payload, "1.2.3", Architecture{Debian: "amd64"}, DefaultSourceDateEpoch, staged, digest, p)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.UnsignedSHA256 == "" || artifact.UnsignedSHA256 != artifact.SHA256 {
		t.Fatal("unsigned DEB archive digest missing")
	}
	extract := filepath.Join(work, "extracted")
	if _, _, err := runTool(t.Context(), work, toolCmd{Name: "dpkg-deb", Args: []string{"--raw-extract", artifact.Path, extract}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"DEBIAN/postinst", "DEBIAN/prerm", "DEBIAN/postrm", "DEBIAN/conffiles", "etc/lindm/agent.json", "etc/lindm/server.json", "usr/lib/systemd/system/lindmd.service", "usr/lib/systemd/system/lindm-agent.service"} {
		if _, err := os.Stat(filepath.Join(extract, path)); !os.IsNotExist(err) {
			t.Fatalf("CLI package owns unexpected resource %s: %v", path, err)
		}
	}
	control, err := os.ReadFile(filepath.Join(extract, "DEBIAN", "control"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(control), "Depends: systemd") {
		t.Fatal("CLI unnecessarily requires a service manager")
	}
	if _, err := os.Stat(filepath.Join(extract, "usr/bin/lindmctl")); err != nil {
		t.Fatal(err)
	}
	spec, err := writeSpec(work, payload, "1.2.3", Architecture{RPM: "aarch64"}, DefaultSourceDateEpoch, staged, p)
	if err != nil {
		t.Fatal(err)
	}
	rpmSpec, err := os.ReadFile(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Requires: systemd", "%posttrans", "%preun", "%postun", "/bin/sh"} {
		if strings.Contains(string(rpmSpec), forbidden) {
			t.Fatalf("CLI RPM has unwanted lifecycle %s", forbidden)
		}
	}
}
