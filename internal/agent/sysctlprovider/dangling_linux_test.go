// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sysctlprovider

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lindm/internal/custody"
)

// Tumbleweed's systemd ships /usr/lib/sysctl.d/99-sysctl.conf ->
// ../../../etc/sysctl.conf and no /etc/sysctl.conf. systemd-sysctl skips the
// dangling link, which still overrides the same name in later directories;
// reading it must not fail every sysctl resource.
func TestDanglingConfigurationLinkOverridesWithoutContent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-protected sysctl.d fixtures require root")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	high, low := filepath.Join(root, "etc-sysctl.d"), filepath.Join(root, "usr-lib-sysctl.d")
	for _, dir := range []string{high, low} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../absent/sysctl.conf", filepath.Join(high, "99-sysctl.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(low, "99-sysctl.conf"), []byte("net.ipv4.ip_forward = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(low, "50-default.conf"), []byte("net.ipv4.ip_forward = 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := readConfigurationFrom([]string{high, low})
	if errors.Is(err, custody.ErrUnsafe) || errors.Is(err, ErrConflict) {
		t.Skip("custody needs a root-protected TMPDIR ancestry (not a sticky /tmp)")
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[1].path != filepath.Join(high, "99-sysctl.conf") || files[1].data != nil || files[1].masked {
		t.Fatalf("configuration = %+v", files)
	}
	got, err := effectivePersistence(files, "net.ipv4.ip_forward")
	if err != nil {
		t.Fatal(err)
	}
	if got.value == nil || *got.value != "0" || got.source == nil || *got.source != filepath.Join(low, "50-default.conf") {
		t.Fatalf("effective persistence %+v: the dangling link must override the lower 99-sysctl.conf", got)
	}
}
