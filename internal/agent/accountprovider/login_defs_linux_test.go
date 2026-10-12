//go:build linux

package accountprovider

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Tumbleweed's shadow (libeconf vendor directory) ships /usr/etc/login.defs
// and drop-ins, with no /etc/login.defs; the hook check failed every account
// resource with "no such file or directory".
func TestLoginDefsSourcesIncludeVendorDirectoryAndDropins(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loginDefsSources(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent login.defs: %v", err)
	}
	write("usr/etc/login.defs", "UID_MIN 1000\n#USERDEL_CMD /usr/sbin/userdel_local\n")
	write("etc/login.defs.d/login_defs-4.20.3-1.1.noarch", "")
	write("usr/etc/login.defs.d/50-vendor.defs", "SYS_UID_MAX 499\n")
	write("etc/login.defs.d/90-site.defs", "USERADD_CMD /usr/local/sbin/hook\n")
	sources, err := loginDefsSources(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(root, "usr/etc/login.defs"), filepath.Join(root, "usr/etc/login.defs.d/50-vendor.defs"), filepath.Join(root, "etc/login.defs.d/90-site.defs")}
	if !slices.Equal(sources, want) {
		t.Fatalf("sources %q, want %q", sources, want)
	}
	write("etc/login.defs", "UID_MIN 1000\n")
	if sources, err := loginDefsSources(root); err != nil || sources[0] != filepath.Join(root, "etc/login.defs") || sources[1] != filepath.Join(root, "usr/etc/login.defs") {
		t.Fatalf("sources %q: %v", sources, err)
	}
	for content, hook := range map[string]bool{"UID_MIN 1000\n#USERDEL_CMD /x\n": false, "USERADD_CMD /usr/local/sbin/hook\n": true, "  USERDEL_CMD\t/x\n": true} {
		if loginDefsHook([]byte(content)) != hook {
			t.Fatalf("hook(%q) != %t", content, hook)
		}
	}
}
