//go:build linux

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestPacmanDescExactIdentity(t *testing.T) {
	for _, version := range []string{"1.2.3-4", "2:1.2.3-4", "0:1.0.r12-1"} {
		input := "%NAME%\nexample\n\n%VERSION%\n" + version + "\n\n%ARCH%\nany\n\n%DEPENDS%\nfoo\nbar\n\n"
		pkg, status := parsePacmanDesc(context.Background(), strings.NewReader(input))
		if status != success || pkg.Name != "example" || pkg.Version != version || pkg.Architecture != "any" || pkg.Manager != "pacman" {
			t.Fatalf("identity lost: %v %v", pkg, status)
		}
	}
}

func TestPacmanDescRejectsIncompleteIdentity(t *testing.T) {
	valid := "%NAME%\nexample\n\n%VERSION%\n1:2.0-3\n\n%ARCH%\nx86_64\n\n"
	for _, input := range []string{
		strings.ReplaceAll(valid, "%ARCH%\nx86_64\n\n", ""),
		valid + "%NAME%\nother\n\n",
		strings.ReplaceAll(valid, "1:2.0-3", "bad:2.0-3"),
		strings.ReplaceAll(valid, "example\n", "example\nother\n"),
		strings.TrimSuffix(valid, "\n\n"),
		strings.ReplaceAll(valid, "example", strings.Repeat("x", maxLineBytes)),
	} {
		if pkg, status := parsePacmanDesc(context.Background(), strings.NewReader(input)); status == success || pkg != nil {
			t.Fatalf("accepted invalid database record: %v", status)
		}
	}
}

func TestPacmanDatabaseBoundsAndLinks(t *testing.T) {
	root := t.TempDir()
	pkgdir := filepath.Join(root, "example-1.0-1")
	if err := os.Mkdir(pkgdir, 0755); err != nil {
		t.Fatal(err)
	}
	desc := filepath.Join(pkgdir, "desc")
	if err := os.WriteFile(desc, []byte("%NAME%\nexample\n\n%VERSION%\n1.0-1\n\n%ARCH%\nx86_64\n\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if pkgs, status := collectPacman(context.Background(), root, parseLimits{10, 4096}); status != success || len(pkgs) != 1 {
		t.Fatalf("valid local database: %v %v", pkgs, status)
	}
	for _, limits := range []parseLimits{{0, 4096}, {10, 8}} {
		if pkgs, status := collectPacman(context.Background(), root, limits); status != capacity || pkgs != nil {
			t.Fatalf("limit leaked partial inventory: %v %v", pkgs, status)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if pkgs, status := collectPacman(ctx, root, parseLimits{10, 4096}); status == success || pkgs != nil {
		t.Fatal("cancellation accepted")
	}
	if err := os.Remove(desc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", desc); err != nil {
		t.Fatal(err)
	}
	if pkgs, status := collectPacman(context.Background(), root, parseLimits{10, 4096}); status == success || pkgs != nil {
		t.Fatal("followed desc symlink")
	}
}

func TestArchBackendDoesNotInventRelease(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	selected, status := selectBackend(map[string]string{"ID": "arch"}, func(string) (os.FileInfo, error) { return info, nil })
	if status != success || selected.name != "pacman" {
		t.Fatalf("rolling database unavailable: %v %v", selected, status)
	}
}

func TestArchPackageIdentityAcceptsOnlyNativeAbsentVersion(t *testing.T) {
	for _, tc := range []struct {
		id      string
		status  inventoryv1.CollectionStatus
		allowed bool
	}{
		{"arch", unavailable, true},
		{"arch", invalid, false},
		{"arch", inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED, false},
		{"debian", unavailable, false},
		{"debian", success, true},
		{"", unavailable, false},
	} {
		host := &inventoryv1.HostObservation{
			OsId:      &inventoryv1.ObservedString{Status: success, Value: tc.id},
			OsVersion: &inventoryv1.ObservedString{Status: tc.status},
		}
		if got := nativePackageIdentityAvailable(host); got != tc.allowed {
			t.Errorf("%q %v allowed=%v want=%v", tc.id, tc.status, got, tc.allowed)
		}
		host.OsId.Status = invalid
		if nativePackageIdentityAvailable(host) {
			t.Error("accepted unsuccessful distribution identity")
		}
	}
}
