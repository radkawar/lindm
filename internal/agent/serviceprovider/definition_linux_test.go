//go:build linux

package serviceprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDefinitionRejectsUnsafePathsAndCounts(t *testing.T) {
	for _, path := range []string{"", "relative.service", "/nul\x00.service", "/" + string(bytes.Repeat([]byte{'x'}, maxDefinitionPath))} {
		if file, _, _, err := openDefinition(path); err == nil {
			_ = file.Close()
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
	if _, err := definitionHash(context.Background(), "/unused", make([]string, maxDefinitionFiles)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("excessive drop-ins accepted: %v", err)
	}
	// Even a sticky writable directory is not trusted definition ancestry.
	directory := t.TempDir()
	if err := os.Chmod(directory, os.ModeSticky|0777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "unit.service")
	if err := os.WriteFile(path, []byte("[Service]\nType=simple\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if file, _, _, err := openDefinition(path); err == nil {
		_ = file.Close()
		t.Fatal("untrusted/writable definition ancestry accepted")
	}
}

func TestDefinitionReadDetectsMetadataChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unit.service")
	if err := os.WriteFile(path, []byte("[Service]\nType=simple\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if err := hashFile(context.Background(), sha256.New(), file, stat, make([]byte, 32)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changing definition accepted: %v", err)
	}
}

func TestDefinitionRejectsUnreportedBytes(t *testing.T) {
	// procfs exposes regular, root-owned files with bytes beyond st_size.
	// Metadata stability alone must not authorize an empty hash of those bytes.
	file, _, stat, err := openDefinition("/proc/version")
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("procfs is not mounted")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if stat.Size != 0 {
		t.Skip("procfs version file reports its content length")
	}
	var probe [1]byte
	if n, err := file.ReadAt(probe[:], 0); n != 1 || err != nil {
		t.Fatalf("procfs fixture does not expose bytes beyond its reported size: n=%d err=%v", n, err)
	}
	var buffer [32]byte
	if err := hashFile(context.Background(), sha256.New(), file, stat, buffer[:]); !errors.Is(err, ErrConflict) {
		t.Fatalf("unreported definition bytes accepted: %v", err)
	}
}

func TestDefinitionHashesEmptyFileAndHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.conf")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	h := sha256.New()
	if err := hashFile(context.Background(), h, file, stat, buffer[:]); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(nil)
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("empty regular definition hash changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := hashFile(ctx, sha256.New(), file, stat, buffer[:]); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled empty definition read accepted: %v", err)
	}
}

func TestDefinitionRejectsLegacyIncludes(t *testing.T) {
	for _, input := range []string{
		".include /unbound.conf\n",
		"[Service]\n \t.include relative.conf\n",
		"\xef\xbb\xbf.include /unbound.conf\n",
		"# earlier physical line\x00.include /unbound.conf\n",
		".include\\\n /unbound.conf\n",
		" \\\n.include /unbound.conf\n",
	} {
		t.Run(input, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "unit.service")
			if err := os.WriteFile(path, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			var stat unix.Stat_t
			if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
				t.Fatal(err)
			}
			// Keep tokens and BOM bytes split across reads.
			var buffer [2]byte
			if err := hashFile(context.Background(), sha256.New(), file, stat, buffer[:]); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unbound legacy include accepted: %v", err)
			}
		})
	}
}

func TestDefinitionHashesOrdinaryIncludeMentions(t *testing.T) {
	const input = "# .include in a comment\n[Unit]\nDescription=Text mentioning .include\n; .include in another comment\n[Service]\nExecStart=/usr/bin/sleep infinity\n"
	path := filepath.Join(t.TempDir(), "unit.service")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	var buffer [2]byte
	h := sha256.New()
	if err := hashFile(context.Background(), h, file, stat, buffer[:]); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(input))
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("ordinary definition bytes changed during include screening")
	}
}

func rootDefinitionDirectory(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("trusted native definition boundary requires root-owned test ancestry")
	}
	directory, err := os.MkdirTemp("/run", "lindm-definition-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	return directory
}

func TestTrustedDefinitionHashAndVendorSymlink(t *testing.T) {
	directory := rootDefinitionDirectory(t)
	vendor := filepath.Join(directory, "vendor")
	if err := os.Mkdir(vendor, 0755); err != nil {
		t.Fatal(err)
	}
	fragment := filepath.Join(vendor, "unit.service")
	if err := os.WriteFile(fragment, []byte("[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("vendor", filepath.Join(directory, "lib")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "lib", "unit.service")
	file, canonical, _, err := openDefinition(alias)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if canonical != fragment {
		t.Fatalf("resolved %q, want %q", canonical, fragment)
	}
	first := filepath.Join(vendor, "10-first.conf")
	second := filepath.Join(vendor, "20-second.conf")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("[Service]\nRemainAfterExit=yes\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	base, err := definitionHash(context.Background(), alias, []string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := definitionHash(context.Background(), alias, []string{first, second})
	if err != nil || !bytes.Equal(base, repeated) {
		t.Fatalf("unchanged definition hash drifted: %v", err)
	}
	reordered, err := definitionHash(context.Background(), alias, []string{second, first})
	if err != nil || bytes.Equal(base, reordered) {
		t.Fatalf("ordered paths not bound: %v", err)
	}
	if err := os.WriteFile(second, []byte("[Service]\nRemainAfterExit=no\n"), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := definitionHash(context.Background(), alias, []string{first, second})
	if err != nil || bytes.Equal(base, changed) {
		t.Fatalf("definition bytes not bound: %v", err)
	}
	if err := os.Chmod(vendor, 0775); err != nil {
		t.Fatal(err)
	}
	if _, err := definitionHash(context.Background(), alias, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("writable resolved vendor ancestry accepted: %v", err)
	}
}

func TestTrustedDefinitionRejectsOriginalSymlinkAncestry(t *testing.T) {
	directory := rootDefinitionDirectory(t)
	fragment := filepath.Join(directory, "unit.service")
	if err := os.WriteFile(fragment, []byte("[Service]\nType=simple\n"), 0644); err != nil {
		t.Fatal(err)
	}
	untrusted := filepath.Join(directory, "untrusted")
	if err := os.Mkdir(untrusted, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(untrusted, 0777); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(untrusted, "alias.service")
	if err := os.Symlink(fragment, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := definitionHash(context.Background(), alias, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("symlink through untrusted original ancestry accepted: %v", err)
	}
	if err := os.Chmod(fragment, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := definitionHash(context.Background(), fragment, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("writable regular definition accepted: %v", err)
	}
}
