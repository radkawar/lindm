package custody

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadRootFollowsNoLinksAndRequiresRootAncestry(t *testing.T) {
	data, err := ReadRoot("/usr/lib/os-release", 1<<20, true)
	if err != nil || len(data) == 0 {
		t.Fatalf("vendor os-release: %d bytes, %v", len(data), err)
	}
	// /etc/os-release is a symlink on every supported distribution.
	if info, err := os.Lstat("/etc/os-release"); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if _, err := ReadRoot("/etc/os-release", 1<<20, true); !errors.Is(err, unix.ELOOP) {
			t.Fatalf("symlink leaf: %v", err)
		}
	}
	// t.TempDir lives under world-writable /tmp, or a user-owned directory.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRoot(file, 1, true); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("replaceable ancestry: %v", err)
	}
	for _, path := range []string{"relative", "/usr/../etc/passwd", "/"} {
		if _, _, err := OpenRoot(path, unix.O_PATH); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%q: %v", path, err)
		}
	}
	if _, err := ReadRoot("/usr/lib/os-release", 1, true); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("oversized read: %v", err)
	}
}

func TestOwnedRejectsSharedAndLinkedLeaves(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(dir, "private")
	shared := filepath.Join(dir, "shared")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(private, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shared, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Owned(dir, true); err != nil {
		t.Fatalf("private directory: %v", err)
	}
	if _, err := Owned(private, false); err != nil {
		t.Fatalf("private file: %v", err)
	}
	for path, directory := range map[string]bool{shared: false, link: false, private: true, dir: false} {
		if _, err := Owned(path, directory); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s directory=%t: %v", path, directory, err)
		}
	}
}
