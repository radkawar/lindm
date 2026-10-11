package devlab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOwnedEnforcesCustodyAndBound(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, size int, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, make([]byte, size), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if data, err := readOwned(write("private", maxFixtureFile, 0o600)); err != nil || len(data) != maxFixtureFile {
		t.Fatalf("private fixture file: %d bytes, %v", len(data), err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "private"), link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"oversized":      write("oversized", maxFixtureFile+1, 0o600),
		"group readable": write("shared", 1, 0o640),
		"symlink":        link,
		"directory":      dir,
	} {
		if _, err := readOwned(path); err == nil {
			t.Errorf("%s fixture file accepted", name)
		}
	}
}
