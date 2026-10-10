//go:build linux

package nativehelper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// A retained observer directory (for example after a stopped verification
// unit) must not make every later observation fail: before the fix, entry
// metadata was resolved relative to the executor's working directory.
func TestObservationDirectoryAdmitsRetainedObserver(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	retained := uuid.NewString()
	if err := os.MkdirAll(filepath.Join(state, "resource-observations", retained), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(state, "resource-observations"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	id := uuid.NewString()
	directory, err := observationDirectory(t.Context(), nil, state, id)
	if err != nil {
		t.Fatalf("retained observer blocked a new observation: %v", err)
	}
	if directory != filepath.Join(state, "resource-observations", id) {
		t.Fatalf("unexpected observation directory %s", directory)
	}
	for _, name := range []string{retained, id} {
		if info, err := os.Stat(filepath.Join(state, "resource-observations", name)); err != nil || !info.IsDir() {
			t.Fatalf("observer %s not retained: %v", name, err)
		}
	}
}
