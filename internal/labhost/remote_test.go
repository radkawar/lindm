package labhost

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReturnedEvidenceDoesNotOverwriteExistingRecord(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "downloaded.json")
	destination := filepath.Join(root, "evidence.json")
	if err := os.WriteFile(source, []byte("new record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("retained record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishRecord(source, destination); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing evidence not refused: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "retained record\n" {
		t.Fatal("existing record was changed")
	}
	fresh := filepath.Join(root, "fresh.json")
	if err := publishRecord(source, fresh); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("evidence mode = %v", info.Mode())
	}
}
