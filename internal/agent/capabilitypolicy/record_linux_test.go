//go:build linux

package capabilitypolicy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

func stateDirectory(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// t.TempDir's leaf honours the umask; the record custody refuses any
	// group-writable ancestor.
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "state")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestRecordRoundTrip(t *testing.T) {
	directory := stateDirectory(t)
	if record, err := LoadRecord(directory); record != nil || err != nil {
		t.Fatalf("absent record = %v, %v", record, err)
	}
	record := testRecord(true, capPackages, capFirewall)
	if err := StoreRecord(directory, record); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(RecordPath(directory))
	if err != nil || info.Mode() != 0600 {
		t.Fatalf("record mode = %v, %v", info, err)
	}
	loaded, err := LoadRecord(directory)
	if err != nil || !proto.Equal(loaded, record) {
		t.Fatalf("loaded = %v, %v", loaded, err)
	}
	replacement := testRecord(false, capPackages)
	if err := StoreRecord(directory, replacement); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadRecord(directory); err != nil || !proto.Equal(loaded, replacement) {
		t.Fatalf("replaced = %v, %v", loaded, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("state directory retains temporary files: %v %v", entries, err)
	}
}

func TestRecordCustody(t *testing.T) {
	valid, err := proto.Marshal(testRecord(true, capPackages))
	if err != nil {
		t.Fatal(err)
	}
	for name, prepare := range map[string]func(t *testing.T, directory string){
		"group readable": func(t *testing.T, directory string) {
			write(t, RecordPath(directory), valid, 0640)
		},
		"symlink": func(t *testing.T, directory string) {
			target := filepath.Join(filepath.Dir(directory), "elsewhere")
			write(t, target, valid, 0600)
			if err := os.Symlink(target, RecordPath(directory)); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, directory string) {
			other := filepath.Join(directory, "other")
			write(t, other, valid, 0600)
			if err := os.Link(other, RecordPath(directory)); err != nil {
				t.Fatal(err)
			}
		},
		"oversized": func(t *testing.T, directory string) {
			write(t, RecordPath(directory), bytes.Repeat([]byte{0}, maxRecordBytes+1), 0600)
		},
		"undecodable": func(t *testing.T, directory string) {
			write(t, RecordPath(directory), []byte{0xff, 0xff, 0xff}, 0600)
		},
		"invalid": func(t *testing.T, directory string) {
			record := testRecord(true, capPackages)
			record.PolicyEnvelope = nil
			data, err := proto.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			write(t, RecordPath(directory), data, 0600)
		},
		"directory": func(t *testing.T, directory string) {
			if err := os.Mkdir(RecordPath(directory), 0700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := stateDirectory(t)
			prepare(t, directory)
			if record, err := LoadRecord(directory); err == nil || record != nil {
				t.Fatalf("unsafe record accepted: %v %v", record, err)
			}
		})
	}
	t.Run("replaceable state directory", func(t *testing.T) {
		directory := stateDirectory(t)
		if err := os.Chmod(directory, 0770); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRecord(directory); err == nil {
			t.Fatal("group-accessible state directory accepted")
		}
		if err := StoreRecord(directory, testRecord(true, capPackages)); err == nil {
			t.Fatal("record stored in group-accessible state directory")
		}
	})
	t.Run("store rejects invalid record", func(t *testing.T) {
		directory := stateDirectory(t)
		record := testRecord(true, capPackages)
		record.Policy = nil
		if err := StoreRecord(directory, record); !errors.Is(err, ErrRecord) {
			t.Fatalf("invalid record stored: %v", err)
		}
		if _, err := os.Lstat(RecordPath(directory)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid record left a file: %v", err)
		}
	})
}

func write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
