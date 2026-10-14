// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
)

func statusFixture(t *testing.T) (*config.Document, *agentv1.TransportStatus) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "spool")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	document := &config.Document{SpoolDirectory: directory, NetworkUID: uint32(os.Geteuid())}
	status := &agentv1.TransportStatus{
		RecordedAt:  timestamppb.New(time.Unix(1_700_000_000, 0)),
		LastAttempt: agentv1.TransportOutcome_TRANSPORT_OUTCOME_WAITING_FOR_ENROLLMENT,
	}
	if err := writeStatus(t.Context(), directory, status); err != nil {
		t.Fatal(err)
	}
	return document, status
}

func TestReadStatusOwnSpool(t *testing.T) {
	document, want := statusFixture(t)
	got, err := ReadStatus(document)
	if err != nil || !proto.Equal(got, want) {
		t.Fatalf("ReadStatus() = %v, %v; want %v", got, err, want)
	}
}

func TestReadStatusRootReadsNetworkSpool(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a separately owned network spool")
	}
	document, want := statusFixture(t)
	document.NetworkUID = 65534
	path := filepath.Join(document.SpoolDirectory, transportStatusName)
	if err := os.Chown(path, int(document.NetworkUID), -1); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(document.SpoolDirectory, int(document.NetworkUID), -1); err != nil {
		t.Fatal(err)
	}
	got, err := ReadStatus(document)
	if err != nil || !proto.Equal(got, want) {
		t.Fatalf("root ReadStatus() = %v, %v; want %v", got, err, want)
	}
	if err := os.Chown(path, 0, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(document); err == nil {
		t.Fatal("accepted a status file not owned by the configured network UID")
	}
}

func TestReadStatusRejectsUnsafeFilesystem(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *config.Document, string) error
	}{
		{"file symlink", func(_ *testing.T, _ *config.Document, path string) error {
			if err := os.Rename(path, path+".real"); err != nil {
				return err
			}
			return os.Symlink(path+".real", path)
		}},
		{"magic link", func(t *testing.T, _ *config.Document, path string) error {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			t.Cleanup(func() { _ = file.Close() })
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink("/proc/self/fd/"+strconv.Itoa(int(file.Fd())), path)
		}},
		{"spool symlink", func(_ *testing.T, document *config.Document, _ string) error {
			link := document.SpoolDirectory + ".link"
			if err := os.Symlink(document.SpoolDirectory, link); err != nil {
				return err
			}
			document.SpoolDirectory = link
			return nil
		}},
		{"ancestor symlink", func(_ *testing.T, document *config.Document, _ string) error {
			parent := filepath.Dir(document.SpoolDirectory)
			link := filepath.Join(parent, "link")
			if err := os.Symlink(parent, link); err != nil {
				return err
			}
			document.SpoolDirectory = filepath.Join(link, "spool")
			return nil
		}},
		{"writable ancestor", func(_ *testing.T, document *config.Document, _ string) error {
			return os.Chmod(filepath.Dir(document.SpoolDirectory), 0777)
		}},
		{"traversable spool", func(_ *testing.T, document *config.Document, _ string) error {
			return os.Chmod(document.SpoolDirectory, 0755)
		}},
		{"wrong spool owner", func(_ *testing.T, document *config.Document, _ string) error {
			document.NetworkUID++
			return nil
		}},
		{"readable file", func(_ *testing.T, _ *config.Document, path string) error {
			return os.Chmod(path, 0644)
		}},
		{"setuid file", func(_ *testing.T, _ *config.Document, path string) error {
			return os.Chmod(path, 0600|os.ModeSetuid)
		}},
		{"hardlinked file", func(_ *testing.T, _ *config.Document, path string) error {
			return os.Link(path, path+".link")
		}},
		{"directory", func(_ *testing.T, _ *config.Document, path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Mkdir(path, 0600)
		}},
		{"fifo", func(_ *testing.T, _ *config.Document, path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return unix.Mkfifo(path, 0600)
		}},
		{"oversized file", func(_ *testing.T, _ *config.Document, path string) error {
			return os.Truncate(path, maxTransportStatus+1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, _ := statusFixture(t)
			if err := test.mutate(t, document, filepath.Join(document.SpoolDirectory, transportStatusName)); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadStatus(document); err == nil {
				t.Fatal("accepted unsafe transport status")
			}
		})
	}
}

func TestReadStatusMissing(t *testing.T) {
	document, _ := statusFixture(t)
	if err := os.Remove(filepath.Join(document.SpoolDirectory, transportStatusName)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(document); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing status: %v", err)
	}
}
