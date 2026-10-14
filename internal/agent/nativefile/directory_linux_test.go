// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nativefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// /etc is root-protected on every supported host, so these read-only probes
// run unprivileged; nothing is created.
func absentEtcDirectory(t *testing.T) string {
	t.Helper()
	directory := "/etc/lindm-absent-" + uuid.NewString()
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Skip("fixture path unexpectedly exists")
	}
	return directory
}

func directoryTemplate() *resourcev1.ResourceObservation {
	return &resourcev1.ResourceObservation{Metadata: &resourcev1.ObservationMetadata{BootId: uuid.NewString(), ObservedAt: timestamppb.Now()}}
}

func TestAbsentDirectoryCaptureBindsDistinctAncestry(t *testing.T) {
	directory := absentEtcDirectory(t)
	ancestry, absent, err := DirectoryAbsent(directory)
	if err != nil || !absent || len(ancestry) != 32 {
		t.Fatalf("absent root = %x %v %v", ancestry, absent, err)
	}
	snapshot, err := CaptureInAbsentDirectory(filepath.Join(directory, "50-company"), directoryTemplate())
	if err != nil {
		t.Fatal(err)
	}
	o := snapshot.GetObservation().GetManagedFile()
	if o.GetExists() || !bytes.Equal(o.GetAncestrySha256(), ancestry) || len(snapshot.GetObservation().GetMetadata().GetNativeRevision()) != 32 {
		t.Fatal("absent-root observation does not bind its ancestry", o)
	}
	present, err := Capture("/etc/lindm-absent-file-"+uuid.NewString(), directoryTemplate())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(present.GetObservation().GetManagedFile().GetAncestrySha256(), ancestry) {
		t.Fatal("absent-root ancestry collides with a present chain")
	}
}

func TestAbsentDirectoryRefusesExistingAndDeeperAbsence(t *testing.T) {
	if _, absent, err := DirectoryAbsent("/etc"); err != nil || absent {
		t.Fatalf("existing directory reported absent: %v %v", absent, err)
	}
	if _, err := CaptureInAbsentDirectory("/etc/hostname-dir-check/../x", directoryTemplate()); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("unclean path accepted: %v", err)
	}
	directory := absentEtcDirectory(t)
	_, err := CaptureInAbsentDirectory(filepath.Join(directory, "nested", "file"), directoryTemplate())
	if !errors.Is(err, ErrConflict) || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("absent ancestor above the root was not a precondition: %v", err)
	}
	if _, err := CaptureInAbsentDirectory("/etc/x", directoryTemplate()); !errors.Is(err, ErrConflict) {
		t.Fatalf("existing directory captured as absent: %v", err)
	}
}

func TestCreatedDirectoryShape(t *testing.T) {
	for _, test := range []struct {
		st   unix.Stat_t
		want bool
	}{
		{unix.Stat_t{Mode: unix.S_IFDIR | 0755}, true},
		{unix.Stat_t{Mode: unix.S_IFDIR | 0775}, false},
		{unix.Stat_t{Mode: unix.S_IFDIR | 0755, Uid: 1}, false},
		{unix.Stat_t{Mode: unix.S_IFDIR | 0755, Gid: 1}, false},
		{unix.Stat_t{Mode: unix.S_IFREG | 0755}, false},
	} {
		if createdDirectoryShape(&test.st) != test.want {
			t.Fatalf("shape %+v", test.st)
		}
	}
}
