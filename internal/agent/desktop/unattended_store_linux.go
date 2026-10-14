// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	enrollmentFile    = "assistance-unattended.json"
	enrollmentMaxSize = 4 << 10
)

// FileEnrollmentStore keeps the unattended opt-in in the user's private
// state directory ($XDG_STATE_HOME/lindm, mode 0700). Every access goes
// through an os.Root so a link in the directory cannot redirect it.
type FileEnrollmentStore struct {
	dir string
}

var _ EnrollmentStore = (*FileEnrollmentStore)(nil)

type enrollmentDocument struct {
	EnrollmentID string    `json:"enrollment_id"`
	Mode         int32     `json:"mode"`
	ExpiresAt    time.Time `json:"expires_at"`
	RestoreToken string    `json:"restore_token"`
}

// NewFileEnrollmentStore resolves the helper user's state directory.
func NewFileEnrollmentStore() (*FileEnrollmentStore, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" || !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("desktop: resolve state directory: %w", err)
		}
		base = filepath.Join(home, ".local", "state")
	}
	return &FileEnrollmentStore{dir: filepath.Join(base, "lindm")}, nil
}

// root opens the private directory, creating it, and refuses one that is
// not a directory owned by this user with no group or other access.
func (s *FileEnrollmentStore) root(create bool) (*os.Root, error) {
	if create {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(s.dir)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("desktop: unattended state directory is not private")
	}
	return os.OpenRoot(s.dir)
}

func (s *FileEnrollmentStore) Load() (_ Enrollment, err error) {
	root, err := s.root(false)
	if err != nil {
		return Enrollment{}, errEnrollmentMissing
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	// The opt-in is a regular file in the private directory, never a link.
	linked, err := root.Lstat(enrollmentFile)
	if err != nil || !linked.Mode().IsRegular() {
		return Enrollment{}, errEnrollmentMissing
	}
	file, err := root.OpenFile(enrollmentFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Enrollment{}, errEnrollmentMissing
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if opened, err := file.Stat(); err != nil || !os.SameFile(linked, opened) {
		return Enrollment{}, errEnrollmentMissing
	}
	data, err := io.ReadAll(io.LimitReader(file, enrollmentMaxSize+1))
	if err != nil || len(data) > enrollmentMaxSize {
		return Enrollment{}, errEnrollmentMissing
	}
	var document enrollmentDocument
	if json.Unmarshal(data, &document) != nil || !validRestoreToken(document.RestoreToken) {
		return Enrollment{}, errEnrollmentMissing
	}
	return Enrollment{ID: document.EnrollmentID, Mode: agentv1.AssistanceMode(document.Mode), ExpiresAt: document.ExpiresAt, RestoreToken: document.RestoreToken}, nil
}

// Save replaces the opt-in atomically with a 0600 file.
func (s *FileEnrollmentStore) Save(enrollment Enrollment) (err error) {
	data, err := json.Marshal(enrollmentDocument{EnrollmentID: enrollment.ID, Mode: int32(enrollment.Mode), ExpiresAt: enrollment.ExpiresAt.UTC(), RestoreToken: enrollment.RestoreToken})
	if err != nil {
		return err
	}
	root, err := s.root(true)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	temporary := enrollmentFile + ".tmp"
	if err := root.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return errors.Join(err, file.Close(), root.Remove(temporary))
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return errors.Join(err, root.Remove(temporary))
	}
	return root.Rename(temporary, enrollmentFile)
}

// Remove withdraws the opt-in. A missing file is already removed.
func (s *FileEnrollmentStore) Remove() (err error) {
	root, err := s.root(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err := root.Remove(enrollmentFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
