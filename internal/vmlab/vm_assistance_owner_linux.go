// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AssistanceOwnerAccessExists checks the private create-once credential file.
// A partial or nonprivate file is an error, never permission to issue new access.
func AssistanceOwnerAccessExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
		return false, errors.New("existing owner access must be a private 0400 regular file")
	}
	data, err := readRegular(path, 16<<10)
	if err != nil {
		return false, err
	}
	defer clear(data)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	prefixes := []string{"Enrollment URL: ", "Username: ", "Enrollment secret (one-time): ", "Expires at: ", "Guest desktop user: ", "Guest desktop password: "}
	if len(lines) != len(prefixes) {
		return false, errors.New("existing owner access is incomplete")
	}
	for i, prefix := range prefixes {
		value, ok := strings.CutPrefix(lines[i], prefix)
		if !ok || value == "" {
			return false, errors.New("existing owner access is incomplete")
		}
	}
	return true, nil
}

// WriteAssistanceOwnerAccess atomically publishes a new 0400 owner-only access
// file without replacing any earlier enrollment. Nothing is written to logs.
func WriteAssistanceOwnerAccess(path string, access *AssistanceHold) (err error) {
	if access == nil || access.EnrollmentSecret == "" || access.DesktopPassword == "" {
		return errors.New("owner access requires enrollment and desktop credentials")
	}
	parent := filepath.Dir(path)
	file, err := os.CreateTemp(parent, ".owner-access-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.Remove(file.Name())) }()
	_, writeErr := fmt.Fprintf(file, "Enrollment URL: %s/enroll\nUsername: %s\nEnrollment secret (one-time): %s\nExpires at: %s\nGuest desktop user: %s\nGuest desktop password: %s\n", access.ConsoleOrigin, access.Username, access.EnrollmentSecret, access.ExpiresAt.Format(time.RFC3339), access.DesktopUser, access.DesktopPassword)
	if err = errors.Join(writeErr, file.Chmod(0400), file.Sync(), file.Close()); err != nil {
		return err
	}
	// link is a no-replace publication on the same filesystem; readers see all
	// bytes or no destination, including when the process is interrupted.
	if err = os.Link(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
