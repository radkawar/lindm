// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// Offline operator tools do not acquire root privileges. Root invocations retain
// root-protected ancestry; unprivileged invocations require caller-owned private
// descriptors and produce only caller-owned private staging/output files.
func openOperationFile(path string, limit int64, private bool) (*os.File, unix.Stat_t, error) {
	if os.Geteuid() == 0 {
		file, stat, err := custody.OpenRoot(path, unix.O_RDONLY)
		if err != nil {
			return nil, stat, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size > limit || (private && stat.Mode&0077 != 0) {
			return nil, stat, errors.Join(errors.New("operations: unsafe_offline_input"), file.Close())
		}
		return file, stat, nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	var stat unix.Stat_t
	if err != nil {
		return nil, stat, err
	}
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, stat, errors.Join(err, unix.Close(fd))
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&0077 != 0 || stat.Size > limit {
		return nil, stat, errors.Join(errors.New("operations: caller_owned_private_offline_input_required"), unix.Close(fd))
	}
	return os.NewFile(uintptr(fd), path), stat, nil
}

func readOperationFile(path string, limit int64, private bool) (_ []byte, err error) {
	file, _, err := openOperationFile(path, limit, private)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("operations: offline_input_size_exceeded")
	}
	return data, nil
}

func offlineStage(prefix string) (string, error) {
	parent := "/run"
	if os.Geteuid() != 0 {
		parent = os.TempDir()
	}
	return os.MkdirTemp(parent, prefix)
}

func privateOutputDirectory(path string) error {
	if os.Geteuid() == 0 {
		return custody.PrivateDirectory(path)
	}
	_, err := custody.Owned(path, true)
	return err
}
