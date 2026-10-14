// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/statefs"
	"lindm/internal/protodata"
)

const transportStatusName = "transport-status.pb"
const maxTransportStatus = 16 << 10

var statusValidator = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(&agentv1.TransportStatus{}), protovalidate.WithDisableLazy())
})

// ReadStatus reads unprivileged diagnostic evidence without opening the spool
// database or acquiring its writer lock. The caller must compare the reported
// identity with the executor's protected identity before combining their output.
func ReadStatus(document *config.Document) (*agentv1.TransportStatus, error) {
	directoryFD, err := statefs.OpenDiagnosticDirectory(document.SpoolDirectory, document.NetworkUID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(directoryFD) }()
	fd, err := unix.Openat(directoryFD, transportStatusName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "transport-status")
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != document.NetworkUID || stat.Nlink != 1 || stat.Size > maxTransportStatus {
		return nil, errors.New("unsafe transport status file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxTransportStatus+1))
	if err != nil || len(data) > maxTransportStatus {
		return nil, errors.New("unreadable transport status")
	}
	status := new(agentv1.TransportStatus)
	if err := proto.Unmarshal(data, status); err != nil {
		return nil, errors.New("invalid transport status encoding")
	}
	if err := validateTransportStatus(status); err != nil {
		return nil, err
	}
	return status, nil
}

func writeStatus(ctx context.Context, directory string, status *agentv1.TransportStatus) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateTransportStatus(status); err != nil {
		return err
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil || len(data) > maxTransportStatus {
		return errors.New("transport status exceeds capacity")
	}
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), "transport-status-directory")
	defer func() { resultErr = errors.Join(resultErr, dir.Close()) }()
	if _, err := statefs.CheckFile(fd, transportStatusName); err != nil {
		return err
	}
	file, err := os.CreateTemp("/proc/self/fd/"+strconv.Itoa(fd), ".transport-status-")
	if err != nil {
		return err
	}
	name := filepath.Base(file.Name())
	defer func() { _ = file.Close(); _ = unix.Unlinkat(fd, name, 0) }()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(fd, name, fd, transportStatusName); err != nil {
		return err
	}
	return dir.Sync()
}

func validateTransportStatus(status *agentv1.TransportStatus) error {
	validator, err := statusValidator()
	if err != nil {
		return errors.New("compile transport status schema failed")
	}
	if status == nil || protodata.ValidateClosed(status.ProtoReflect()) != nil || validator.Validate(status) != nil {
		return errors.New("invalid transport status schema")
	}
	return nil
}
