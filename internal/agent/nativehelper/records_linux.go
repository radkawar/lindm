// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package nativehelper launches closed native resource transactions in separate
// systemd units. The executor stays sandboxed; a private root Unix handshake
// consumes signed start authority only after the helper's final native preflight.
// Interrupted effects are never replayed. Durable helper receipts are evidence,
// not authority, and cannot replace independent provider verification.
package nativehelper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/statefs"
	"lindm/internal/protodata"
)

const recordLimit = 1 << 20

func transactionDirectory(stateDirectory, id string) (string, error) {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return "", errors.New("package_helper_transaction_identity")
	}
	return filepath.Join(stateDirectory, "packageprovider", id), nil
}

func phaseName(operation agentv1.NativePackageHelperOperation) (string, error) {
	switch operation {
	case agentv1.NativePackageHelperOperation_NATIVE_PACKAGE_HELPER_OPERATION_PREPARE:
		return "prepare", nil
	case agentv1.NativePackageHelperOperation_NATIVE_PACKAGE_HELPER_OPERATION_APPLY:
		return "apply", nil
	default:
		return "", errors.New("package_helper_operation")
	}
}

func encodeRecord(message proto.Message) ([]byte, error) {
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(message); err != nil {
		return nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > recordLimit {
		return nil, errors.New("package_helper_record_capacity")
	}
	return encoded, nil
}

func writeExclusive(directory, name string, encoded []byte) (resultErr error) {
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	if _, err := statefs.CheckFile(fd, name); err != nil {
		return err
	}
	fileFD, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fileFD), "package-helper-record")
	_, writeErr := file.Write(encoded)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func readRecord(directory, name string, target proto.Message) ([]byte, error) {
	encoded, err := readProtected(directory, name)
	if err != nil {
		return nil, err
	}
	valid := false
	defer func() {
		if !valid {
			clear(encoded)
		}
	}()
	if err := proto.Unmarshal(encoded, target); err != nil {
		return nil, fmt.Errorf("decode package helper record: %w", err)
	}
	if err := protodata.ValidateClosed(target.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(target); err != nil {
		return nil, err
	}
	valid = true
	return encoded, nil
}

func readRecordInto(directory, name string, target proto.Message) error {
	encoded, err := readRecord(directory, name, target)
	clear(encoded)
	return err
}

func readRecordBytes(directory, name string) (_ []byte, resultErr error) {
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	exists, err := statefs.CheckFile(fd, name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, os.ErrNotExist
	}
	fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fileFD), "package-helper-record")
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&07777 != 0600 {
		return nil, errors.New("package_helper_record_custody")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, recordLimit+2049))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > recordLimit+2048 {
		return nil, errors.New("package_helper_record_capacity")
	}
	return encoded, nil
}
