// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Laboratory records describe observed artifacts; consumers must still verify
// their files, signatures and runtime state. They are not authority documents.
func readLabEvidence(path string, target any) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "laboratory-evidence")
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("laboratory evidence must be a bounded regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(file, (1<<20)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid laboratory evidence document")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("laboratory evidence contains trailing data")
	}
	return nil
}

func writeLabEvidence(stdout io.Writer, record string, result any) (err error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if record != "" {
		file, err := os.OpenFile(record, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		written, writeErr := file.Write(data)
		if writeErr == nil && written != len(data) {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		writeErr = errors.Join(writeErr, file.Close())
		if writeErr != nil {
			return errors.Join(fmt.Errorf("persist laboratory evidence: %w", writeErr), os.Remove(record))
		}
	}
	_, err = stdout.Write(data)
	return err
}
