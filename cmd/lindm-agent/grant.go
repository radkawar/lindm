// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readGrant(path string) (string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, 258))
	} else {
		data, err = readNoFollow(path, 257, true)
	}
	if err != nil {
		return "", err
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	if len(data) < 32 || len(data) > 256 || bytes.Contains(data, []byte{0}) || bytes.Contains(data, []byte{'\n'}) {
		return "", errors.New("grant must be read from a protected file or stdin, without an embedded newline")
	}
	return string(data), nil
}

func readNoFollow(path string, limit int64, secret bool) (_ []byte, err error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "agent-input")
	defer func() { err = errors.Join(err, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size > limit {
		return nil, errors.New("input must be a bounded regular file")
	}
	if secret && (stat.Mode&0077 != 0 || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("grant file must be private to root or the operator")
	}
	if !secret && stat.Mode&0022 != 0 {
		return nil, errors.New("input must not be group- or world-writable")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("input exceeds size limit")
	}
	return data, nil
}
