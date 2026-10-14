// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/labexec"
)

// protectedDeployPipe is an anonymous caller-owned PIPEFS descriptor. Numeric
// inheritance is the only subprocess argument; contents stay out of files,
// environment values, diagnostics and the evidence record.
func protectedDeployPipe(passphrase []byte) (*os.File, error) {
	if len(passphrase) < 20 || len(passphrase) > 1024 || bytes.ContainsAny(passphrase, "\r\n\x00") {
		return nil, errors.New("deploy requires a bounded strong private passphrase")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	_, writeErr := writer.Write(passphrase)
	if writeErr == nil {
		_, writeErr = io.WriteString(writer, "\n")
	}
	closeErr := writer.Close()
	if writeErr != nil || closeErr != nil {
		return nil, errors.Join(writeErr, closeErr, reader.Close())
	}
	return reader, nil
}

// Raise only this maintained lab process's allowance, so unprivileged offline
// custodian children retain their own private files/pipes and can lock their
// complete secret-bearing address space. No capability is granted to binaries;
// no host-wide setting or other process is modified.
func prepareDeployCustodianMemory(ctx context.Context, repository string) error {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return err
	}
	if limit.Cur == unix.RLIM_INFINITY && limit.Max == unix.RLIM_INFINITY {
		return nil
	}
	args := []string{"-n", "prlimit", "--pid", strconv.Itoa(os.Getpid()), "--memlock=unlimited:unlimited"}
	if err := labexec.Run(ctx, labexec.Command{Path: "sudo", Args: args, Dir: repository, Timeout: 30 * time.Second, Interrupt: syscall.SIGTERM, Grace: 5 * time.Second}); err != nil {
		return fmt.Errorf("deploy requires authorized noninteractive sudo/prlimit for this process's unlimited custodian memory allowance: %w", err)
	}
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return err
	}
	if limit.Cur != unix.RLIM_INFINITY || limit.Max != unix.RLIM_INFINITY {
		return errors.New("deploy custodian refuses a finite secret-memory lock allowance")
	}
	return nil
}
