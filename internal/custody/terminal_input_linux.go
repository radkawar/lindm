// SPDX-License-Identifier: Apache-2.0
//go:build linux

package custody

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// ReadPassphrase reads a private anonymous pipe or a terminal with echo disabled.
// Creation requires confirmation; unlock consumes one LF-terminated line. The
// caller must establish secret-memory protection before calling and wipe the result.
func ReadPassphrase(ctx context.Context, fd int, confirm bool) (value []byte, err error) {
	if fd >= 0 {
		return ReadPassphraseFD(ctx, fd, confirm)
	}
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("custody: private terminal or --passphrase-fd required")
	}
	closed := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { closed <- terminal.Close() })
	defer func() {
		if stop() {
			err = errors.Join(err, terminal.Close())
		} else {
			err = errors.Join(err, <-closed)
		}
		if err != nil {
			clear(value)
			value = nil
		}
	}()
	control, err := unix.FcntlInt(terminal.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.Close(control)) }()
	original, err := unix.IoctlGetTermios(control, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	private := *original
	private.Lflag &^= unix.ECHO | unix.ECHONL
	if err := unix.IoctlSetTermios(control, unix.TCSETS, &private); err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.IoctlSetTermios(control, unix.TCSETS, original)) }()
	reader := bufio.NewReaderSize(io.LimitReader(terminal, 2051), 1026)
	readLine := func(prompt string) ([]byte, error) {
		if _, err := fmt.Fprint(terminal, prompt); err != nil {
			return nil, err
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			clear(line)
			return nil, errors.New("custody: bounded LF-terminated passphrase required")
		}
		line = line[:len(line)-1]
		if len(line) < 20 || len(line) > 1024 || bytes.ContainsAny(line, "\x00\r\n") {
			clear(line)
			return nil, errors.New("custody: passphrase must contain 20 to 1024 bytes without control separators")
		}
		return line, nil
	}
	first, err := readLine("Release custody passphrase (20+ bytes, unique): ")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			clear(first)
		}
	}()
	if confirm {
		second, readErr := readLine("\nRepeat release custody passphrase: ")
		equal := subtle.ConstantTimeCompare(first, second) == 1
		clear(second)
		if readErr != nil || !equal {
			return nil, errors.New("custody: passphrase confirmation mismatch")
		}
	}
	if _, err := fmt.Fprintln(terminal); err != nil {
		return nil, err
	}
	return first, nil
}
