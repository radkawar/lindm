// SPDX-License-Identifier: Apache-2.0

package custody

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// ReadPassphraseFD consumes only an owner-private anonymous pipe. Secret values
// never enter argv, environment, disk files or terminal echo. Creation requires
// two identical LF-terminated lines; decryption consumes a single line.
func ReadPassphraseFD(ctx context.Context, fd int, confirm bool) (value []byte, err error) {
	if fd < 0 || fd > 1024 {
		return nil, errors.New("custody: protected_passphrase_fd_required")
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, errors.New("custody: protected_passphrase_fd_required")
	}
	var filesystem unix.Statfs_t
	if err = unix.Fstatfs(fd, &filesystem); err != nil {
		return nil, errors.New("custody: protected_passphrase_fd_required")
	}
	if filesystem.Type != unix.PIPEFS_MAGIC || stat.Mode&unix.S_IFMT != unix.S_IFIFO || stat.Mode&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("custody: owner_private_anonymous_pipe_required")
	}
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	if err = unix.SetNonblock(duplicate, true); err != nil {
		return nil, errors.Join(err, unix.Close(duplicate))
	}
	input := os.NewFile(uintptr(duplicate), "custody-passphrase")
	var once sync.Once
	var closeErr error
	closeInput := func() { once.Do(func() { closeErr = input.Close() }) }
	stop := context.AfterFunc(ctx, closeInput)
	defer func() {
		stop()
		closeInput()
		err = errors.Join(err, closeErr, ctx.Err())
		if err != nil {
			clear(value)
			value = nil
		}
	}()
	reader := bufio.NewReaderSize(io.LimitReader(input, 2051), 1026)
	readLine := func() ([]byte, error) {
		line, readErr := reader.ReadBytes('\n')
		if readErr != nil {
			clear(line)
			return nil, errors.New("custody: lf_terminated_passphrase_required")
		}
		line = line[:len(line)-1]
		if len(line) < 20 || len(line) > 1024 || bytes.ContainsAny(line, "\x00\r\n") {
			clear(line)
			return nil, errors.New("custody: passphrase_length_or_encoding_invalid")
		}
		return line, nil
	}
	first, err := readLine()
	if err != nil {
		return nil, err
	}
	if confirm {
		second, readErr := readLine()
		equal := subtle.ConstantTimeCompare(first, second) == 1
		clear(second)
		if readErr != nil || !equal {
			clear(first)
			return nil, errors.New("custody: passphrase_confirmation_mismatch")
		}
	}
	return first, nil
}
