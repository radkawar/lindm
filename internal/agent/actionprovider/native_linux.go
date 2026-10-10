//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Native executables are a closed local implementation detail, never plan data.
type command uint8

const (
	cryptsetup command = iota
	cryptenroll
	nft
	lsblk
	systemctl
	dmsetup
	nvme
	usermod
	chage
)

var executable = [...]string{"/usr/sbin/cryptsetup", "/usr/bin/systemd-cryptenroll", "/usr/sbin/nft", "/usr/bin/lsblk", "/usr/bin/systemctl", "/usr/sbin/dmsetup", "/usr/sbin/nvme", "/usr/sbin/usermod", "/usr/bin/chage"}

const outputLimit = 1 << 20

var errNativeNotLUKS = errors.New("native_invalid_luks_header")

type nativeRequest struct {
	command command
	args    []string
	input   []byte
	files   []*os.File
}

type nativeRunner func(context.Context, nativeRequest) ([]byte, error)

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > outputLimit-b.Len() {
		b.overflow = true
		return 0, errors.New("native_output_limit")
	}
	return b.Buffer.Write(data)
}

func runNative(ctx context.Context, request nativeRequest) ([]byte, error) {
	if int(request.command) >= len(executable) {
		return nil, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable[request.command], request.args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	cmd.Stdin = bytes.NewReader(request.input)
	cmd.ExtraFiles = request.files
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	var out, diagnostic boundedOutput
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	err := cmd.Run()
	if out.overflow || diagnostic.overflow {
		return nil, errors.New("native_output_limit")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Neither stderr nor argv is included: native helpers can echo credentials.
	if err != nil {
		if request.command == cryptsetup && len(request.args) > 0 && request.args[0] == "luksDump" && bytes.Contains(diagnostic.Bytes(), []byte("is not a valid LUKS device")) {
			err = errors.Join(errNativeNotLUKS, err)
		}
		if request.command == nvme && nvmeUnsupportedDiagnostic(diagnostic.Bytes()) {
			// Preserve explicit emulated/firmware opcode refusal. A consumed
			// command still remains outcome_unknown at the provider boundary.
			err = errors.Join(ErrUnsupported, err)
		}
		return nil, fmt.Errorf("native %d failed: %w", request.command, err)
	}
	return out.Bytes(), nil
}

// secretHandle keeps anonymous pages locked until the helper exits. Existing
// writable mapping permits explicit erasure; FUTURE_WRITE prevents the inherited
// descriptor from being used to modify the file or create a writable mapping.
type secretHandle struct {
	file   *os.File
	memory []byte
}

func (s *secretHandle) Close() error {
	clear(s.memory)
	err := errors.Join(unix.Munlock(s.memory), unix.Munmap(s.memory))
	return errors.Join(err, s.file.Close())
}

func lockedMemory(size int) ([]byte, error) {
	memory, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, err
	}
	if err := unix.Mlock(memory); err != nil {
		return nil, errors.Join(err, unix.Munmap(memory))
	}
	if err := unix.Madvise(memory, unix.MADV_DONTDUMP); err != nil {
		return nil, errors.Join(err, unix.Munlock(memory), unix.Munmap(memory))
	}
	return memory, nil
}

func releaseMemory(memory []byte) error {
	clear(memory)
	return errors.Join(unix.Munlock(memory), unix.Munmap(memory))
}

func secretFile(secret []byte) (_ *secretHandle, err error) {
	if len(secret) == 0 || len(secret) > 4096 {
		return nil, ErrCredential
	}
	fd, err := unix.MemfdCreate("lindm-unlock", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "lindm-unlock")
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	if err := file.Truncate(int64(len(secret))); err != nil {
		return nil, err
	}
	memory, err := unix.Mmap(fd, 0, len(secret), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			clear(memory)
			err = errors.Join(err, unix.Munlock(memory), unix.Munmap(memory))
		}
	}()
	if err := unix.Mlock(memory); err != nil {
		return nil, err
	}
	if err := unix.Madvise(memory, unix.MADV_DONTDUMP); err != nil {
		return nil, err
	}
	copy(memory, secret)
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_FUTURE_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, err
	}
	return &secretHandle{file: file, memory: memory}, nil
}

func descriptor(index int) string { return "/proc/self/fd/" + strconv.Itoa(index+3) }

func (p *Provider) crypt(ctx context.Context, target *os.File, args []string, secrets ...[]byte) (_ []byte, err error) {
	files := []*os.File{target}
	handles := make([]*secretHandle, 0, len(secrets))
	defer func() {
		for _, handle := range handles {
			err = errors.Join(err, handle.Close())
		}
	}()
	for _, secret := range secrets {
		handle, e := secretFile(secret)
		if e != nil {
			return nil, e
		}
		handles = append(handles, handle)
		files = append(files, handle.file)
	}
	return p.run(ctx, nativeRequest{command: cryptsetup, args: args, files: files})
}

// nvme-cli's C-locale status spelling differs across maintained 2.x releases.
// Only an explicit invalid opcode/field is unsupported, never an I/O timeout or
// permission error. This classification is not evidence that erasure occurred.
func nvmeUnsupportedDiagnostic(diagnostic []byte) bool {
	return bytes.Contains(diagnostic, []byte("INVALID_OPCODE")) ||
		bytes.Contains(diagnostic, []byte("Invalid Command Opcode")) ||
		bytes.Contains(diagnostic, []byte("INVALID_FIELD")) ||
		bytes.Contains(diagnostic, []byte("Invalid Field in Command"))
}
