//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const labUser = "lindm-lab"
const guestAgent = "/home/lindm-lab/lindm-agent"
const maxGuestOutput = 64 << 20

// guestVM owns a single disposable machine, its credentials, and its directory.
// Its SSH transport is pinned to the host key injected through private NoCloud.
// It never changes host networking or exposes a management port off loopback.
type guestVM struct {
	dir                string
	cmd                *exec.Cmd
	done               chan struct{}
	waitErr            error
	log                *vmLog
	address            string
	config             *ssh.ClientConfig
	client             *ssh.Client
	captureDiagnostics bool
	lastOperation      *guestOperationDiagnostic
}

type vmRuntimeEvidence struct {
	Accelerator     string `json:"accelerator"`
	QEMUVersion     string `json:"qemu_version"`
	FirmwareVendor  string `json:"firmware_vendor"`
	FirmwareVersion string `json:"firmware_version"`
}

func (v *guestVM) runtimeEvidence(ctx context.Context) (*vmRuntimeEvidence, error) {
	if err := v.processError(); err != nil {
		return nil, err
	}
	// Query the running executable, not a PATH entry which could have changed
	// after launch. Firmware is observed inside this guest.
	version, err := hostCommand(ctx, v.dir, fmt.Sprintf("/proc/%d/exe", v.cmd.Process.Pid), nil, "--version")
	if err != nil {
		return nil, err
	}
	qemu, _, _ := strings.Cut(string(version), "\n")
	firmware, err := v.run(ctx, "cat /sys/class/dmi/id/bios_vendor /sys/class/dmi/id/bios_version", nil, 4096, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("read guest firmware evidence: %w", err)
	}
	fields := strings.Split(strings.TrimSuffix(string(firmware), "\n"), "\n")
	if strings.TrimSpace(qemu) == "" || len(fields) != 2 || strings.TrimSpace(fields[0]) == "" || strings.TrimSpace(fields[1]) == "" {
		return nil, errors.New("incomplete hypervisor or guest firmware evidence")
	}
	// The launch requires accel=kvm and has no emulation fallback.
	return &vmRuntimeEvidence{Accelerator: "kvm", QEMUVersion: qemu, FirmwareVendor: fields[0], FirmwareVersion: fields[1]}, nil
}

// vmLog retains only bounded process diagnostics, never guest serial output.
type vmLog struct {
	mu   sync.Mutex
	data []byte
}

func (l *vmLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	const limit = 8192
	if len(p) >= limit {
		l.data = append(l.data[:0], p[len(p)-limit:]...)
	} else {
		if excess := len(l.data) + len(p) - limit; excess > 0 {
			copy(l.data, l.data[excess:])
			l.data = l.data[:len(l.data)-excess]
		}
		l.data = append(l.data, p...)
	}
	return n, nil
}

func (l *vmLog) diagnostic(dir string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := strings.ReplaceAll(string(l.data), dir, "<private-run>")
	return strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return ' '
		}
		return r
	}, s)
}

func hostCommand(ctx context.Context, dir, name string, files []*os.File, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	// cloud-localds copies private user-data into TMPDIR. Its EXIT trap cannot
	// run after SIGKILL, so all staging must remain inside owned cleanup.
	cmd.Env = append(os.Environ(), "TMPDIR="+dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Stop the script and its ISO/image-builder descendants together.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	cmd.ExtraFiles = files
	cmd.WaitDelay = 2 * time.Second
	out := &limitedOutput{limit: 1 << 20}
	log := new(vmLog)
	cmd.Stdout, cmd.Stderr = out, log
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %w; %s", name, err, log.diagnostic(dir))
	}
	if out.exceeded {
		return nil, fmt.Errorf("%s output exceeded limit", name)
	}
	return out.data, nil
}

func newGuestVM(ctx context.Context, base *os.File, workDir string, allowReboot bool) (_ *guestVM, err error) {
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("KVM access is required (no software fallback): %w", err)
	}
	if err := kvm.Close(); err != nil {
		return nil, err
	}
	for _, tool := range []string{"qemu-system-x86_64", "qemu-img", "cloud-localds"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, fmt.Errorf("required host tool %s: %w", tool, err)
		}
	}
	if workDir == "" {
		workDir = os.TempDir()
	}
	workDir, err = filepath.Abs(workDir)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(workDir, "lindm-vm-")
	if err != nil {
		return nil, fmt.Errorf("create private run directory: %w", err)
	}
	vm := &guestVM{dir: dir, log: new(vmLog)}
	defer func() {
		if err != nil {
			err = errors.Join(err, vm.close())
		}
	}()

	infoBytes, err := hostCommand(ctx, dir, "qemu-img", []*os.File{base}, "info", "--output=json", "-f", "qcow2", "/proc/self/fd/3")
	if err != nil {
		return nil, err
	}
	var info struct {
		Format      string `json:"format"`
		VirtualSize int64  `json:"virtual-size"`
		Backing     string `json:"backing-filename"`
	}
	if err := json.Unmarshal(infoBytes, &info); err != nil {
		return nil, fmt.Errorf("decode qcow2 metadata: %w", err)
	}
	if info.Format != "qcow2" || info.Backing != "" || info.VirtualSize <= 0 || info.VirtualSize > 64<<30 {
		return nil, errors.New("base must be standalone qcow2 with virtual size at most 64 GiB")
	}
	if _, err := hostCommand(ctx, dir, "qemu-img", nil, "create", "-f", "qcow2", "-F", "qcow2", "-b", "/proc/self/fd/3", "-u", "overlay.qcow2", strconv.FormatInt(info.VirtualSize, 10)); err != nil {
		return nil, err
	}

	_, loginKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	login, err := ssh.NewSignerFromKey(loginKey)
	if err != nil {
		return nil, err
	}
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	host, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		return nil, err
	}
	private, err := ssh.MarshalPrivateKey(hostKey, "")
	if err != nil {
		return nil, err
	}
	config := map[string]any{
		"users":        []any{map[string]any{"name": labUser, "shell": "/bin/sh", "lock_passwd": true, "sudo": "ALL=(ALL) NOPASSWD:ALL", "ssh_authorized_keys": []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(login.PublicKey())))}}},
		"disable_root": true, "ssh_pwauth": false, "ssh_deletekeys": true,
		"ssh_keys":       map[string]string{"ed25519_private": string(pem.EncodeToMemory(private)), "ed25519_public": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host.PublicKey())))},
		"ssh":            map[string]bool{"emit_keys_to_console": false},
		"package_update": false, "package_upgrade": false,
		// Inspection compares the vendor's actual hostname and does not
		// require cloud-init to configure a different one.
		"preserve_hostname": true,
		// Stop periodic native package mutation before taking the two truth snapshots.
		// This changes the disposable guest only; it installs nothing.
		"runcmd": []any{[]string{"sh", "-c", "for unit in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service dnf-makecache.timer dnf-makecache.service dnf-automatic.timer; do if systemctl cat \"$unit\" >/dev/null 2>&1; then systemctl mask --now \"$unit\" || exit; fi; done"}},
	}
	userData, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "user-data"), append([]byte("#cloud-config\n"), userData...), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "meta-data"), []byte("instance-id: "+filepath.Base(dir)+"\n"), 0600); err != nil {
		return nil, err
	}
	if _, err := hostCommand(ctx, dir, "cloud-localds", nil, "seed.img", "user-data", "meta-data"); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Join(dir, "seed.img"), 0600); err != nil {
		return nil, err
	}
	if err := os.Remove(filepath.Join(dir, "user-data")); err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	vm.address = listener.Addr().String()
	_, port, err := net.SplitHostPort(vm.address)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	// Closing the reservation has an unavoidable bind race. QEMU bind failure
	// is terminal; even a competing SSH daemon cannot satisfy this exact key pin.
	if err := listener.Close(); err != nil {
		return nil, err
	}
	args := []string{
		"-no-user-config", "-nodefaults", "-display", "none", "-serial", "none", "-monitor", "none",
		"-machine", "q35,accel=kvm", "-cpu", "host", "-m", "2048", "-smp", "2",
	}
	if !allowReboot {
		args = append(args, "-no-reboot")
	}
	for _, block := range []map[string]any{
		{"driver": "file", "node-name": "base-file", "filename": "/proc/self/fd/3", "read-only": true},
		{"driver": "qcow2", "node-name": "base", "file": "base-file", "read-only": true, "backing": nil},
		{"driver": "file", "node-name": "overlay-file", "filename": filepath.Join(dir, "overlay.qcow2")},
		{"driver": "qcow2", "node-name": "overlay", "file": "overlay-file", "backing": "base"},
		{"driver": "file", "node-name": "seed-file", "filename": filepath.Join(dir, "seed.img"), "read-only": true},
		{"driver": "raw", "node-name": "seed", "file": "seed-file", "read-only": true},
	} {
		encoded, err := json.Marshal(block)
		if err != nil {
			return nil, fmt.Errorf("encode QEMU block device: %w", err)
		}
		args = append(args, "-blockdev", string(encoded))
	}
	args = append(args,
		"-device", "virtio-blk-pci,drive=overlay,bootindex=0",
		"-device", "virtio-blk-pci,drive=seed", "-device", "virtio-rng-pci",
		"-netdev", fmt.Sprintf("user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:%s-:22", port),
		"-device", "virtio-net-pci,netdev=net0",
	)
	vm.cmd = exec.CommandContext(ctx, "qemu-system-x86_64", args...)
	vm.cmd.Dir = dir
	vm.cmd.ExtraFiles = []*os.File{base}
	vm.cmd.Stdout, vm.cmd.Stderr = vm.log, vm.log
	vm.cmd.WaitDelay = 2 * time.Second
	// Linux sends Pdeathsig when the creating thread dies, not merely when
	// the Go process exits. Keep that OS thread alive for the child's lifetime.
	vm.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	started := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		startErr := vm.cmd.Start()
		started <- startErr
		if startErr == nil {
			vm.waitErr = vm.cmd.Wait()
		}
		close(done)
	}()
	if err := <-started; err != nil {
		return nil, fmt.Errorf("start QEMU: %w", err)
	}
	vm.done = done
	vm.config = &ssh.ClientConfig{User: labUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(login)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, Timeout: 5 * time.Second}
	return vm, nil
}

func (v *guestVM) processError() error {
	select {
	case <-v.done:
		return fmt.Errorf("QEMU exited unexpectedly (%v); %s", v.waitErr, v.log.diagnostic(v.dir))
	default:
		return nil
	}
}

func (v *guestVM) connect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		if err := v.processError(); err != nil {
			return err
		}
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		conn, err := (&net.Dialer{}).DialContext(attempt, "tcp4", v.address)
		if err == nil {
			deadline, _ := attempt.Deadline()
			_ = conn.SetDeadline(deadline)
			cancelConn := context.AfterFunc(attempt, func() { _ = conn.Close() })
			sshConn, channels, requests, handshakeErr := ssh.NewClientConn(conn, v.address, v.config)
			if handshakeErr == nil && cancelConn() {
				_ = conn.SetDeadline(time.Time{})
				v.client = ssh.NewClient(sshConn, channels, requests)
				stop()
				return v.processError()
			}
			cancelConn()
			_ = conn.Close()
		}
		stop()
		select {
		case <-ctx.Done():
			return fmt.Errorf("SSH readiness deadline: %w", ctx.Err())
		case <-v.done:
			return v.processError()
		case <-time.After(time.Second):
		}
	}
}

// close kills and reaps QEMU before removing every secret-bearing artifact.
// A requested SIGKILL is expected; an already exited guest is always a failure.
func (v *guestVM) close() error {
	var err error
	if v.client != nil {
		_ = v.client.Close()
	}
	if v.done != nil {
		select {
		case <-v.done:
			err = v.processError()
		default:
			killErr := v.cmd.Process.Kill()
			if killErr != nil {
				err = errors.Join(err, fmt.Errorf("stop QEMU: %w", killErr))
			}
			select {
			case <-v.done:
				var exit *exec.ExitError
				if v.waitErr != nil {
					if errors.As(v.waitErr, &exit) {
						status, ok := exit.Sys().(syscall.WaitStatus)
						if !ok || status.Signal() != syscall.SIGKILL {
							err = errors.Join(err, fmt.Errorf("reap QEMU: %w", v.waitErr))
						}
					} else {
						err = errors.Join(err, fmt.Errorf("reap QEMU: %w", v.waitErr))
					}
				}
			case <-time.After(10 * time.Second):
				err = errors.Join(err, errors.New("QEMU did not exit within cleanup deadline"))
			}
		}
	}
	return errors.Join(err, os.RemoveAll(v.dir))
}

type limitedOutput struct {
	data     []byte
	limit    int
	exceeded bool
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-len(w.data) {
		w.exceeded = true
		return 0, errors.New("command output exceeds capacity")
	}
	w.data = append(w.data, p...)
	return len(p), nil
}

// guestCommandResult keeps bounded diagnostics private to the lab caller.
// ExitCode is meaningful only when runResult returns a nil transport error.
type guestCommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type guestOperationDiagnostic struct {
	Command         string
	ExitCode        int
	Completed       bool
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
}

func (v *guestVM) run(ctx context.Context, command string, input io.Reader, limit int, timeout time.Duration) ([]byte, error) {
	result, err := v.runResult(ctx, command, input, limit, timeout)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return result.Stdout, fmt.Errorf("guest operation exited with status %d (stderr bytes %d)", result.ExitCode, len(result.Stderr))
	}
	if len(bytes.TrimSpace(result.Stderr)) != 0 {
		return nil, errors.New("guest operation emitted unexpected stderr")
	}
	return result.Stdout, nil
}

func (v *guestVM) runResult(ctx context.Context, command string, input io.Reader, limit int, timeout time.Duration) (guestCommandResult, error) {
	var result guestCommandResult
	if v.client == nil {
		return result, errors.New("guest SSH is not connected")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := v.processError(); err != nil {
		return result, err
	}
	// Closing the transport interrupts channel creation, requests and stream I/O.
	// A timeout ends the scenario; a possibly ambiguous session is never reused.
	stop := context.AfterFunc(ctx, func() { _ = v.client.Close() })
	defer stop()
	session, err := v.client.NewSession()
	if err != nil {
		return result, fmt.Errorf("open pinned SSH session: %w", err)
	}
	defer func() { _ = session.Close() }() // Run already checked remote completion.
	stdout := &limitedOutput{limit: limit}
	stderr := &limitedOutput{limit: limit}
	session.Stdin, session.Stdout, session.Stderr = input, stdout, stderr
	err = session.Run(command)
	if v.captureDiagnostics {
		defer func() {
			var exit *ssh.ExitError
			v.lastOperation = &guestOperationDiagnostic{
				Command: command, ExitCode: result.ExitCode,
				Completed:       ctx.Err() == nil && (err == nil || errors.As(err, &exit)),
				Stdout:          string(stdout.data[:min(len(stdout.data), 16<<10)]),
				Stderr:          string(stderr.data[:min(len(stderr.data), 16<<10)]),
				StdoutTruncated: len(stdout.data) > 16<<10 || stdout.exceeded,
				StderrTruncated: len(stderr.data) > 16<<10 || stderr.exceeded,
			}
		}()
	}
	if processErr := v.processError(); processErr != nil {
		return result, processErr
	}
	if ctx.Err() != nil {
		return result, fmt.Errorf("guest operation deadline: %w", ctx.Err())
	}
	if stdout.exceeded || stderr.exceeded {
		return result, errors.New("guest operation output exceeds capacity")
	}
	result.Stdout, result.Stderr = stdout.data, stderr.data
	// Do not print guest-controlled stderr: it may contain host facts or seed keys.
	if err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			result.ExitCode = exit.ExitStatus()
			return result, nil
		}
		return result, errors.New("guest operation transport failed")
	}
	return result, nil
}
