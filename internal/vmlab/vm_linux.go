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

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
	"lindm/internal/platform"
)

const labUser = "lindm-lab"
const guestAgent = "/home/lindm-lab/lindm-agent"
const maxGuestOutput = 64 << 20

// minGuestDiskBytes is the disposable overlay floor. Vendor cloud images
// expect to be resized before first boot: openSUSE Leap 16.0 Minimal-VM
// Build18.75 ships a 1.5 GiB disk whose root is too full for one agent RPM
// until kiwi-repart grows it into a larger disk. EL GenericCloud images
// already carry 10 GiB. Larger bases keep their own virtual size.
const minGuestDiskBytes = 10 << 30

// createGuestOverlay writes dir/overlay.qcow2 over the verified standalone
// base, which QEMU later receives as inherited descriptor 3.
func createGuestOverlay(ctx context.Context, dir string, base *os.File) error {
	infoBytes, err := hostCommand(ctx, dir, "qemu-img", []*os.File{base}, "info", "--output=json", "-f", "qcow2", "/proc/self/fd/3")
	if err != nil {
		return err
	}
	var info struct {
		Format      string `json:"format"`
		VirtualSize int64  `json:"virtual-size"`
		Backing     string `json:"backing-filename"`
	}
	if err := json.Unmarshal(infoBytes, &info); err != nil {
		return fmt.Errorf("decode qcow2 metadata: %w", err)
	}
	if info.Format != "qcow2" || info.Backing != "" || info.VirtualSize <= 0 || info.VirtualSize > 64<<30 {
		return errors.New("base must be standalone qcow2 with virtual size at most 64 GiB")
	}
	_, err = hostCommand(ctx, dir, "qemu-img", nil, "create", "-f", "qcow2", "-F", "qcow2", "-b", "/proc/self/fd/3", "-u", "overlay.qcow2", strconv.FormatInt(max(info.VirtualSize, minGuestDiskBytes), 10))
	return err
}

// guestVM owns a single disposable machine, its credentials, and its directory.
// Its SSH transport is pinned to the host key injected through private NoCloud.
// It never changes host networking or exposes a management port off loopback.
type guestVM struct {
	dir                string
	cmd                *exec.Cmd
	base               *os.File
	done               chan struct{}
	waitErr            error
	log                *vmLog
	address            string
	config             *ssh.ClientConfig
	client             *ssh.Client
	captureDiagnostics bool
	diagnosticsDir     string
	lastOperation      *guestOperationDiagnostic
	hardware           VMHardwareOptions
	firmware           *EncryptedFirmwareEvidence
	tpm                *encryptedProcess
	// Only configured UEFI guests defer a requested no-reboot policy until SSH.
	// Manually assembled encrypted guests retain their existing reboot policy.
	stopRebootAfterConnect bool
	// release is the registry row a verified manifest booted; nil for
	// manually assembled guests.
	release *platform.Release
}

// vmLog retains the last 8 KiB of process diagnostics, never guest serial
// output. Unlike a bare nativeexec.Buffer it is safe for concurrent writers.
type vmLog struct {
	mu   sync.Mutex
	tail *nativeexec.Buffer
}

func (l *vmLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tail == nil {
		l.tail = nativeexec.NewTailBuffer(8192)
	}
	return l.tail.Write(p)
}

func (l *vmLog) diagnostic(dir string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var data string
	if l.tail != nil {
		data = l.tail.String()
	}
	s := strings.ReplaceAll(data, dir, "<private-run>")
	return strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return ' '
		}
		return r
	}, s)
}

func hostCommand(ctx context.Context, dir, name string, files []*os.File, args ...string) ([]byte, error) {
	out, log := nativeexec.NewBuffer(1<<20), new(vmLog)
	// cloud-localds copies private user-data into TMPDIR. Its EXIT trap cannot
	// run after SIGKILL, so all staging must remain inside owned cleanup.
	if err := labexec.Run(ctx, labexec.Command{Path: name, Args: args, Env: append(os.Environ(), "TMPDIR="+dir), Dir: dir, Files: files, Stdout: out, Stderr: log, Timeout: time.Minute}); err != nil {
		return nil, fmt.Errorf("%s failed: %w; %s", name, err, log.diagnostic(dir))
	}
	if out.Truncated() {
		return nil, fmt.Errorf("%s output exceeded limit", name)
	}
	return out.Bytes(), nil
}

func newConfiguredGuestVM(ctx context.Context, base *os.File, workDir string, allowReboot bool, hardware *VMHardwareOptions) (_ *guestVM, err error) {
	return newSeededGuestVM(ctx, base, workDir, allowReboot, hardware, nil)
}

// newSeededGuestVM accepts only internally constructed, root-only enrollment
// material. The seed and overlay remain owned by the disposable VM lifecycle.
func newSeededGuestVM(ctx context.Context, base *os.File, workDir string, allowReboot bool, hardware *VMHardwareOptions, enrollment *unattendedSeed) (_ *guestVM, err error) {
	h, err := defaultVMHardware(hardware)
	if err != nil {
		return nil, err
	}
	if err := checkVMAcceleration(h); err != nil {
		return nil, err
	}
	tools := []string{"qemu-system-" + h.Architecture, "qemu-img", "cloud-localds"}
	if h.TPM {
		tools = append(tools, "swtpm")
	}
	for _, tool := range tools {
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
	vm := &guestVM{dir: dir, log: new(vmLog), hardware: h, stopRebootAfterConnect: !allowReboot && h.Firmware != nil}
	defer func() {
		if err != nil {
			err = errors.Join(err, vm.close())
		}
	}()
	// Retain the exact verified base for independent stopped-disk oracles;
	// the caller's borrowed descriptor closes after QEMU inherits its copy.
	vm.base, err = os.Open(fmt.Sprintf("/proc/self/fd/%d", base.Fd()))
	if err != nil {
		return nil, fmt.Errorf("retain verified VM base: %w", err)
	}
	if err := vm.prepareHardware(ctx); err != nil {
		return nil, err
	}

	if err := createGuestOverlay(ctx, dir, base); err != nil {
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
		// This changes the disposable guest only; it installs nothing. Stop before
		// mask: "mask --now" reloads first, and systemd 259 then re-coldplugs the
		// still-active masked timer without its Triggers= dependency and fails it
		// ("Unit to trigger vanished", result resources), degrading Ubuntu 26.04.
		"runcmd": []any{[]string{"sh", "-c", "for unit in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service dnf-makecache.timer dnf-makecache.service dnf-automatic.timer; do if systemctl cat \"$unit\" >/dev/null 2>&1; then systemctl stop \"$unit\" && systemctl mask \"$unit\" || exit; fi; done"}},
	}
	if h.stockAcceptance {
		delete(config, "runcmd")
	}
	if enrollment != nil {
		enrollment.apply(config)
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
	args, err := configuredVMArguments(h, dir, port, allowReboot)
	if err != nil {
		return nil, err
	}
	// Not labexec: QEMU's Pdeathsig must be bound to a thread locked for the VM's lifetime.
	vm.cmd = exec.CommandContext(ctx, "qemu-system-"+h.Architecture, args...)
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
	if v.tpm != nil {
		select {
		case <-v.tpm.done:
			return fmt.Errorf("swtpm exited unexpectedly (%v); %s; QEMU diagnostics: %s", v.tpm.err, v.tpm.log.diagnostic(v.dir), v.log.diagnostic(v.dir))
		default:
		}
	}
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
				if err := v.finishStartup(ctx); err != nil {
					return err
				}
				// Authentication precedes sshd's PAM/session startup. Only
				// transient transport loss or explicit channel unavailability
				// may retry this side-effect-free readiness command.
				if _, err := v.run(ctx, "true", nil, 128, 15*time.Second); err != nil {
					_ = v.client.Close()
					v.client = nil
					if !sshBootNotReady(err) {
						return fmt.Errorf("SSH session readiness: %w", err)
					}
				} else {
					return v.processError()
				}
			}
			cancelConn()
			_ = conn.Close()
			if handshakeErr != nil && !sshBootNotReady(handshakeErr) {
				stop()
				return fmt.Errorf("pinned SSH handshake: %w", handshakeErr)
			}
		} else if !errors.Is(err, syscall.ECONNREFUSED) && !sshBootNotReady(err) {
			stop()
			return fmt.Errorf("dial guest SSH: %w", err)
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

// sshBootNotReady admits only transport startup failures and explicit temporary
// channel rejection. Authentication, host-key, protocol and command failures are
// terminal; polling readiness must never hide a changed security boundary.
func sshBootNotReady(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return true
	}
	var channel *ssh.OpenChannelError
	return errors.As(err, &channel) &&
		(channel.Reason == ssh.ConnectionFailed || channel.Reason == ssh.ResourceShortage)
}

// close kills and reaps QEMU before removing every secret-bearing artifact.
// A requested SIGKILL is expected; an already exited guest is always a failure.
func (v *guestVM) close() error {
	return v.closeWithExpectedExit(false)
}

// closeAfterExpectedExit cleans a successfully reaped process only. Callers must
// independently prove the intended guest outcome before discarding its state.
func (v *guestVM) closeAfterExpectedExit() error {
	if v.done == nil || v.cmd == nil {
		return errors.New("expected-exit cleanup requires an owned stopped process")
	}
	select {
	case <-v.done:
		if v.waitErr != nil || v.cmd.ProcessState == nil || !v.cmd.ProcessState.Success() {
			return fmt.Errorf("expected-exit cleanup rejected unsuccessful process: %v", v.waitErr)
		}
	default:
		return errors.New("expected-exit cleanup requires a reaped process")
	}
	return v.closeWithExpectedExit(true)
}

func (v *guestVM) closeWithExpectedExit(expected bool) error {
	var err error
	if v.client != nil {
		_ = v.client.Close()
	}
	if v.done != nil {
		select {
		case <-v.done:
			if !expected {
				err = v.processError()
			}
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
				return errors.Join(err, errors.New("QEMU did not exit within cleanup deadline; private state retained"))
			}
		}
	}
	if stopErr := v.tpm.stop(); stopErr != nil {
		return errors.Join(err, stopErr)
	}
	v.tpm = nil
	if v.base != nil {
		err = errors.Join(err, v.base.Close())
		v.base = nil
	}
	return errors.Join(err, os.RemoveAll(v.dir))
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
	// A timed-out session is never reused; only connect's no-effect readiness
	// probe may poll again on a fresh authenticated transport.
	client := v.client
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	session, err := v.client.NewSession()
	if err != nil {
		// x/crypto reports a closed channel response as unexpected packet(nil).
		// Preserve explicit channel rejection, otherwise classify the actual
		// terminal transport error, not that synthetic protocol diagnostic.
		_ = client.Close()
		transportErr := client.Wait()
		if ctx.Err() != nil {
			return result, fmt.Errorf("open pinned SSH session deadline: %w (transport closure: %v)", ctx.Err(), transportErr)
		}
		var rejected *ssh.OpenChannelError
		if errors.As(err, &rejected) {
			return result, fmt.Errorf("open pinned SSH session: %w (transport closure: %v)", err, transportErr)
		}
		return result, fmt.Errorf("open pinned SSH session: %v (transport closure: %w)", err, transportErr)
	}
	defer func() { _ = session.Close() }() // Run already checked remote completion.
	stdout, stderr := nativeexec.NewBuffer(limit), nativeexec.NewBuffer(limit)
	session.Stdin, session.Stdout, session.Stderr = input, stdout, stderr
	err = session.Run(command)
	if v.captureDiagnostics {
		defer func() {
			var exit *ssh.ExitError
			v.lastOperation = &guestOperationDiagnostic{
				Command: command, ExitCode: result.ExitCode,
				Completed:       ctx.Err() == nil && (err == nil || errors.As(err, &exit)),
				Stdout:          string(stdout.Bytes()[:min(stdout.Len(), 16<<10)]),
				Stderr:          string(stderr.Bytes()[:min(stderr.Len(), 16<<10)]),
				StdoutTruncated: stdout.Len() > 16<<10 || stdout.Truncated(),
				StderrTruncated: stderr.Len() > 16<<10 || stderr.Truncated(),
			}
		}()
	}
	if processErr := v.processError(); processErr != nil {
		return result, processErr
	}
	if ctx.Err() != nil {
		return result, fmt.Errorf("guest operation deadline: %w", ctx.Err())
	}
	if stdout.Truncated() || stderr.Truncated() {
		return result, errors.New("guest operation output exceeds capacity")
	}
	result.Stdout, result.Stderr = stdout.Bytes(), stderr.Bytes()
	// Do not print guest-controlled stderr: it may contain host facts or seed keys.
	if err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			result.ExitCode = exit.ExitStatus()
			return result, nil
		}
		return result, fmt.Errorf("guest operation transport failed: %w", err)
	}
	return result, nil
}
