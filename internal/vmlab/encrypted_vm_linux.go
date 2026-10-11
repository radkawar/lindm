//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	labv1 "lindm/gen/lindm/lab/v1"
)

// EncryptedVMOptions selects private caches and an exact installed firmware package.
// These are lab process options, not production device configuration.
type EncryptedVMOptions struct {
	CacheDir  string
	GoldenDir string
	WorkDir   string
	Firmware  EncryptedFirmwareOptions
	Hardware  *VMHardwareOptions
	Desktop   string
	TPMBoot   bool
	// RequireCachedGolden forbids installer provisioning when the pinned golden
	// is absent. Read-only observation lanes must set this option.
	RequireCachedGolden bool
}

// UnlockOutcome distinguishes observed boot success from merely submitting a key.
// A failed or interrupted boot never proves that disk contents were erased.
type UnlockOutcome struct {
	Accepted   bool   `json:"accepted"`
	PromptSeen bool   `json:"prompt_seen"`
	BootID     string `json:"boot_id,omitempty"`
}

// EncryptedVM owns a disposable disk overlay, NVRAM and software TPM as one unit.
// Methods are sequential except Kill, which may interrupt a guest Run call.
// Never use this harness or its lab-only golden credentials on a real endpoint.
type EncryptedVM struct {
	dir            string
	guest          *guestVM
	tpm            *encryptedProcess
	firmware       *EncryptedFirmwareEvidence
	config         *ssh.ClientConfig
	initialSecret  string
	cacheDir       string
	hardware       VMHardwareOptions
	recoveryActive bool
	closed         bool
}

type encryptedProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	log  *vmLog
}

func startEncryptedProcess(ctx context.Context, dir, name string, args ...string) (*encryptedProcess, error) {
	// Not labexec: the Pdeathsig must be bound to a thread locked for the process's lifetime.
	p := &encryptedProcess{cmd: exec.CommandContext(ctx, name, args...), done: make(chan struct{}), log: new(vmLog)}
	p.cmd.Dir = dir
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	p.cmd.WaitDelay = 2 * time.Second
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := p.cmd.Start()
		started <- err
		if err == nil {
			p.err = p.cmd.Wait()
		}
		close(p.done)
	}()
	if err := <-started; err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	return p, nil
}

func (p *encryptedProcess) stop() error {
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		return nil
	default:
	}
	if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-p.done:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("encrypted VM process failed to stop")
	}
}

// NewEncryptedVM obtains a verified installer-built golden machine and clones all
// mutable state. The returned machine is powered off; call ColdBoot explicitly.
func NewEncryptedVM(ctx context.Context, manifest *labv1.ImageManifest, options EncryptedVMOptions) (_ *EncryptedVM, err error) {
	if options.CacheDir == "" {
		options.CacheDir = ".cache/lab/images"
	}
	hardware, err := encryptedMachineHardware(manifest, options)
	if err != nil {
		return nil, err
	}
	hardware.Desktop = hardware.Desktop || options.Desktop != ""
	golden, err := encryptedGolden(ctx, manifest, options)
	if err != nil {
		return nil, err
	}
	if options.WorkDir != "" {
		options.WorkDir, err = filepath.Abs(options.WorkDir)
		if err != nil {
			return nil, err
		}
	}
	dir, err := os.MkdirTemp(options.WorkDir, "lindm-encrypted-")
	if err != nil {
		return nil, err
	}
	v := &EncryptedVM{dir: dir, initialSecret: golden.Secret, firmware: golden.Firmware, cacheDir: options.CacheDir, hardware: hardware}
	defer func() {
		if err != nil {
			err = errors.Join(err, v.Close())
		}
	}()
	if err = copyEncryptedState(golden.Dir, dir); err != nil {
		return nil, err
	}
	if _, err = hostCommand(ctx, dir, "qemu-img", nil, "create", "-f", "qcow2", "-F", "qcow2", "-b", filepath.Join(golden.Dir, "disk.qcow2"), filepath.Join(dir, "disk.qcow2")); err != nil {
		return nil, err
	}
	for i := range hardware.ExtraDisks {
		name := fmt.Sprintf("extra-%d.qcow2", i)
		if _, err = hostCommand(ctx, dir, "qemu-img", nil, "create", "-f", "qcow2", name, "1G"); err != nil {
			return nil, err
		}
		if err = os.Chmod(filepath.Join(dir, name), 0600); err != nil {
			return nil, err
		}
	}
	v.config, err = encryptedSSHConfig(golden.LoginKey, golden.HostKey)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func encryptedMachineHardware(manifest *labv1.ImageManifest, options EncryptedVMOptions) (VMHardwareOptions, error) {
	if manifest == nil {
		return VMHardwareOptions{}, errors.New("encrypted VM requires an installer manifest")
	}
	architecture, _, err := encryptedInstallerArchitecture(manifest.Architecture)
	if err != nil {
		return VMHardwareOptions{}, err
	}
	hardware := VMHardwareOptions{TPM: true}
	if options.Hardware != nil {
		hardware = *options.Hardware
	}
	if hardware.Architecture != "" && hardware.Architecture != architecture {
		return hardware, errors.New("encrypted VM architecture differs from installer manifest")
	}
	hardware.Architecture = architecture
	hardware.Firmware = &options.Firmware
	return resolveVMHardware(&hardware, runtime.GOARCH)
}

func encryptedSSHConfig(loginKey, hostKey []byte) (*ssh.ClientConfig, error) {
	login, err := ssh.ParsePrivateKey(loginKey)
	if err != nil {
		return nil, err
	}
	host, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{User: labUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(login)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, Timeout: 5 * time.Second}, nil
}

// InitialUnlockSecret returns the lab-only installer passphrase. Do not record it.
func (v *EncryptedVM) InitialUnlockSecret() string { return v.initialSecret }

func (v *EncryptedVM) start(ctx context.Context, installer string) (err error) {
	if v.closed {
		return errors.New("encrypted VM is closed")
	}
	if v.recoveryActive {
		return errors.New("encrypted target is attached to a recovery VM")
	}
	if v.guest != nil {
		return errors.New("encrypted VM is already running")
	}
	hardware, resolveErr := resolveVMHardware(&v.hardware, runtime.GOARCH)
	if resolveErr != nil {
		return resolveErr
	}
	if err = checkVMAcceleration(hardware); err != nil {
		return err
	}
	for _, name := range []string{"serial.sock", "tpm.sock", "qmp.sock"} {
		if err = os.Remove(filepath.Join(v.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if hardware.TPM {
		v.tpm, err = startEncryptedProcess(ctx, v.dir, "swtpm", "socket", "--tpm2", "--tpmstate", "dir=tpm", "--ctrl", "type=unixio,path=tpm.sock,mode=0600", "--flags", "not-need-init")
		if err != nil {
			return err
		}
		defer func() {
			if err != nil {
				err = errors.Join(err, v.tpm.stop())
				v.tpm = nil
			}
		}()
		ready, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		for {
			if _, statErr := os.Stat(filepath.Join(v.dir, "tpm.sock")); statErr == nil {
				break
			}
			select {
			case <-ready.Done():
				return fmt.Errorf("swtpm socket: %w", ready.Err())
			case <-v.tpm.done:
				return fmt.Errorf("swtpm exited: %s", v.tpm.log.diagnostic(v.dir))
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.Join(err, listener.Close())
	}
	if err = listener.Close(); err != nil {
		return err
	}
	cpu := "max"
	if hardware.Accelerator == "kvm" {
		cpu = "host"
	}
	network := "user,id=net0,hostfwd=tcp:127.0.0.1:" + port + "-:22"
	if installer == "" && !hardware.AllowNetwork {
		network += ",restrict=on"
	}
	machine, emulator, serialDevice := "q35", "qemu-system-x86_64", "isa-serial,chardev=serial"
	if hardware.Architecture == "aarch64" {
		machine, emulator, serialDevice = "virt", "qemu-system-aarch64", ""
	}
	machine += ",accel=" + hardware.Accelerator
	if hardware.Architecture == "x86_64" && hardware.Firmware.SecureBoot {
		machine += ",smm=on"
	}
	args := []string{"-no-user-config", "-nodefaults", "-display", "none", "-monitor", "none", "-qmp", "unix:qmp.sock,server=on,wait=off", "-machine", machine, "-cpu", cpu, "-m", "4096", "-smp", "2",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=firmware-code.fd",
		"-drive", "if=pflash,format=raw,unit=1,file=nvram.fd",
		"-chardev", "socket,id=serial,path=serial.sock,server=on,wait=off",
		"-drive", "if=none,id=disk,format=qcow2,file=disk.qcow2", "-device", "virtio-rng-pci",
		"-netdev", network, "-device", "virtio-net-pci,netdev=net0,id=nic0"}
	if serialDevice == "" {
		args = append(args, "-serial", "chardev:serial")
	} else {
		args = append(args, "-device", serialDevice)
	}
	if hardware.Architecture == "x86_64" && hardware.Firmware.SecureBoot {
		args = append(args, "-global", "driver=cfi.pflash01,property=secure,value=on")
	}
	nodes := []string{"disk"}
	for i := range hardware.ExtraDisks {
		id := fmt.Sprintf("extra-%d", i)
		nodes = append(nodes, id)
		args = append(args, "-drive", "if=none,id="+id+",format=qcow2,file="+id+".qcow2")
	}
	args = append(args, vmStorageArguments(hardware, nodes, 1)...)
	if hardware.TPM {
		device := "tpm-tis"
		if hardware.Architecture == "aarch64" {
			device = "tpm-tis-device"
		}
		args = append(args, "-chardev", "socket,id=tpm,path=tpm.sock", "-tpmdev", "emulator,id=tpm0,chardev=tpm", "-device", device+",tpmdev=tpm0")
	}
	if hardware.Desktop {
		args = append(args, "-device", "virtio-gpu-pci", "-vnc", "unix:display.sock", "-device", "qemu-xhci,id=usb", "-device", "usb-tablet,bus=usb.0")
	}
	if installer != "" {
		relative, relErr := filepath.Rel(v.dir, installer)
		if relErr != nil {
			return relErr
		}
		if strings.ContainsAny(relative, ",\r\n") || strings.HasPrefix(relative, "..") {
			return errors.New("installer must reside inside private VM state")
		}
		args = append(args, "-drive", "if=none,id=installer,media=cdrom,readonly=on,format=raw,file="+relative)
		if hardware.Architecture == "aarch64" {
			args = append(args, "-device", "virtio-scsi-pci,id=installer-scsi", "-device", "scsi-cd,bus=installer-scsi.0,drive=installer,bootindex=0")
		} else {
			args = append(args, "-device", "ide-cd,drive=installer,bootindex=0")
		}
		args = append(args, "-no-reboot")
	}
	p, err := startEncryptedProcess(ctx, v.dir, emulator, args...)
	if err != nil {
		return err
	}
	v.guest = &guestVM{dir: v.dir, cmd: p.cmd, done: p.done, log: p.log, address: address, config: v.config, hardware: hardware, firmware: v.firmware, tpm: v.tpm}
	return nil
}

// ColdBoot starts from powered-off disk/NVRAM/TPM state, supplies the chosen
// passphrase only after an actual initramfs prompt, and proves SSH plus a boot ID.
// Recovery keys use exactly the same path as installer passphrases.
func (v *EncryptedVM) ColdBoot(ctx context.Context, secret string) (out UnlockOutcome, err error) {
	if strings.ContainsAny(secret, "\r\n\x00") {
		return out, errors.New("unlock secret must be a single line")
	}
	lifetime := ctx
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// The process lifetime belongs to the caller, not the readiness timeout.
	if err = v.start(lifetime, ""); err != nil {
		return out, err
	}
	success := false
	defer func() {
		if !success {
			err = errors.Join(err, v.Kill())
		}
	}()
	console, err := v.serial(ctx)
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, console.Close()) }()
	bootctx, stop := context.WithCancel(ctx)
	defer stop()
	type promptResult struct {
		seen bool
		err  error
	}
	prompt := make(chan promptResult, 1)
	go func() {
		seen, err := unlockEncryptedSerial(bootctx, console, secret)
		prompt <- promptResult{seen, err}
		if err != nil {
			stop()
		}
	}()
	err = v.guest.connect(bootctx)
	stop()
	_ = console.SetReadDeadline(time.Now())
	r := <-prompt
	out.PromptSeen = r.seen
	if r.err != nil {
		return out, r.err
	}
	if err == nil && secret != "" && !r.seen {
		return out, errors.New("guest booted without consuming the chosen unlock secret")
	}
	if err != nil {
		return out, err
	}
	data, err := v.guest.run(ctx, "cat /proc/sys/kernel/random/boot_id", nil, 128, 10*time.Second)
	if err != nil {
		return out, err
	}
	out.BootID = strings.TrimSpace(string(data))
	if len(out.BootID) != 36 {
		return out, errors.New("invalid observed guest boot ID")
	}
	out.Accepted = true
	success = true
	return out, nil
}

func (v *EncryptedVM) serial(ctx context.Context) (net.Conn, error) {
	for {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(v.dir, "serial.sock"))
		if err == nil {
			return conn, nil
		}
		if err = v.guest.processError(); err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func encryptedUnlockPrompt(text string) bool {
	text = strings.ToLower(text)
	return strings.Contains(text, "please unlock disk") || strings.Contains(text, "enter passphrase for") || strings.Contains(text, "please enter passphrase for disk")
}

func unlockEncryptedSerial(ctx context.Context, conn net.Conn, secret string) (bool, error) {
	var pending string
	sent := false
	buf := make([]byte, 4096)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return sent, err
		}
		n, err := conn.Read(buf)
		if n > 0 {
			pending += string(buf[:n])
			if len(pending) > 8192 {
				pending = pending[len(pending)-8192:]
			}
			// Some initramfs password agents report cryptsetup's rejection without
			// repeating the original prompt on the serial console.
			if sent && (strings.Contains(pending, "No key available with this passphrase.") ||
				strings.Contains(pending, "Failed to activate with specified passphrase. (Passphrase incorrect?)")) {
				return true, errors.New("encrypted boot rejected unlock secret")
			}
			if encryptedUnlockPrompt(pending) {
				if secret == "" {
					return true, errors.New("unattended encrypted boot requested a passphrase")
				}
				if sent {
					return true, errors.New("encrypted boot rejected unlock secret")
				}
				if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return sent, err
				}
				if _, err := io.WriteString(conn, secret+"\r"); err != nil {
					return sent, errors.New("submit encrypted boot unlock secret failed")
				}
				sent = true
				pending = ""
			}
		}
		if ctx.Err() != nil {
			return sent, nil
		}
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				continue
			}
			return sent, errors.New("encrypted boot serial console closed before readiness")
		}
	}
}

// Run is an out-of-band native test/oracle channel, never production authority.
// Input and output are not logged. Callers must keep secret-bearing output private.
func (v *EncryptedVM) Run(ctx context.Context, command string, input io.Reader) ([]byte, error) {
	if v.guest == nil {
		return nil, errors.New("encrypted VM is powered off")
	}
	return v.guest.run(ctx, command, input, 1<<20, 2*time.Minute)
}

// Kill cuts VM power without asking the guest, waits for disk writers to stop,
// then stops swtpm. Disk, NVRAM and TPM remain available for reconciliation.
func (v *EncryptedVM) Kill() error {
	var err error
	if v.recoveryActive {
		return errors.New("close recovery VM before stopping encrypted target")
	}
	if v.guest != nil {
		if v.guest.client != nil {
			_ = v.guest.client.Close()
		}
		p := &encryptedProcess{cmd: v.guest.cmd, done: v.guest.done}
		err = p.stop()
		if err == nil {
			v.guest = nil
		}
	}
	if err == nil {
		err = v.tpm.stop()
		if err == nil {
			v.tpm = nil
		}
	}
	return err
}

// PowerOff requests a real guest shutdown and waits before stopping swtpm.
func (v *EncryptedVM) PowerOff(ctx context.Context) error {
	if v.guest == nil {
		return errors.New("encrypted VM is powered off")
	}
	// Match the lifecycle reboot contract: first acknowledge a transient timer,
	// then observe actual process termination. Immediate poweroff can reap sshd
	// before it reports whether the request succeeded.
	if _, err := v.Run(ctx, "sudo systemd-run --quiet --on-active=2s --unit=lindm-lab-poweroff /usr/bin/systemctl poweroff", nil); err != nil {
		return err
	}
	select {
	case <-v.guest.done:
		if v.guest.cmd.ProcessState == nil || !v.guest.cmd.ProcessState.Success() {
			return errors.New("encrypted guest shutdown exited unsuccessfully")
		}
		return v.Kill()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// NetworkLink changes only this emulated NIC through its private QMP socket.
// It works while SSH is disconnected and never changes host networking.
func (v *EncryptedVM) NetworkLink(ctx context.Context, up bool) error {
	if v.guest == nil {
		return errors.New("encrypted VM is powered off")
	}
	return v.guest.setNetworkLink(ctx, up)
}

// Headers reads the stopped overlay through a read-only independent appliance.
func (v *EncryptedVM) Headers(ctx context.Context) ([]EncryptedHeader, error) {
	if v.guest != nil || v.tpm != nil || v.recoveryActive {
		return nil, errors.New("header oracle requires powered-off detached machine")
	}
	return readEncryptedHeaders(ctx, filepath.Join(v.dir, "disk.qcow2"), v.dir)
}

// HeadersAll observes the root and every additional disk, including whole-disk
// LUKS containers. Disk identifies the frozen root/extra-N attachment; UUIDs must
// be unique across the complete machine. No guest-supplied device path is used.
func (v *EncryptedVM) HeadersAll(ctx context.Context) ([]EncryptedHeader, error) {
	if v.guest != nil || v.tpm != nil || v.recoveryActive {
		return nil, errors.New("header oracle requires powered-off detached machine")
	}
	result := make([]EncryptedHeader, 0)
	seen := make(map[string]bool)
	for index := -1; index < v.hardware.ExtraDisks; index++ {
		disk, name := "root", "disk.qcow2"
		if index >= 0 {
			disk = fmt.Sprintf("extra-%d", index)
			name = disk + ".qcow2"
		}
		headers, err := readEncryptedHeaders(ctx, filepath.Join(v.dir, name), v.dir)
		if err != nil {
			return nil, fmt.Errorf("inspect encrypted %s: %w", disk, err)
		}
		for i := range headers {
			if seen[headers[i].UUID] {
				return nil, errors.New("duplicate LUKS UUID across machine disks")
			}
			seen[headers[i].UUID] = true
			headers[i].Disk = disk
		}
		result = append(result, headers...)
	}
	return result, nil
}

// Snapshot exports a complete powered-off machine, flattening the backing chain.
// destination must not exist. No disk-only snapshot/restore interface is provided.
func (v *EncryptedVM) Snapshot(ctx context.Context, destination string) (err error) {
	if v.guest != nil || v.tpm != nil || v.recoveryActive {
		return errors.New("snapshot requires powered-off detached machine")
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return err
	}
	if err = os.Mkdir(destination, 0700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(destination))
		}
	}()
	if err = copyEncryptedState(v.dir, destination); err != nil {
		return err
	}
	for i := range v.hardware.ExtraDisks {
		name := fmt.Sprintf("extra-%d.qcow2", i)
		if err = encryptedConvert(ctx, v.dir, filepath.Join(v.dir, name), filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	return encryptedConvert(ctx, v.dir, filepath.Join(v.dir, "disk.qcow2"), filepath.Join(destination, "disk.qcow2"))
}

// Close stops owned processes before removing only the private run directory.
func (v *EncryptedVM) Close() error {
	if v.closed {
		return nil
	}
	if err := v.Kill(); err != nil {
		return err
	}
	if err := os.RemoveAll(v.dir); err != nil {
		return err
	}
	v.closed = true
	return nil
}
