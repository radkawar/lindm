package vmlab

import (
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/agent/statefs"
)

const snapshotMarker = "/.lindm-native-snapshot.json"

// InstallSnapshotEvidence qualifies copied bytes and literal directory links in
// an actual private root. The synthetic configuration is initially empty. This
// is not a packaged worker sandbox, host management or execution authority.
type InstallSnapshotEvidence struct {
	SourceSHA256        string                `json:"source_sha256"`
	ChangedSourceSHA256 string                `json:"changed_source_sha256"`
	SourceUnitPaths     []string              `json:"source_unit_paths"`
	NativeUnitPaths     []string              `json:"native_unit_paths"`
	DirectoryAlias      InstallProjectionLink `json:"directory_alias"`
	WantedLink          InstallProjectionLink `json:"wanted_link"`
	OutsideLinkAbsent   bool                  `json:"outside_link_absent"`
	Child               snapshotChildEvidence `json:"child"`
}

type snapshotChildEvidence struct {
	Version                       string `json:"version"`
	NativeStderr                  string `json:"native_stderr"`
	EnableStdout                  string `json:"enable_stdout"`
	State                         string `json:"state"`
	UID                           int    `json:"uid"`
	ExecThreadCapabilitiesCleared bool   `json:"exec_thread_capabilities_cleared"`
}

type snapshotChildInput struct {
	RootDevice     uint64   `json:"root_device"`
	RootInode      uint64   `json:"root_inode"`
	HostRootDevice uint64   `json:"host_root_device"`
	HostRootInode  uint64   `json:"host_root_inode"`
	Unit           string   `json:"unit"`
	UnitPaths      []string `json:"unit_paths"`
}

// CheckInstallSnapshot requires UID0, chroot/mknod bootstrap capabilities, a
// static installed lab executable, and a protected mode-0700 work directory on
// an executable, device-capable filesystem.
// It creates and removes only its private fixture; no host unit is installed.
func CheckInstallSnapshot(ctx context.Context, workDir string) (_ *InstallSnapshotEvidence, resultErr error) {
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 || workDir == "" {
		return nil, errors.New("snapshot qualification requires root and an explicit protected work directory")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	parent, err := filepath.Abs(workDir)
	if err != nil {
		return nil, err
	}
	parentFD, err := statefs.OpenDirectory(parent)
	if err != nil {
		return nil, fmt.Errorf("snapshot qualification requires a protected root-owned mode-0700 work directory: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(parentFD)) }()
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(parentFD, &filesystem); err != nil {
		return nil, err
	}
	if filesystem.Flags&(unix.ST_NOEXEC|unix.ST_NODEV) != 0 {
		return nil, errors.New("snapshot qualification bootstrap requires an executable, device-capable work filesystem")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(parent, "lindm-snapshot-")
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(work)) }()
	units, external, alias := work+"/units", work+"/external", work+"/directory-alias"
	rootPath := work + "/root"
	for _, path := range []string{units, external, rootPath} {
		if err := os.Mkdir(path, 0700); err != nil {
			return nil, err
		}
	}
	unit := "snapshot-copied-" + rand.Text() + ".service"
	definition := external + "/" + unit
	if err := os.WriteFile(definition, snapshotUnitBytes("snapshot-captured.target"), 0600); err != nil {
		return nil, err
	}
	if err := os.Symlink(external, alias); err != nil {
		return nil, err
	}
	if err := os.Symlink(alias+"/"+unit, units+"/"+unit); err != nil {
		return nil, err
	}
	runtimeFiles, err := serviceprovider.InstallRuntimeFiles(ctx)
	if err != nil {
		return nil, err
	}
	inputs := serviceprovider.InstallSnapshotInputs{
		UnitPaths:    []string{units, alias},
		ContextFiles: []string{"/etc/ld.so.cache", "/etc/ld.so.preload", "/etc/os-release", "/usr/lib/os-release", "/etc/machine-id", "/etc/machine-info", "/dev/null"},
		RuntimeFiles: append(runtimeFiles, self),
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	captured, err := serviceprovider.CaptureInstallSnapshot(ctx, root, inputs)
	if err != nil {
		return nil, fmt.Errorf("capture native fixture: %w", err)
	}
	// Validate the executable actually copied into the root, not an earlier
	// version of its live pathname. No worker dependency closure is assumed.
	stagedSelf, err := root.Open(strings.TrimPrefix(self, "/"))
	if err != nil {
		return nil, err
	}
	program, parseErr := elf.NewFile(stagedSelf)
	if err := errors.Join(parseErr, stagedSelf.Close()); err != nil {
		return nil, err
	}
	for _, segment := range program.Progs {
		if segment.Type == elf.PT_INTERP {
			return nil, errors.New("snapshot qualification requires a static lab executable; build with CGO_ENABLED=0")
		}
	}
	fresh, err := serviceprovider.FingerprintInstallSnapshot(ctx, inputs)
	if err != nil {
		return nil, err
	}
	if fresh != captured {
		return nil, errors.New("unchanged source fingerprint differs from capture")
	}
	literal, err := root.Readlink(strings.TrimPrefix(alias, "/"))
	if err != nil || literal != external {
		return nil, fmt.Errorf("literal directory alias changed: %q: %v", literal, err)
	}
	if err := os.WriteFile(definition, snapshotUnitBytes("snapshot-live-changed.target"), 0600); err != nil {
		return nil, err
	}
	changed, err := serviceprovider.FingerprintInstallSnapshot(ctx, inputs)
	if err != nil {
		return nil, err
	}
	if changed == captured {
		return nil, errors.New("source definition change did not change fingerprint")
	}
	// This deliberately synthetic empty configuration is not a captured host
	// configuration or a source-authority claim. Production must bind its baseline.
	if err := root.MkdirAll("etc/systemd/system", 0700); err != nil {
		return nil, err
	}
	if err := root.Remove("dev/null"); err != nil {
		return nil, err
	}
	if err := unix.Mknod(rootPath+"/dev/null", unix.S_IFCHR|0600, int(unix.Mkdev(1, 3))); err != nil {
		return nil, err
	}
	var staged, host unix.Stat_t
	if err := unix.Stat(rootPath, &staged); err != nil {
		return nil, err
	}
	if err := unix.Stat("/", &host); err != nil {
		return nil, err
	}
	childInput := snapshotChildInput{RootDevice: staged.Dev, RootInode: staged.Ino, HostRootDevice: host.Dev, HostRootInode: host.Ino, Unit: unit, UnitPaths: append([]string{"/etc/systemd/system"}, inputs.UnitPaths...)}
	marker, err := json.Marshal(childInput)
	if err != nil {
		return nil, err
	}
	if err := root.WriteFile(strings.TrimPrefix(snapshotMarker, "/"), marker, 0600); err != nil {
		return nil, err
	}
	wanted := "/etc/systemd/system/snapshot-captured.target.wants/" + unit
	if err := snapshotAbsent(wanted); err != nil {
		return nil, err
	}
	stdout, stderr := nativeexec.NewBuffer(128<<10), nativeexec.NewBuffer(32<<10)
	command := exec.CommandContext(ctx, self, "native", "install-snapshot-child")
	command.SysProcAttr = &syscall.SysProcAttr{Chroot: rootPath}
	command.Dir, command.Env = "/", []string{"GOMAXPROCS=2"}
	command.Stdout, command.Stderr = stdout, stderr
	command.WaitDelay = time.Second
	if err := runSnapshotCommand(command); err != nil {
		return nil, fmt.Errorf("captured-root child: %w: %s", err, stderr.Bytes())
	}
	if stdout.Truncated() || stderr.Truncated() {
		return nil, errors.New("captured-root child output exceeds limit")
	}
	var child snapshotChildEvidence
	if err := json.Unmarshal(stdout.Bytes(), &child); err != nil {
		return nil, err
	}
	if child.State != "enabled" || child.UID != 0 || !child.ExecThreadCapabilitiesCleared {
		return nil, errors.New("captured-root child evidence incomplete")
	}
	target, err := root.Readlink(strings.TrimPrefix(wanted, "/"))
	if err != nil {
		return nil, fmt.Errorf("captured WantedBy was not consumed: %w", err)
	}
	if target != alias+"/"+unit && target != definition {
		return nil, fmt.Errorf("unexpected native wanted target %q", target)
	}
	if err := snapshotAbsent(rootPath + "/etc/systemd/system/snapshot-live-changed.target.wants/" + unit); err != nil {
		return nil, err
	}
	if err := snapshotAbsent(wanted); err != nil {
		return nil, err
	}
	return &InstallSnapshotEvidence{
		SourceSHA256: hex.EncodeToString(captured[:]), ChangedSourceSHA256: hex.EncodeToString(changed[:]),
		SourceUnitPaths: inputs.UnitPaths, NativeUnitPaths: childInput.UnitPaths,
		DirectoryAlias: InstallProjectionLink{Path: alias, Target: literal},
		WantedLink:     InstallProjectionLink{Path: wanted, Target: target}, OutsideLinkAbsent: true, Child: child,
	}, nil
}

func snapshotAbsent(path string) error {
	_, err := os.Lstat(path)
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("fixture expected absent path %s: %v", path, err)
	}
	return nil
}

func snapshotUnitBytes(wanted string) []byte {
	return []byte("[Unit]\nDescription=Copied-root native fixture\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n[Install]\nWantedBy=" + wanted + "\n")
}

// RunInstallSnapshotChild is the private re-exec entrypoint for the lab fixture.
// It refuses the original host root even if invoked directly with the marker.
func RunInstallSnapshotChild(ctx context.Context, output io.Writer) error {
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("snapshot child requires root")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	fd, err := unix.Open(snapshotMarker, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), snapshotMarker)
	var marker unix.Stat_t
	if err := unix.Fstat(fd, &marker); err != nil {
		_ = file.Close()
		return err
	}
	if marker.Mode&unix.S_IFMT != unix.S_IFREG || marker.Uid != 0 || marker.Mode&07777 != 0600 || marker.Size < 1 || marker.Size > 64<<10 {
		_ = file.Close()
		return errors.New("snapshot child marker is not a protected bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	closeErr := file.Close()
	if err := errors.Join(err, closeErr); err != nil {
		return err
	}
	if len(data) > 64<<10 {
		return errors.New("snapshot child marker exceeds limit")
	}
	var input snapshotChildInput
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	var root unix.Stat_t
	if err := unix.Stat("/", &root); err != nil {
		return err
	}
	if input.RootInode == 0 || input.HostRootInode == 0 || root.Dev != input.RootDevice || root.Ino != input.RootInode || (root.Dev == input.HostRootDevice && root.Ino == input.HostRootInode) {
		return errors.New("snapshot child is not in its distinct captured root")
	}
	if !strings.HasPrefix(input.Unit, "snapshot-copied-") || !strings.HasSuffix(input.Unit, ".service") || strings.ContainsAny(input.Unit, "/\\:\x00") || len(input.Unit) > 128 || len(input.UnitPaths) != 3 || input.UnitPaths[0] != "/etc/systemd/system" {
		return errors.New("invalid snapshot child fixture identity")
	}
	for _, path := range input.UnitPaths {
		if !strings.HasPrefix(path, "/") || len(path) > 4096 || strings.ContainsAny(path, ":\x00") {
			return errors.New("invalid snapshot child unit path")
		}
	}
	// Credential and NNP changes are per-thread. All native execs must stay on
	// this thread; this does not claim every Go runtime thread lost privileges.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if err := unix.Capset(&header, &caps[0]); err != nil {
		return err
	}
	if err := unix.Capget(&header, &caps[0]); err != nil {
		return err
	}
	if caps != [2]unix.CapUserData{} {
		return errors.New("snapshot child retains capabilities")
	}
	diagnostics := nativeexec.NewBuffer(32 << 10)
	version, err := snapshotNative(ctx, input.UnitPaths, diagnostics, "--version")
	if err != nil {
		return err
	}
	args := []string{"--system", "--root=/", "--no-reload", "--no-ask-password", "--no-pager", "enable", "--", input.Unit}
	enabled, err := snapshotNative(ctx, input.UnitPaths, diagnostics, args...)
	if err != nil {
		return err
	}
	args[5] = "is-enabled"
	state, err := snapshotNative(ctx, input.UnitPaths, diagnostics, args...)
	if err != nil {
		return err
	}
	if string(state) != "enabled\n" {
		return fmt.Errorf("unexpected private native state %q", state)
	}
	return json.NewEncoder(output).Encode(snapshotChildEvidence{Version: strings.TrimSpace(string(version)), NativeStderr: diagnostics.String(), EnableStdout: string(enabled), State: "enabled", UID: os.Getuid(), ExecThreadCapabilitiesCleared: true})
}

func snapshotNative(ctx context.Context, paths []string, diagnostics *nativeexec.Buffer, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	command.Dir = "/"
	command.Env = []string{"LC_ALL=C", "PATH=/usr/bin", "SYSTEMCTL_SKIP_SYSV=1", "SYSTEMD_LOG_TARGET=console", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat", "SYSTEMD_UNIT_PATH=" + strings.Join(paths, ":")}
	stdout := nativeexec.NewBuffer(64 << 10)
	command.Stdout, command.Stderr = stdout, diagnostics
	command.WaitDelay = time.Second
	if err := runSnapshotCommand(command); err != nil {
		return nil, fmt.Errorf("private native command: %w: %s: %s", err, stdout.Bytes(), diagnostics.Bytes())
	}
	if stdout.Truncated() || diagnostics.Truncated() {
		return nil, errors.New("private native command output exceeds limit")
	}
	return stdout.Bytes(), nil
}

// runSnapshotCommand is not labexec: a chroot or NNP child must be forked from
// this locked, privilege-dropped thread, which also owns its Pdeathsig.
func runSnapshotCommand(command *exec.Cmd) error {
	// Linux parent-death signals belong to the creating thread. Keep it alive
	// until Wait, so runtime thread retirement cannot kill a healthy child.
	// This also kills the fixed native subprocess if its lab parent is canceled.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.Pdeathsig = syscall.SIGKILL
	return command.Run()
}
