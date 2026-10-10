//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const (
	rootInventoryOutputLimit     = 80 << 10
	rootInventoryDiagnosticLimit = 8 << 10
	rootInventoryCleanupTimeout  = time.Second
	rootInventoryWaitDelay       = 100 * time.Millisecond
)

// observeRootInventory starts a new host-device observation for every request.
// The executor itself keeps PrivateDevices: only this short-lived, read-only
// unit sees host block devices. Neither configuration nor caller arguments cross
// the boundary; systemd-run is the native D-Bus frontend, not a shell.
func (s *Service) observeRootInventory(ctx context.Context) (*inventoryv1.RootObservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	boot, err := s.bootID()
	if _, parseErr := uuid.Parse(boot); err != nil || parseErr != nil {
		return nil, errInternal
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	unit := "lindm-inventory-" + id + ".service"
	run := s.rootInventoryCommand
	if run == nil {
		run = runRootInventoryCommand
	}
	// Reserve cleanup and pipe-join time within the RPC's 15-second budget.
	// Early caller cancellation still joins bounded cleanup independently.
	deadline := time.Now().Add(12 * time.Second)
	if outer, ok := ctx.Deadline(); ok && outer.Add(-2*time.Second).Before(deadline) {
		deadline = outer.Add(-2 * time.Second)
	}
	if !deadline.After(time.Now()) {
		return nil, context.DeadlineExceeded
	}
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	started := s.now()
	payload, runErr := run(call, "/usr/bin/systemd-run", rootInventoryArguments(unit)...)
	if runErr != nil || call.Err() != nil {
		// Even a failed/timed-out start may already have reached PID 1. StopUnit
		// waits for the cgroup to stop; RuntimeMaxSec is an independent backstop
		// if PID 1 cannot be reached. Never return before the stop command joins.
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), rootInventoryCleanupTimeout)
		_, stopErr := run(cleanup, "/usr/bin/systemctl", "--no-ask-password", "stop", unit)
		stop()
		return nil, errors.Join(errInternal, runErr, call.Err(), stopErr)
	}
	if len(payload) == 0 || len(payload) > rootInventoryOutputLimit {
		return nil, errInternal
	}
	root := new(inventoryv1.RootObservation)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, root); err != nil {
		return nil, errInternal
	}
	if err := s.admit(root); err != nil {
		return nil, errInternal
	}
	currentBoot, err := s.bootID()
	if err != nil || currentBoot != boot || root.GetBootId() != boot || ctx.Err() != nil ||
		root.GetStartedAt().AsTime().Before(started) || root.GetFinishedAt().AsTime().After(s.now()) {
		return nil, errInternal
	}
	return root, nil
}

func rootInventoryArguments(unit string) []string {
	return []string{
		"--quiet", "--no-ask-password", "--pipe", "--wait", "--collect", "--unit=" + unit,
		"--property=Type=exec", "--property=User=root", "--property=Group=root",
		"--property=PrivateDevices=no", "--property=DevicePolicy=closed", "--property=DeviceAllow=block-* r",
		"--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=", "--property=NoNewPrivileges=yes",
		"--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
		"--property=PrivateNetwork=yes", "--property=RestrictAddressFamilies=AF_UNIX",
		"--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectKernelLogs=yes",
		"--property=ProtectClock=yes", "--property=ProtectHostname=yes", "--property=ProtectProc=invisible",
		"--property=ProtectControlGroups=yes", "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
		"--property=RestrictSUIDSGID=yes", "--property=LockPersonality=yes", "--property=MemoryDenyWriteExecute=yes",
		"--property=SystemCallArchitectures=native", "--property=SystemCallFilter=@system-service",
		"--property=InaccessiblePaths=-/etc/lindm -/var/lib/lindm -/run/lindm",
		"--property=UMask=0077", "--property=WorkingDirectory=/",
		"--property=RuntimeMaxSec=10s", "--property=TimeoutStartSec=10s", "--property=TimeoutStopSec=500ms",
		"--property=KillMode=control-group", "--property=SendSIGKILL=yes", "--property=TasksMax=64",
		"--property=MemoryMax=256M", "--property=LimitCORE=0", "--property=LimitNOFILE=256",
		"--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin", "--setenv=LC_ALL=C", "--setenv=LANG=C",
		"--", "/usr/libexec/lindm/lindm-agent", "inventory-observe",
	}
}

type rootInventoryOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *rootInventoryOutput) Write(p []byte) (int, error) {
	n := len(p)
	if n > b.limit-b.buffer.Len() {
		b.overflow = true
		p = p[:b.limit-b.buffer.Len()]
	}
	_, err := b.buffer.Write(p)
	return n, err
}

// Keep diagnostics bounded and internal. Error strings never include native
// output, which may contain device identities or the helper's JSON payload.
type rootInventoryFailure struct {
	cause      error
	diagnostic string
}

func (e *rootInventoryFailure) Error() string { return "root inventory native command failed" }
func (e *rootInventoryFailure) Unwrap() error { return e.cause }

func runRootInventoryCommand(ctx context.Context, executable string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = rootInventoryWaitDelay
	stdout := rootInventoryOutput{limit: rootInventoryOutputLimit}
	stderr := rootInventoryOutput{limit: rootInventoryDiagnosticLimit}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if stdout.overflow || stderr.overflow {
		err = errors.Join(err, errors.New("root inventory command output exceeds bound"))
	}
	if err != nil || ctx.Err() != nil {
		return nil, &rootInventoryFailure{cause: errors.Join(err, ctx.Err()), diagnostic: stderr.buffer.String()}
	}
	return stdout.buffer.Bytes(), nil
}
