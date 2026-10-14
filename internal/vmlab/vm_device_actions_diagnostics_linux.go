// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/packaging"
)

func actionDiagnosticsDirectory(vm *guestVM) string {
	if vm.diagnosticsDir != "" {
		return vm.diagnosticsDir
	}
	return os.TempDir()
}

// observeActionGuest retains only the post-unlock console window and unit
// diagnostics, never credentials, configuration files or disk/header contents.
// A separate pinned connection diagnoses a failed transport; it never repeats
// enrollment or any action on the failed connection.
func observeActionGuest(ctx context.Context, vm *guestVM) (func(error) error, error) {
	started := time.Now().UTC()
	before, err := vm.run(ctx, "cat /proc/sys/kernel/random/boot_id; cat /proc/uptime", nil, 1024, 10*time.Second)
	if err != nil {
		return nil, err
	}
	serial := new(vmLog)
	var console net.Conn
	var drained chan struct{}
	path := filepath.Join(vm.dir, "serial.sock")
	if _, err := os.Stat(path); err == nil {
		console, err = (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		drained = make(chan struct{})
		go func() { _, _ = io.Copy(serial, console); close(drained) }()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return func(cause error) error {
		if console != nil {
			_ = console.Close()
			<-drained
		}
		if cause == nil {
			return nil
		}
		diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		probe := &guestVM{dir: vm.dir, cmd: vm.cmd, done: vm.done, waitErr: vm.waitErr, log: vm.log, address: vm.address, config: vm.config, tpm: vm.tpm}
		connectErr := probe.connect(diagnostic)
		var result guestCommandResult
		if connectErr == nil {
			defer func() { _ = probe.client.Close() }()
			command := "sudo -n sh -c " + nativeQuote("cat /proc/sys/kernel/random/boot_id; cat /proc/uptime; free -m; loginctl list-sessions --no-legend --no-pager; ps -eo pid,uid,comm; systemctl show ssh.service sshd.service lindm-executor.service lindm-agent.service -p Id -p ActiveState -p MainPID -p NRestarts -p ExecMainStartTimestamp -p ExecMainStatus; journalctl -b --no-pager -o short-monotonic --since '"+started.Format(time.RFC3339)+"' -u ssh.service -u sshd.service -u lindm-executor.service -u lindm-agent.service -u gdm.service -u gdm3.service; journalctl -b -k --no-pager -n 100")
			result, connectErr = probe.runResult(diagnostic, command, nil, 256<<10, 30*time.Second)
		}
		connectionFailure := ""
		if connectErr != nil {
			connectionFailure = connectErr.Error()
		}
		data, err := json.Marshal(struct {
			Started  time.Time `json:"started_at"`
			Finished time.Time `json:"finished_at"`
			Before   string    `json:"before_boot_id_uptime"`
			Serial   string    `json:"post_unlock_serial"`
			Journal  string    `json:"journal"`
			Stderr   string    `json:"stderr"`
			Failure  string    `json:"diagnostic_failure,omitempty"`
		}{started, time.Now().UTC(), string(before), serial.diagnostic(vm.dir), string(result.Stdout), string(result.Stderr), connectionFailure})
		if err != nil {
			return errors.Join(cause, err)
		}
		path, err := saveGuestDiagnostics(actionDiagnosticsDirectory(vm), data)
		if err != nil {
			return errors.Join(cause, err)
		}
		return errors.Join(cause, fmt.Errorf("private action guest diagnostics saved to %q", path))
	}, nil
}

func diagnoseActionFailure(ctx context.Context, vm *guestVM, cause error) error {
	if cause == nil || vm == nil {
		return cause
	}
	return errors.Join(cause, saveLifecycleFailure(ctx, vm, actionDiagnosticsDirectory(vm)))
}

// diagnoseNativeAction reads the protected executor view before guest cleanup.
// It never copies the journal database, credentials, keys or native headers.
func diagnoseNativeAction(ctx context.Context, vm *guestVM, actionID string, cause error) error {
	if cause == nil || vm == nil || !vmValidID(actionID) {
		return cause
	}
	diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	probe := &guestVM{dir: vm.dir, cmd: vm.cmd, done: vm.done, waitErr: vm.waitErr, log: vm.log, address: vm.address, config: vm.config, tpm: vm.tpm}
	type actionDiagnostic struct {
		ActionID       string                `json:"action_id"`
		ObservedAt     time.Time             `json:"observed_at"`
		Status         json.RawMessage       `json:"executor_status,omitempty"`
		StatusFailure  string                `json:"executor_status_failure,omitempty"`
		Journal        string                `json:"journal_tail"`
		JournalFailure string                `json:"journal_failure,omitempty"`
		Host           *HostResourceEvidence `json:"host_before_cleanup,omitempty"`
		HostFailure    string                `json:"host_observation_error,omitempty"`
	}
	result := actionDiagnostic{ActionID: actionID, ObservedAt: time.Now().UTC()}
	host, hostErr := captureHostResources()
	result.Host = host
	if hostErr != nil {
		result.HostFailure = hostErr.Error()
	}
	if err := probe.connect(diagnostic); err != nil {
		result.StatusFailure, result.JournalFailure = err.Error(), err.Error()
	} else {
		defer func() { _ = probe.client.Close() }()
		path, err := prepareActionStatusFile(diagnostic, probe, actionID)
		if err == nil {
			defer func() { _, _ = probe.run(diagnostic, "sudo -n rm -f -- "+nativeQuote(path), nil, 4096, 5*time.Second) }()
			status, readErr := probe.runResult(diagnostic, "sudo -n "+packaging.BinaryPath+" action-status -file "+nativeQuote(path), nil, 128<<10, 10*time.Second)
			if readErr != nil {
				err = readErr
			} else if status.ExitCode != 0 {
				err = fmt.Errorf("action-status exit %d: %s", status.ExitCode, status.Stderr)
			} else {
				result.Status, err = actionStatusDiagnostic(status.Stdout)
			}
		}
		if err != nil {
			result.StatusFailure = err.Error()
		}
		journal, err := probe.runResult(diagnostic, "sudo -n journalctl -b --no-pager -o short-iso-precise -n 200 -u lindm-executor.service -u lindm-agent.service -u lindm-live-root-poweroff.service", nil, 128<<10, 15*time.Second)
		result.Journal = string(journal.Stdout)
		if err != nil {
			result.JournalFailure = err.Error()
		} else if journal.ExitCode != 0 {
			result.JournalFailure = fmt.Sprintf("journalctl exit %d: %s", journal.ExitCode, journal.Stderr)
		}
	}
	data, err := json.Marshal(result)
	if err != nil {
		return errors.Join(cause, err)
	}
	path, err := saveGuestDiagnostics(actionDiagnosticsDirectory(vm), data)
	if err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, fmt.Errorf("private executor action diagnostics saved to %q", path))
}

func actionStatusDiagnostic(data []byte) (json.RawMessage, error) {
	decoded := new(agentv1.GetDeviceActionResponse)
	if err := protojson.Unmarshal(data, decoded); err != nil {
		return nil, err
	}
	// Even encrypted escrow material has no diagnostic purpose. Preserve
	// native outcome and timing, but never retain ciphertext or key digests.
	if verification := decoded.GetStatus().GetVerification(); verification != nil {
		verification.Escrow = nil
	}
	return protojson.Marshal(decoded)
}

type liveRootDiagnostic struct {
	ObservedAt time.Time                   `json:"observed_at"`
	Status     *agentv1.DeviceActionStatus `json:"executor_status,omitempty"`
	Journal    string                      `json:"journal_tail,omitempty"`
	Failure    string                      `json:"observation_failure,omitempty"`
}

// Live-root evidence is volatile and disappears at forced poweroff. Observe it
// on a separate pinned SSH transport while the server attestation oracle runs;
// diagnostic latency or cancellation must not block that oracle or its socket.
func monitorLiveRoot(ctx context.Context, vm *guestVM, actionID string) func() *liveRootDiagnostic {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	result := &liveRootDiagnostic{}
	go func() {
		defer close(done)
		probe := &guestVM{dir: vm.dir, cmd: vm.cmd, done: vm.done, waitErr: vm.waitErr, log: vm.log, address: vm.address, config: vm.config, tpm: vm.tpm}
		if err := probe.connect(ctx); err != nil {
			result.Failure = err.Error()
			return
		}
		defer func() { _ = probe.client.Close() }()
		path, err := prepareActionStatusFile(ctx, probe, actionID)
		if err != nil {
			result.Failure = err.Error()
			return
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer stop()
			_, _ = probe.run(cleanup, "sudo -n rm -f -- "+nativeQuote(path), nil, 4096, 2*time.Second)
		}()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			status, statusErr := nativeActionStatus(ctx, probe, path)
			if statusErr != nil {
				if ctx.Err() == nil {
					result.Failure = statusErr.Error()
				}
				return
			}
			if status != nil {
				if verification := status.GetVerification(); verification != nil {
					verification.Escrow = nil
				}
				result.Status, result.ObservedAt = status, time.Now().UTC()
			}
			journal, journalErr := probe.runResult(ctx, "sudo -n journalctl -b --no-pager -o short-iso-precise -n 200 -u lindm-executor.service -u lindm-agent.service -u lindm-live-root-poweroff.service", nil, 128<<10, 10*time.Second)
			if journalErr == nil && journal.ExitCode == 0 {
				result.Journal = string(journal.Stdout)
			} else if ctx.Err() == nil {
				result.Failure = fmt.Sprintf("live journal observation: %v; exit %d", journalErr, journal.ExitCode)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() *liveRootDiagnostic {
		cancel()
		<-done
		return result
	}
}
