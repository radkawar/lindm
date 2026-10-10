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
)

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
		path, err := saveGuestDiagnostics(os.TempDir(), data)
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
	return errors.Join(cause, saveLifecycleFailure(ctx, vm, os.TempDir()))
}
