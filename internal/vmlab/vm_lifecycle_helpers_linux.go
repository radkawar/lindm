// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
)

const guestLifecycleProbe = "/var/tmp/lindm-native-lab/lab-probe"

func uploadLifecycleProbe(ctx context.Context, vm *guestVM, path string) error {
	file, err := openRegular(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	_, machine, err := inspectArchitecture(vm.hardware.Architecture)
	if err != nil {
		return err
	}
	binary, err := elf.NewFile(file)
	if err != nil || binary.Machine != machine || binary.Class != elf.ELFCLASS64 || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) {
		return errors.New("laboratory probe must be an executable ELF matching the guest architecture")
	}
	hash := sha256.New()
	if _, err := copyVMBytes(ctx, hash, file, 256<<20); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	command := "sudo -n sh -eu -c 'umask 022; cat > " + guestLifecycleProbe + "; chmod 0555 " + guestLifecycleProbe + "; printf \"%s  %s\\n\" " + digest + " " + guestLifecycleProbe + " | sha256sum --check --status'"
	if _, err := vm.run(ctx, command, file, 1024, time.Minute); err != nil {
		return fmt.Errorf("upload laboratory probe over pinned SSH: %w", err)
	}
	return nil
}

func interruptBootstrap(ctx context.Context, vm *guestVM, material *vmBootstrapMaterial) (*labv1.InterruptedBootstrapEvidence, error) {
	request := &agentv1.PrepareBootstrapRequest{ExecutionRootJson: material.ExecutionRootJSON, BootstrapEnvelope: material.BootstrapEnvelope, PendingGrant: string(material.GrantSecret)}
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(request)
	request.PendingGrant = ""
	if err != nil {
		return nil, errors.New("encode protected laboratory bootstrap input")
	}
	defer clear(payload)
	data, err := vm.run(ctx, "sudo -n "+guestLifecycleProbe+" guest bootstrap-interrupted", bytes.NewReader(payload), 16<<10, time.Minute)
	if err != nil {
		return nil, fmt.Errorf("interrupt after real enrollment issuance: %w", err)
	}
	evidence := new(labv1.InterruptedBootstrapEvidence)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, evidence); err != nil {
		return nil, errors.New("invalid interrupted-issuance evidence encoding")
	}
	if err := protovalidate.Validate(evidence); err != nil {
		return nil, errors.New("invalid interrupted-issuance evidence contract")
	}
	return evidence, nil
}

func probeGuestPrivileges(ctx context.Context, vm *guestVM) (*labv1.NetworkBoundaryEvidence, error) {
	data, err := vm.run(ctx, "sudo -n runuser -u lindm -- "+guestLifecycleProbe+" guest network-boundaries", nil, 16<<10, time.Minute)
	if err != nil {
		return nil, fmt.Errorf("actual network-UID boundary probe: %w", err)
	}
	evidence := new(labv1.NetworkBoundaryEvidence)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, evidence); err != nil {
		return nil, errors.New("invalid network-boundary evidence encoding")
	}
	if err := protovalidate.Validate(evidence); err != nil {
		return nil, errors.New("invalid network-boundary evidence contract")
	}
	return evidence, nil
}

// systemctlKillWhom expands, in a guest shell, to systemctl's process-selection
// option: systemd 252 renamed --kill-who= to --kill-whom= (still accepting the
// old name), while Ubuntu 22.04's systemd 249 knows only --kill-who=. Append
// "=main" or "=all".
const systemctlKillWhom = `$(systemctl --kill-whom=main --version >/dev/null 2>&1 && echo --kill-whom || echo --kill-who)`

func lifecycleCommand(ctx context.Context, vm *guestVM, phase, command string) error {
	return lifecycleCommandWithin(ctx, vm, phase, command, time.Minute)
}

func lifecycleCommandWithin(ctx context.Context, vm *guestVM, phase, command string, timeout time.Duration) error {
	result, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(command), nil, 1<<20, timeout)
	if err != nil {
		return fmt.Errorf("%s: %w", phase, err)
	}
	if result.ExitCode != 0 {
		stderr := strings.TrimSpace(string(result.Stderr))
		if len(stderr) > 512 {
			stderr = stderr[:512]
		}
		return fmt.Errorf("%s: guest exit %d (stdout bytes %d, stderr bytes %d): %q", phase, result.ExitCode, len(result.Stdout), len(result.Stderr), stderr)
	}
	return nil
}

func waitGuestExecutorReady(ctx context.Context, vm *guestVM, expected agentv1.Lifecycle) (*agentv1.StatusResponse, error) {
	// Unlike the installed status command, this probe cannot report an offline
	// journal inspection as readiness. Its bounded wait authenticates the root
	// executor peer and completes an actual Status RPC.
	data, err := vm.run(ctx, "sudo -n "+guestLifecycleProbe+" guest executor-ready", nil, 64<<10, 45*time.Second)
	if err != nil {
		return nil, fmt.Errorf("wait for executor RPC readiness: %w", err)
	}
	status := new(agentv1.StatusResponse)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, status); err != nil {
		return nil, errors.New("executor readiness is not strict StatusResponse protobuf JSON")
	}
	if err := protovalidate.Validate(status); err != nil {
		return nil, errors.New("executor readiness status does not satisfy its protobuf contract")
	}
	if status.GetLifecycle() != expected {
		return nil, fmt.Errorf("executor RPC is ready with lifecycle %s, expected %s", status.GetLifecycle(), expected)
	}
	return status, nil
}

func openLifecycleForwards(ctx context.Context, vm *guestVM, destinations [2]string) ([]*guestForward, error) {
	return openGuestForwards(ctx, vm, [2]string{"127.0.0.1:18444", "127.0.0.1:18445"}, destinations)
}

func openGuestForwards(ctx context.Context, vm *guestVM, addresses, destinations [2]string) ([]*guestForward, error) {
	var forwards []*guestForward
	for i, address := range addresses {
		forward, err := newGuestForward(ctx, vm, address, destinations[i])
		if err != nil {
			return nil, errors.Join(err, closeLifecycleForwards(forwards))
		}
		forwards = append(forwards, forward)
	}
	return forwards, nil
}

func closeLifecycleForwards(forwards []*guestForward) error {
	var result error
	for _, forward := range forwards {
		result = errors.Join(result, forward.Close())
	}
	return result
}

func rebootLifecycleGuest(ctx context.Context, vm *guestVM, previousBoot string) error {
	previous, err := uuid.Parse(previousBoot)
	if err != nil || previous == uuid.Nil {
		return errors.New("previous protected boot ID is invalid")
	}
	if vm.client == nil {
		return errors.New("guest reboot requires the old pinned SSH connection")
	}
	if err := lifecycleCommand(ctx, vm, "schedule real guest reboot", "systemd-run --quiet --on-active=2s --unit=lindm-lab-reboot /usr/bin/systemctl reboot"); err != nil {
		return err
	}
	return awaitLifecycleGuestBoot(ctx, vm, previous, 6*time.Minute)
}

// awaitLifecycleGuestBoot waits, without issuing any reboot, for a fresh pinned
// connection to report a boot ID other than previous, then for cloud-init.
func awaitLifecycleGuestBoot(ctx context.Context, vm *guestVM, previous uuid.UUID, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := awaitGuestBootChange(ctx, vm, previous); err != nil {
		return err
	}
	_, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute)
	return err
}

// awaitGuestBootChange waits, without issuing any reboot, for a fresh pinned
// connection to report a boot ID other than previous. Installer-built
// goldens have no cloud-init to wait for.
func awaitGuestBootChange(ctx context.Context, vm *guestVM, previous uuid.UUID) error {
	return waitGuestBootChange(ctx, previous, func(probe context.Context) (string, error) {
		// QEMU/slirp can retain the old host TCP connection after the guest
		// has rebooted. A FIN is neither necessary nor sufficient boot proof.
		if vm.client != nil {
			_ = vm.client.Close()
			vm.client = nil
		}
		if err := vm.connect(probe); err != nil {
			return "", err
		}
		boot, err := vm.run(probe, "cat /proc/sys/kernel/random/boot_id", nil, 128, 10*time.Second)
		return strings.TrimSpace(string(boot)), err
	})
}

// Only a fresh pinned connection reporting a changed boot ID establishes the
// reboot boundary. Polls are read-only; the reboot command is never replayed.
// A probe can reach the old boot's sshd just before shutdown stops it; the
// killed session then ends without an exit status (observed on EL 10 guests)
// and is retried like any other transport loss of the old boot.
func waitGuestBootChange(ctx context.Context, previous uuid.UUID, probe func(context.Context) (string, error)) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait for changed guest boot ID: %w", err)
		}
		boot, err := probe(ctx)
		if err != nil {
			var missing *ssh.ExitMissingError
			if !sshBootNotReady(err) && !errors.As(err, &missing) {
				return fmt.Errorf("probe reconnected guest boot ID: %w", err)
			}
		} else {
			id, err := uuid.Parse(boot)
			if err != nil || id == uuid.Nil {
				return errors.New("reconnected guest boot ID is invalid")
			}
			if id != previous {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for changed guest boot ID: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitGuestAuthorityRejection(ctx context.Context, vm *guestVM) error {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	for {
		status, err := readGuestAgentStatus(ctx, vm)
		if err != nil {
			return err
		}
		if status.GetTransportReportState() == agentv1.TransportReportState_TRANSPORT_REPORT_STATE_RECORDED && status.GetTransport().GetLastAttempt() == agentv1.TransportOutcome_TRANSPORT_OUTCOME_AUTHORITY_REJECTED {
			return nil
		}
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return fmt.Errorf("installed network process did not observe revocation: %w", err)
		}
	}
}

func holdMissingGuestJournal(ctx context.Context, vm *guestVM) error {
	if err := lifecycleCommand(ctx, vm, "remove protected database without its marker", "systemctl stop lindm-agent.service lindm-executor.service; test -f /var/lib/lindm/executor/installation; test -f /var/lib/lindm/executor/journal.sqlite; test ! -e /var/lib/lindm/executor/journal.sqlite.lindm-lab-held; mv /var/lib/lindm/executor/journal.sqlite /var/lib/lindm/executor/journal.sqlite.lindm-lab-held; systemctl start lindm-executor.service"); err != nil {
		return err
	}
	status, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_RECOVERY_HOLD)
	if err != nil {
		return err
	}
	if status.GetTlsUsable() {
		return errors.New("missing protected journal did not fail closed")
	}
	attempt, err := vm.runResult(ctx, "sudo -n "+packaging.BinaryPath+" resume", nil, 16<<10, 15*time.Second)
	if err != nil {
		return err
	}
	if attempt.ExitCode != 1 {
		return errors.New("missing protected journal accepted a resume operation")
	}
	if err := lifecycleCommand(ctx, vm, "confirm held identity was not recreated", "test -f /var/lib/lindm/executor/installation; test ! -e /var/lib/lindm/executor/journal.sqlite"); err != nil {
		return err
	}
	after, err := readGuestAgentStatus(ctx, vm)
	if err != nil {
		return err
	}
	if after.GetExecutor().GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_RECOVERY_HOLD {
		return errors.New("resume cleared protected recovery hold")
	}
	return nil
}

func lifecycleDelay(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// lifecycleFailureCommand collects the installed units' state. Package
// preparation and apply, and every other resource kind's effect and
// observation, run in transient lindm-package-*, lindm-resource-* and
// lindm-observe-* helper units whose journal alone carries the native tool's
// diagnostic; the executor logs only the reason code
// (package_staging_native_failed, native_effect_outcome_unknown).
const lifecycleFailureCommand = "systemctl status --no-pager --full lindm-executor.service lindm-agent.service; journalctl --no-pager -n 120 -u lindm-executor.service -u lindm-agent.service; journalctl --no-pager -n 120 -u 'lindm-package-*' -u 'lindm-resource-*' -u 'lindm-observe-*'; systemctl show lindm-agent.service -p MainPID -p RestrictAddressFamilies -p SystemCallFilter -p SystemCallErrorNumber -p IPAddressDeny; ls -ldZ / /etc /etc/lindm /etc/lindm/agent.json /etc/lindm/executor.json /var /var/lib /var/lib/lindm " + packaging.BinaryPath + " /var/lib/lindm/agent; namei -l /etc/lindm/agent.json /etc/lindm/executor.json; ps -eo pid,label,comm; journalctl --no-pager -k -n 120; journalctl --no-pager -n 80 _TRANSPORT=audit"

func saveLifecycleFailure(ctx context.Context, vm *guestVM, directory string) error {
	if vm.client == nil || vm.processError() != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	previous := vm.lastOperation
	result, err := vm.runResult(ctx, "sudo -n sh -c "+nativeQuote(lifecycleFailureCommand), nil, 2<<20, 8*time.Second)
	if err != nil {
		return fmt.Errorf("collect private lifecycle diagnostics: %w", err)
	}
	data, err := json.Marshal(struct {
		Source         string
		LastOperation  *guestOperationDiagnostic
		ExitCode       int
		Stdout, Stderr string
	}{"installed-agent-units", previous, result.ExitCode, string(result.Stdout), string(result.Stderr)})
	if err != nil {
		return err
	}
	path, err := saveGuestDiagnostics(directory, data)
	if err != nil {
		return err
	}
	return fmt.Errorf("private lifecycle diagnostics saved to %q", path)
}

// saveFixtureServerLog keeps the isolated lindmd's bounded log tail beside a
// failed lane's other private diagnostics.
func saveFixtureServerLog(fixture *devlab.AuthorityFixture, directory string) error {
	tail, err := fixture.ServerLogTail()
	if err != nil {
		return fmt.Errorf("collect private fixture server log: %w", err)
	}
	data, err := json.Marshal(struct {
		Source  string
		LogTail string
	}{"isolated-lindmd-log-tail", string(tail)})
	if err != nil {
		return err
	}
	path, err := saveGuestDiagnostics(directory, data)
	if err != nil {
		return err
	}
	return fmt.Errorf("private fixture server log saved to %q", path)
}
