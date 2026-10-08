//go:build linux

package vmlab

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
)

func vmCrashRunningService(ctx context.Context, packages *nativeGuestPackages, prepare func(agentv1.ServiceRuntimeState, agentv1.ServiceEnablement) (*vmPreparedService, error)) ([]*agentv1.ServiceExecutionStatus, error) {
	vm := packages.vm
	unit := devlab.ServiceExecutionProbeUnit
	path := "/etc/systemd/system/" + unit
	// The slow native pre-start creates an observable RUNNING transaction. The
	// native job must survive executor SIGKILL; the executor never owns its PID.
	definition := strings.Replace(signedServiceDefinition, "ExecStart=", "ExecStartPre=/usr/bin/sleep 20\nExecStart=", 1)
	if err := packages.uploadBytes(ctx, nativeGuestDir+"/signed-service-unit", []byte(definition)); err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "install slow signed fixture", "install -o root -g root -m 0644 "+nativeQuote(nativeGuestDir+"/signed-service-unit")+" "+nativeQuote(path)+"; if command -v restorecon >/dev/null 2>&1; then restorecon -F "+nativeQuote(path)+"; fi; systemctl daemon-reload"); err != nil {
		return nil, err
	}
	action, err := prepare(agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED)
	if err != nil {
		return nil, err
	}
	accepted := new(agentv1.StartServiceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "service-start", action.intent.GetActionId(), action.start, accepted); err != nil {
		return nil, err
	}
	window, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var invocation string
	for {
		status, err := vmGetService(window, packages, action.intent.GetActionId())
		if err != nil {
			return nil, err
		}
		state, id, err := vmServiceInvocation(window, vm)
		if err != nil {
			return nil, err
		}
		if status.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING && status.GetStartedAt() != nil && state == "activating" {
			invocation = id
			break
		}
		if status.GetState() >= agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED {
			return nil, errors.New("crash fixture completed before a running native job was observed")
		}
		if err := vmServicePause(window); err != nil {
			return nil, err
		}
	}
	if err := lifecycleCommand(ctx, vm, "crash executor during native service job", "systemctl kill --kill-whom=main --signal=KILL lindm-executor.service"); err != nil {
		return nil, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return nil, err
	}
	var reconciled *agentv1.ServiceExecutionStatus
	recovery, stop := context.WithTimeout(ctx, time.Minute)
	defer stop()
	for {
		status, err := vmGetService(recovery, packages, action.intent.GetActionId())
		if err != nil {
			return nil, err
		}
		if status.GetState() >= agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED {
			if status.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN && status.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED {
				return nil, errors.New("running crash was neither read-only convergence nor persistent unknown")
			}
			if status.GetStartedAt() == nil || status.GetCompletedAt() == nil {
				return nil, errors.New("running crash lost consumed-start evidence")
			}
			if status.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED && !status.GetVerification().GetConverged() {
				return nil, errors.New("running crash falsely claimed verified success")
			}
			reconciled = status
			break
		}
		if err := vmServicePause(recovery); err != nil {
			return nil, err
		}
	}
	for {
		state, id, err := vmServiceInvocation(recovery, vm)
		if err != nil {
			return nil, err
		}
		if id != invocation {
			return nil, errors.New("native service invocation changed across executor crash")
		}
		if state == "active" {
			break
		}
		if state != "activating" {
			return nil, errors.New("native service job did not survive executor crash")
		}
		if err := vmServicePause(recovery); err != nil {
			return nil, err
		}
	}
	if err := vmServiceNative(ctx, vm, "active", "enabled"); err != nil {
		return nil, err
	}
	replay := new(agentv1.StartServiceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "service-start", action.intent.GetActionId(), action.start, replay); err != nil {
		return nil, err
	}
	if !proto.Equal(reconciled, replay.GetStatus()) {
		return nil, errors.New("crashed action retry rewrote history or replayed effects")
	}
	_, afterReplay, err := vmServiceInvocation(ctx, vm)
	if err != nil {
		return nil, err
	}
	if afterReplay != invocation {
		return nil, errors.New("crashed action retry restarted native service")
	}
	inactive, err := prepare(agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED)
	if err != nil {
		return nil, err
	}
	stopped, err := vmStartService(ctx, packages, inactive)
	if err != nil {
		return nil, err
	}
	if err := vmServiceSucceeded(stopped, true); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	return []*agentv1.ServiceExecutionStatus{reconciled, stopped}, nil
}

func vmServiceInvocation(ctx context.Context, vm *guestVM) (string, string, error) {
	unit := nativeQuote(devlab.ServiceExecutionProbeUnit)
	data, err := vm.run(ctx, "sudo -n systemctl show --value --property=ActiveState "+unit+" && sudo -n systemctl show --value --property=InvocationID "+unit, nil, 256, 15*time.Second)
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "inactive" {
		return lines[0], "", nil // QUEUED/RUNNING may precede native submission.
	}
	if len(lines) != 2 || len(lines[1]) != 32 {
		return "", "", errors.New("missing native service invocation identity")
	}
	if _, err := hex.DecodeString(lines[1]); err != nil || lines[1] == strings.Repeat("0", 32) {
		return "", "", errors.New("invalid native service invocation identity")
	}
	return lines[0], lines[1], nil
}

func vmServicePause(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
