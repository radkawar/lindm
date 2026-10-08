//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/protodata"
)

type vmServiceExecutionEvidence struct {
	Completed                 []*agentv1.ServiceExecutionStatus `json:"completed"`
	ForgedIntentRejected      bool                              `json:"forged_intent_rejected"`
	PlanCannotStart           bool                              `json:"plan_cannot_start"`
	ExactStartReplay          bool                              `json:"exact_start_replay"`
	ConflictingIntentRejected bool                              `json:"conflicting_intent_rejected"`
	ExpiredGrantRejected      bool                              `json:"expired_grant_rejected"`
	RestartGrantRejected      bool                              `json:"restart_grant_rejected"`
	StalePlanRejected         bool                              `json:"stale_plan_rejected"`
	RevokedGrantRejected      bool                              `json:"revoked_grant_rejected"`
	RunningCrashReconciled    bool                              `json:"running_crash_reconciled"`
}

type vmPreparedService struct {
	intent   *agentv1.ServiceExecutionIntent
	envelope []byte
	prepared *agentv1.PrepareServiceExecutionResponse
	start    *agentv1.StartServiceExecutionRequest
}

const signedServiceDefinition = `[Unit]
Description=Disposable signed executor service proof
[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
[Install]
WantedBy=multi-user.target
`

// This runs the installed agent as its network UID and lets the installed,
// sandboxed root executor perform every tested effect. Only sacrificial fixture
// setup/independent drift/cleanup use administrator systemctl commands.
func exerciseVMSignedServices(ctx context.Context, packages *nativeGuestPackages, signer *devlab.ExecutionTrustExercise, identity *labv1.ConnectionIdentityEvidence) (_ *vmServiceExecutionEvidence, err error) {
	vm := packages.vm
	unit := devlab.ServiceExecutionProbeUnit
	path := "/etc/systemd/system/" + unit
	if err := lifecycleCommand(ctx, vm, "reserve signed service fixture", "test ! -e "+nativeQuote(path)+" && test ! -L "+nativeQuote(path)); err != nil {
		return nil, err
	}
	if err := packages.uploadBytes(ctx, nativeGuestDir+"/signed-service-unit", []byte(signedServiceDefinition)); err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "install signed service fixture", "install -o root -g root -m 0644 "+nativeQuote(nativeGuestDir+"/signed-service-unit")+" "+nativeQuote(path)); err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err = errors.Join(err, lifecycleCommand(cleanup, vm, "remove signed service fixture", "systemctl disable --now "+nativeQuote(unit)+"; rm -- "+nativeQuote(path)+"; systemctl daemon-reload"))
	}()
	if err := lifecycleCommand(ctx, vm, "load signed service fixture", "if command -v restorecon >/dev/null 2>&1; then restorecon -F "+nativeQuote(path)+"; fi; systemctl daemon-reload"); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	result := new(vmServiceExecutionEvidence)
	var sequence uint64
	prepare := func(runtime agentv1.ServiceRuntimeState, enablement agentv1.ServiceEnablement) (*vmPreparedService, error) {
		sequence++
		return vmPrepareService(ctx, packages, signer, identity, sequence, runtime, enablement)
	}
	active, err := prepare(agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED)
	if err != nil {
		return nil, err
	}
	if active.prepared.GetStatus().GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED || !active.prepared.GetNativePlan().GetChangeRuntime() || !active.prepared.GetNativePlan().GetChangeEnablement() {
		return nil, errors.New("signed preflight did not record both required changes")
	}
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	forgedIntent := proto.CloneOf(active.intent)
	forgedIntent.ActionId = uuid.NewString()
	forgedIntent.ResourceSequence++
	signed, err := signer.SignServiceIntent(ctx, forgedIntent)
	if err != nil {
		return nil, err
	}
	var forged dsse.Envelope
	if err := json.Unmarshal(signed, &forged); err != nil {
		return nil, err
	}
	if len(forged.Signatures) != 1 {
		return nil, errors.New("forged fixture requires exactly one original signature")
	}
	forged.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, 64))
	encodedForged, err := json.Marshal(&forged)
	if err != nil {
		return nil, err
	}
	if err := vmRejectServiceRPC(ctx, packages, "service-prepare", "forged", &agentv1.PrepareServiceExecutionRequest{IntentEnvelope: encodedForged}, connect.CodePermissionDenied); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	result.ForgedIntentRejected = true
	if err := vmRejectServiceRPC(ctx, packages, "service-start", "plan-domain", &agentv1.StartServiceExecutionRequest{ActionId: active.intent.GetActionId(), StartGrantEnvelope: active.envelope}, connect.CodePermissionDenied); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	result.PlanCannotStart = true
	completed, err := vmStartService(ctx, packages, active)
	if err != nil {
		return nil, err
	}
	if err := vmServiceSucceeded(completed, true); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "active", "enabled"); err != nil {
		return nil, err
	}
	result.Completed = append(result.Completed, completed)
	replay := new(agentv1.StartServiceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "service-start", active.intent.GetActionId(), active.start, replay); err != nil {
		return nil, err
	}
	if !proto.Equal(replay.GetStatus(), completed) {
		return nil, errors.New("exact signed start retry changed terminal evidence")
	}
	result.ExactStartReplay = true
	conflict := proto.CloneOf(active.intent)
	conflict.DesiredRevision = uuid.NewString()
	conflictingEnvelope, err := signer.SignServiceIntent(ctx, conflict)
	if err != nil {
		return nil, err
	}
	if err := vmRejectServiceRPC(ctx, packages, "service-prepare", "conflict", &agentv1.PrepareServiceExecutionRequest{IntentEnvelope: conflictingEnvelope}, connect.CodeAlreadyExists); err != nil {
		return nil, err
	}
	result.ConflictingIntentRejected = true
	// Runtime-only stop and start qualify the later callback after job-match setup.
	for _, runtime := range []agentv1.ServiceRuntimeState{agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE} {
		action, err := prepare(runtime, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED)
		if err != nil {
			return nil, err
		}
		if !action.prepared.GetNativePlan().GetChangeRuntime() || action.prepared.GetNativePlan().GetChangeEnablement() {
			return nil, errors.New("runtime-only fixture did not isolate runtime effect")
		}
		status, err := vmStartService(ctx, packages, action)
		if err != nil {
			return nil, err
		}
		if err := vmServiceSucceeded(status, true); err != nil {
			return nil, err
		}
		want := "active"
		if runtime == agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE {
			want = "inactive"
		}
		if err := vmServiceNative(ctx, vm, want, "enabled"); err != nil {
			return nil, err
		}
		result.Completed = append(result.Completed, status)
	}
	noop, err := prepare(agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED)
	if err != nil {
		return nil, err
	}
	if err := vmServiceSucceeded(noop.prepared.GetStatus(), false); err != nil {
		return nil, err
	}
	if noop.prepared.GetNativePlan().GetChangeRuntime() || noop.prepared.GetNativePlan().GetChangeEnablement() || len(noop.prepared.GetChallengeProof()) != 0 {
		return nil, errors.New("no-drift intent acquired a start challenge")
	}
	noopStatus, err := vmGetService(ctx, packages, noop.intent.GetActionId())
	if err != nil {
		return nil, err
	}
	result.Completed = append(result.Completed, noopStatus)
	expired, err := prepare(agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(31 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	if err := vmRejectServiceRPC(ctx, packages, "service-start", expired.intent.GetActionId(), expired.start, connect.CodePermissionDenied); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "active", "enabled"); err != nil {
		return nil, err
	}
	expiredStatus, err := vmGetService(ctx, packages, expired.intent.GetActionId())
	if err != nil {
		return nil, err
	}
	if expiredStatus.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED || expiredStatus.GetStartedAt() != nil {
		return nil, errors.New("expired challenge did not retain a no-start terminal result")
	}
	result.Completed = append(result.Completed, expiredStatus)
	result.ExpiredGrantRejected = true
	restarted, err := prepare(agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED)
	if err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "restart signed executor", "systemctl restart lindm-executor.service"); err != nil {
		return nil, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return nil, err
	}
	if err := vmRejectServiceRPC(ctx, packages, "service-start", restarted.intent.GetActionId(), restarted.start, connect.CodePermissionDenied); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "active", "enabled"); err != nil {
		return nil, err
	}
	restartStatus, err := vmGetService(ctx, packages, restarted.intent.GetActionId())
	if err != nil {
		return nil, err
	}
	if restartStatus.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED || restartStatus.GetStartedAt() != nil {
		return nil, errors.New("same-boot restart retained usable challenge authority")
	}
	result.Completed = append(result.Completed, restartStatus)
	result.RestartGrantRejected = true
	stale, err := prepare(agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED)
	if err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "introduce independent service drift", "systemctl stop "+nativeQuote(unit)); err != nil {
		return nil, err
	}
	staleStatus, err := vmStartService(ctx, packages, stale)
	if err != nil {
		return nil, err
	}
	if staleStatus.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED || staleStatus.GetFailure() != agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_PRECONDITION || staleStatus.GetStartedAt() != nil {
		return nil, errors.New("stale service precondition did not fail before start consumption")
	}
	if err := vmServiceNative(ctx, vm, "inactive", "enabled"); err != nil {
		return nil, err
	}
	result.Completed = append(result.Completed, staleStatus)
	result.StalePlanRejected = true
	inactive, err := prepare(agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED)
	if err != nil {
		return nil, err
	}
	if inactive.prepared.GetNativePlan().GetChangeRuntime() || !inactive.prepared.GetNativePlan().GetChangeEnablement() {
		return nil, errors.New("disable fixture did not isolate enablement")
	}
	inactiveStatus, err := vmStartService(ctx, packages, inactive)
	if err != nil {
		return nil, err
	}
	if err := vmServiceSucceeded(inactiveStatus, true); err != nil {
		return nil, err
	}
	result.Completed = append(result.Completed, inactiveStatus)
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	crashEvidence, err := vmCrashRunningService(ctx, packages, prepare)
	if err != nil {
		return nil, err
	}
	result.Completed = append(result.Completed, crashEvidence...)
	result.RunningCrashReconciled = true
	revoked, err := prepare(agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED)
	if err != nil {
		return nil, err
	}
	if _, err := vmApplyExecutionTrust(ctx, vm, "revoked"); err != nil {
		return nil, err
	}
	if err := vmRejectServiceRPC(ctx, packages, "service-start", revoked.intent.GetActionId(), revoked.start, connect.CodePermissionDenied); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	result.RevokedGrantRejected = true
	if err := verifyRetainedVMServiceActions(ctx, vm, result); err != nil {
		return nil, err
	}
	return result, nil
}

func vmPrepareService(ctx context.Context, packages *nativeGuestPackages, signer *devlab.ExecutionTrustExercise, identity *labv1.ConnectionIdentityEvidence, sequence uint64, runtime agentv1.ServiceRuntimeState, enablement agentv1.ServiceEnablement) (*vmPreparedService, error) {
	now := time.Now().UTC()
	intent := &agentv1.ServiceExecutionIntent{
		DeploymentId: identity.GetDeploymentId(), DeviceId: identity.GetDeviceId(), EnrollmentGeneration: identity.GetEnrollmentGeneration(), ActionId: uuid.NewString(), DesiredRevision: uuid.NewString(), ActorId: uuid.NewString(),
		ResourceSequence: sequence, RecoveryEpoch: 1, RootVersion: 2, DelegationVersion: 2, AuthorizationVersion: 1,
		NotBefore: timestamppb.New(now.Add(-5 * time.Second)), ExpiresAt: timestamppb.New(now.Add(5 * time.Minute)),
		Desired: &agentv1.ServiceDesiredState{Unit: devlab.ServiceExecutionProbeUnit, Runtime: runtime, Enablement: enablement},
	}
	envelope, err := signer.SignServiceIntent(ctx, intent)
	if err != nil {
		return nil, err
	}
	prepared := new(agentv1.PrepareServiceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "service-prepare", intent.GetActionId(), &agentv1.PrepareServiceExecutionRequest{IntentEnvelope: envelope}, prepared); err != nil {
		return nil, err
	}
	result := &vmPreparedService{intent: intent, envelope: envelope, prepared: prepared}
	if prepared.GetStatus().GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED {
		return result, nil
	}
	certificate, err := packages.vm.run(ctx, "sudo -n -u lindm -- "+nativeQuote(nativeGuestDir+"/lab-probe")+" guest connection-certificate", nil, 16384, 15*time.Second)
	if err != nil {
		return nil, err
	}
	_, grant, err := signer.SignServiceStart(ctx, intent, envelope, certificate, prepared)
	if err != nil {
		return nil, err
	}
	result.start = &agentv1.StartServiceExecutionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: grant}
	return result, nil
}

func vmServicePath(command, name string) string {
	return nativeGuestDir + "/" + command + "-" + name + ".json"
}
func vmServiceCommand(command, name string) string {
	return "sudo -n -u lindm -- " + nativeQuote(packaging.BinaryPath) + " " + command + " -file " + nativeQuote(vmServicePath(command, name))
}
func vmUploadServiceRequest(ctx context.Context, packages *nativeGuestPackages, command, name string, request proto.Message) error {
	encoded, err := protojson.Marshal(request)
	if err != nil {
		return err
	}
	return packages.uploadBytes(ctx, vmServicePath(command, name), encoded)
}
func vmServiceRPC(ctx context.Context, packages *nativeGuestPackages, command, name string, request, response proto.Message) error {
	if err := vmUploadServiceRequest(ctx, packages, command, name, request); err != nil {
		return err
	}
	return vmReadServiceRPC(ctx, packages.vm, command, name, response)
}
func vmReadServiceRPC(ctx context.Context, vm *guestVM, command, name string, response proto.Message) error {
	data, err := vm.run(ctx, vmServiceCommand(command, name), nil, 64<<10, 2*time.Minute)
	if err != nil {
		return fmt.Errorf("packaged %s: %w", command, err)
	}
	if err := protojson.Unmarshal(data, response); err != nil {
		return errors.New("invalid packaged service response JSON")
	}
	if err := protovalidate.Validate(response); err != nil {
		return errors.New("invalid packaged service response")
	}
	return protodata.ValidateClosed(response.ProtoReflect())
}
func vmRejectServiceRPC(ctx context.Context, packages *nativeGuestPackages, command, name string, request proto.Message, expected connect.Code) error {
	if err := vmUploadServiceRequest(ctx, packages, command, name, request); err != nil {
		return err
	}
	result, err := packages.vm.runResult(ctx, vmServiceCommand(command, name), nil, 64<<10, 2*time.Minute)
	if err != nil {
		return err
	}
	denial := bytes.HasPrefix(result.Stderr, []byte("lindm-agent: "+expected.String()+": "))
	if result.ExitCode != 1 || len(bytes.TrimSpace(result.Stdout)) != 0 || !denial {
		return fmt.Errorf("%s did not produce a definitive execution denial: exit=%d stderr=%q", command, result.ExitCode, result.Stderr)
	}
	return nil
}
func vmGetService(ctx context.Context, packages *nativeGuestPackages, action string) (*agentv1.ServiceExecutionStatus, error) {
	response := new(agentv1.GetServiceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "service-status", action, &agentv1.GetServiceExecutionRequest{ActionId: action}, response); err != nil {
		return nil, err
	}
	return response.GetStatus(), nil
}
func vmStartService(ctx context.Context, packages *nativeGuestPackages, prepared *vmPreparedService) (*agentv1.ServiceExecutionStatus, error) {
	response := new(agentv1.StartServiceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "service-start", prepared.intent.GetActionId(), prepared.start, response); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := vmUploadServiceRequest(ctx, packages, "service-status", prepared.intent.GetActionId(), &agentv1.GetServiceExecutionRequest{ActionId: prepared.intent.GetActionId()}); err != nil {
		return nil, err
	}
	for {
		status := new(agentv1.GetServiceExecutionResponse)
		if err := vmReadServiceRPC(ctx, packages.vm, "service-status", prepared.intent.GetActionId(), status); err != nil {
			return nil, err
		}
		if status.GetStatus().GetState() >= agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED {
			return status.GetStatus(), nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
func vmServiceSucceeded(status *agentv1.ServiceExecutionStatus, started bool) error {
	if status.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED || status.GetFailure() != agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NONE || !status.GetVerification().GetConverged() || (status.GetStartedAt() != nil) != started || status.GetCompletedAt() == nil {
		return errors.New("signed service execution did not retain verified success with expected start evidence")
	}
	return nil
}
func vmServiceNative(ctx context.Context, vm *guestVM, active, enablement string) error {
	data, err := vm.run(ctx, "sudo -n systemctl show --no-pager --property=Id --property=LoadState --property=ActiveState --property=UnitFileState "+nativeQuote(devlab.ServiceExecutionProbeUnit), nil, 4096, 15*time.Second)
	if err != nil {
		return err
	}
	properties := make(map[string]string, 4)
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return errors.New("invalid independent service observation")
		}
		if _, duplicate := properties[key]; duplicate {
			return errors.New("duplicate independent service property")
		}
		properties[key] = value
	}
	if len(properties) != 4 || properties["Id"] != devlab.ServiceExecutionProbeUnit || properties["LoadState"] != "loaded" || properties["ActiveState"] != active || properties["UnitFileState"] != enablement {
		return fmt.Errorf("independent service state differs: got=%v want=%s/%s", properties, active, enablement)
	}
	return nil
}
func verifyRetainedVMServiceActions(ctx context.Context, vm *guestVM, evidence *vmServiceExecutionEvidence) error {
	if evidence == nil {
		return nil
	}
	for _, previous := range evidence.Completed {
		response := new(agentv1.GetServiceExecutionResponse)
		if err := vmReadServiceRPC(ctx, vm, "service-status", previous.GetActionId(), response); err != nil {
			return err
		}
		if !proto.Equal(previous, response.GetStatus()) {
			return errors.New("execution evidence changed after restart, revocation or package lifecycle")
		}
	}
	return nil
}
