//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

type vmServiceExecutionEvidence struct {
	Completed                 []*agentv1.ResourceExecutionStatus `json:"completed"`
	ForgedIntentRejected      bool                               `json:"forged_intent_rejected"`
	PlanCannotStart           bool                               `json:"plan_cannot_start"`
	ExactStartReplay          bool                               `json:"exact_start_replay"`
	ConflictingIntentRejected bool                               `json:"conflicting_intent_rejected"`
	ExpiredGrantRejected      bool                               `json:"expired_grant_rejected"`
	RestartGrantRejected      bool                               `json:"restart_grant_rejected"`
	StalePlanRejected         bool                               `json:"stale_plan_rejected"`
	RevokedGrantRejected      bool                               `json:"revoked_grant_rejected"`
	RunningCrashReconciled    bool                               `json:"running_crash_reconciled"`
	// These signatures authenticate terminal history, not a fresh observation
	// or a current authorization/compliance decision.
	Attestations []vmServiceAttestationPhase   `json:"authenticated_history_attestations"`
	ClockChecks  []*labv1.ServiceClockEvidence `json:"clock_checks"`

	packages *nativeGuestPackages
	verifier *devlab.ExecutionTrustExercise
	identity *labv1.ConnectionIdentityEvidence
	bindings map[string]trust.ResourceAttestationBinding
}

type vmServiceAttestationPhase struct {
	Phase                    string                         `json:"phase"`
	RootSession              *agentv1.StatusResponse        `json:"root_session"`
	Actions                  []vmServiceAttestationEvidence `json:"actions"`
	TerminalHistoryUnchanged bool                           `json:"terminal_history_unchanged"`
}

type vmServiceAttestationEvidence struct {
	Attestation              *agentv1.ResourceExecutionAttestation `json:"attestation"`
	Envelope                 []byte                                `json:"attestation_envelope"`
	CertificatePEM           []byte                                `json:"certificate_pem"`
	VerifiedAt               time.Time                             `json:"verified_at"`
	TamperedPayloadRejected  bool                                  `json:"tampered_payload_rejected"`
	WrongNonceReplayRejected bool                                  `json:"wrong_nonce_replay_rejected"`
}

type vmPreparedService struct {
	intent   *agentv1.ResourceExecutionIntent
	envelope []byte
	prepared *agentv1.PrepareResourceExecutionResponse
	start    *agentv1.StartResourceExecutionRequest
	clock    *labv1.ServiceClockEvidence
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
	defer func() { err = serviceFailureWithJournal(ctx, vm, err) }()
	unit := devlab.ResourceExecutionProbeUnit
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
	deployment, err := uuid.Parse(identity.GetDeploymentId())
	if err != nil {
		return nil, err
	}
	device, err := uuid.Parse(identity.GetDeviceId())
	if err != nil {
		return nil, err
	}
	generation, err := uuid.Parse(identity.GetEnrollmentGeneration())
	if err != nil {
		return nil, err
	}
	result := &vmServiceExecutionEvidence{
		packages: packages, verifier: signer, identity: proto.CloneOf(identity),
		bindings: make(map[string]trust.ResourceAttestationBinding),
	}
	var sequence uint64
	prepare := func(runtime resourcev1.ServiceRuntimeState, enablement resourcev1.ServiceEnablement) (*vmPreparedService, error) {
		sequence++
		action, err := vmPrepareService(ctx, packages, signer, identity, sequence, runtime, enablement)
		if err != nil {
			return nil, err
		}
		id, err := uuid.Parse(action.intent.GetActionId())
		if err != nil {
			return nil, err
		}
		result.bindings[action.intent.GetActionId()] = trust.ResourceAttestationBinding{
			DeploymentID: deployment, DeviceID: device, EnrollmentGeneration: generation,
			ActionID: id, IntentSHA256: sha256.Sum256(action.envelope),
		}
		if action.clock != nil {
			result.ClockChecks = append(result.ClockChecks, action.clock)
		}
		return action, nil
	}
	active, err := prepare(resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED)
	if err != nil {
		return nil, err
	}
	if active.prepared.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED || !active.prepared.GetNativePlan().GetSystemdService().GetChangeRuntime() || !active.prepared.GetNativePlan().GetSystemdService().GetChangeEnablement() {
		return nil, errors.New("signed preflight did not record both required changes")
	}
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	forgedIntent := proto.CloneOf(active.intent)
	forgedIntent.ActionId = uuid.NewString()
	forgedIntent.ResourceSequence++
	signed, err := signer.SignResourceIntent(ctx, forgedIntent)
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
	if err := vmRejectServiceRPC(ctx, packages, "resource-prepare", "forged", &agentv1.PrepareResourceExecutionRequest{IntentEnvelope: encodedForged}, connect.CodePermissionDenied); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	result.ForgedIntentRejected = true
	if err := vmRejectServiceRPC(ctx, packages, "resource-start", "plan-domain", &agentv1.StartResourceExecutionRequest{ActionId: active.intent.GetActionId(), StartGrantEnvelope: active.envelope}, connect.CodePermissionDenied); err != nil {
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
	replay := new(agentv1.StartResourceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "resource-start", active.intent.GetActionId(), active.start, replay); err != nil {
		return nil, err
	}
	if !proto.Equal(replay.GetStatus(), completed) {
		return nil, errors.New("exact signed start retry changed terminal evidence")
	}
	result.ExactStartReplay = true
	conflict := proto.CloneOf(active.intent)
	conflict.DesiredRevision = uuid.NewString()
	conflict.Ownership.AssignmentId = conflict.GetDesiredRevision()
	conflictingEnvelope, err := signer.SignResourceIntent(ctx, conflict)
	if err != nil {
		return nil, err
	}
	if err := vmRejectServiceRPC(ctx, packages, "resource-prepare", "conflict", &agentv1.PrepareResourceExecutionRequest{IntentEnvelope: conflictingEnvelope}, connect.CodeAlreadyExists); err != nil {
		return nil, err
	}
	result.ConflictingIntentRejected = true
	// Runtime-only stop and start qualify the later callback after job-match setup.
	for _, runtime := range []resourcev1.ServiceRuntimeState{resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE} {
		action, err := prepare(runtime, resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED)
		if err != nil {
			return nil, err
		}
		if !action.prepared.GetNativePlan().GetSystemdService().GetChangeRuntime() || action.prepared.GetNativePlan().GetSystemdService().GetChangeEnablement() {
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
		if runtime == resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE {
			want = "inactive"
		}
		if err := vmServiceNative(ctx, vm, want, "enabled"); err != nil {
			return nil, err
		}
		result.Completed = append(result.Completed, status)
	}
	noop, err := prepare(resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED)
	if err != nil {
		return nil, err
	}
	if err := vmServiceSucceeded(noop.prepared.GetStatus(), false); err != nil {
		return nil, err
	}
	if noop.prepared.GetNativePlan().GetSystemdService().GetChangeRuntime() || noop.prepared.GetNativePlan().GetSystemdService().GetChangeEnablement() || len(noop.prepared.GetChallengeProof()) != 0 {
		return nil, errors.New("no-drift intent acquired a start challenge")
	}
	noopStatus, err := vmGetService(ctx, packages, noop.intent.GetActionId())
	if err != nil {
		return nil, err
	}
	result.Completed = append(result.Completed, noopStatus)
	expired, err := prepare(resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED)
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
	if err := vmRejectServiceRPC(ctx, packages, "resource-start", expired.intent.GetActionId(), expired.start, connect.CodePermissionDenied); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "active", "enabled"); err != nil {
		return nil, err
	}
	expiredStatus, err := vmGetService(ctx, packages, expired.intent.GetActionId())
	if err != nil {
		return nil, err
	}
	if expiredStatus.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED || expiredStatus.GetStartedAt() != nil {
		return nil, errors.New("expired challenge did not retain a no-start terminal result")
	}
	result.Completed = append(result.Completed, expiredStatus)
	result.ExpiredGrantRejected = true
	restarted, err := prepare(resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED)
	if err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "restart signed executor", "systemctl restart lindm-executor.service"); err != nil {
		return nil, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return nil, err
	}
	if err := vmRejectServiceRPC(ctx, packages, "resource-start", restarted.intent.GetActionId(), restarted.start, connect.CodePermissionDenied); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "active", "enabled"); err != nil {
		return nil, err
	}
	restartStatus, err := vmGetService(ctx, packages, restarted.intent.GetActionId())
	if err != nil {
		return nil, err
	}
	if restartStatus.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED || restartStatus.GetStartedAt() != nil {
		return nil, errors.New("same-boot restart retained usable challenge authority")
	}
	result.Completed = append(result.Completed, restartStatus)
	result.RestartGrantRejected = true
	stale, err := prepare(resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED)
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
	if staleStatus.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || staleStatus.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION || staleStatus.GetStartedAt() != nil {
		return nil, errors.New("stale service precondition did not fail before start consumption")
	}
	if err := vmServiceNative(ctx, vm, "inactive", "enabled"); err != nil {
		return nil, err
	}
	result.Completed = append(result.Completed, staleStatus)
	result.StalePlanRejected = true
	inactive, err := prepare(resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED)
	if err != nil {
		return nil, err
	}
	if inactive.prepared.GetNativePlan().GetSystemdService().GetChangeRuntime() || !inactive.prepared.GetNativePlan().GetSystemdService().GetChangeEnablement() {
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
	// Capture every independently established terminal result before trust
	// revocation, without spending a prepared start challenge's time window.
	if err := vmAttestServiceActions(ctx, result, "terminal", false); err != nil {
		return nil, err
	}
	revoked, err := prepare(resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED)
	if err != nil {
		return nil, err
	}
	if _, err := vmApplyExecutionTrust(ctx, vm, "revoked"); err != nil {
		return nil, err
	}
	if err := vmRejectServiceRPC(ctx, packages, "resource-start", revoked.intent.GetActionId(), revoked.start, connect.CodePermissionDenied); err != nil {
		return nil, err
	}
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return nil, err
	}
	result.RevokedGrantRejected = true
	if err := verifyRetainedVMServiceActions(ctx, vm, result, "execution_trust_revoked"); err != nil {
		return nil, err
	}
	return result, nil
}

func vmPrepareService(ctx context.Context, packages *nativeGuestPackages, signer *devlab.ExecutionTrustExercise, identity *labv1.ConnectionIdentityEvidence, sequence uint64, runtime resourcev1.ServiceRuntimeState, enablement resourcev1.ServiceEnablement) (*vmPreparedService, error) {
	now := time.Now().UTC()
	intent := &agentv1.ResourceExecutionIntent{
		DeploymentId: identity.GetDeploymentId(), DeviceId: identity.GetDeviceId(), EnrollmentGeneration: identity.GetEnrollmentGeneration(), ActionId: uuid.NewString(), DesiredRevision: uuid.NewString(), ActorId: uuid.NewString(),
		ResourceSequence: sequence, RecoveryEpoch: 1, RootVersion: 2, DelegationVersion: 2, AuthorizationVersion: 1,
		NotBefore: timestamppb.New(now.Add(-trust.MaxDeviceClockSkew)), ExpiresAt: timestamppb.New(now.Add(5 * time.Minute)),
		Desired: &resourcev1.ResourceDesiredState{
			Ref:   &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: devlab.ResourceExecutionProbeUnit},
			State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: devlab.ResourceExecutionProbeUnit, Runtime: runtime, Enablement: enablement}},
		},
		Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE,
	}
	// Keep the profile/resource owner stable across desired revisions and all
	// native scenario transitions; the assignment remains an exact action fence.
	intent.Ownership = &agentv1.ResourceOwnershipBinding{
		AssignmentId: intent.GetDesiredRevision(), ResourceId: "1d8f463f-2f92-41ea-b6af-676c9a30e71f",
		Policy:  &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN},
		Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: "40e9179c-48a9-444c-a0e6-3fcbdb2126b0", ProfileRevision: intent.GetDesiredRevision(), ResourceId: "1d8f463f-2f92-41ea-b6af-676c9a30e71f"}},
	}
	envelope, err := signer.SignResourceIntent(ctx, intent)
	if err != nil {
		return nil, err
	}
	prepared := new(agentv1.PrepareResourceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "resource-prepare", intent.GetActionId(), &agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}, prepared); err != nil {
		return nil, err
	}
	result := &vmPreparedService{intent: intent, envelope: envelope, prepared: prepared}
	if prepared.GetStatus().GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
		return result, nil
	}
	certificate, err := packages.vm.run(ctx, "sudo -n -u lindm -- "+nativeQuote(nativeGuestDir+"/lab-probe")+" guest connection-certificate", nil, 16384, 15*time.Second)
	if err != nil {
		return nil, err
	}
	hostBefore := time.Now().UTC()
	start, grant, err := signer.SignResourceStart(ctx, intent, envelope, certificate, prepared)
	hostAfter := time.Now().UTC()
	if err != nil {
		return nil, err
	}
	result.clock = &labv1.ServiceClockEvidence{HostBefore: timestamppb.New(hostBefore), HostAfter: timestamppb.New(hostAfter), Challenge: proto.CloneOf(start.GetChallenge())}
	result.start = &agentv1.StartResourceExecutionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: grant}
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
func vmGetService(ctx context.Context, packages *nativeGuestPackages, action string) (*agentv1.ResourceExecutionStatus, error) {
	response := new(agentv1.GetResourceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "resource-status", action, &agentv1.GetResourceExecutionRequest{ActionId: action}, response); err != nil {
		return nil, err
	}
	return response.GetStatus(), nil
}
func vmStartService(ctx context.Context, packages *nativeGuestPackages, prepared *vmPreparedService) (*agentv1.ResourceExecutionStatus, error) {
	response := new(agentv1.StartResourceExecutionResponse)
	if err := vmServiceRPC(ctx, packages, "resource-start", prepared.intent.GetActionId(), prepared.start, response); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := vmUploadServiceRequest(ctx, packages, "resource-status", prepared.intent.GetActionId(), &agentv1.GetResourceExecutionRequest{ActionId: prepared.intent.GetActionId()}); err != nil {
		return nil, err
	}
	for {
		status := new(agentv1.GetResourceExecutionResponse)
		if err := vmReadServiceRPC(ctx, packages.vm, "resource-status", prepared.intent.GetActionId(), status); err != nil {
			return nil, err
		}
		if status.GetStatus().GetState() >= agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
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
func vmServiceSucceeded(status *agentv1.ResourceExecutionStatus, started bool) error {
	if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE || status.GetVerification().GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED || (status.GetStartedAt() != nil) != started || status.GetCompletedAt() == nil {
		return newServiceStatusFailure(status, started)
	}
	return nil
}
func vmServiceNative(ctx context.Context, vm *guestVM, active, enablement string) error {
	return vmServiceNativeUnit(ctx, vm, devlab.ResourceExecutionProbeUnit, active, enablement)
}

func vmServiceNativeUnit(ctx context.Context, vm *guestVM, unit, active, enablement string) error {
	properties, err := vmServiceNativeProperties(ctx, vm, unit)
	if err != nil {
		return err
	}
	if properties["ActiveState"] != active || properties["UnitFileState"] != enablement {
		return fmt.Errorf("independent service state differs: got=%v want=%s/%s", properties, active, enablement)
	}
	return nil
}

func vmServiceNativeProperties(ctx context.Context, vm *guestVM, unit string) (map[string]string, error) {
	data, err := vm.run(ctx, "sudo -n systemctl show --no-pager --property=Id --property=LoadState --property=ActiveState --property=UnitFileState "+nativeQuote(unit), nil, 4096, 15*time.Second)
	if err != nil {
		return nil, err
	}
	properties := make(map[string]string, 4)
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("invalid independent service observation")
		}
		if _, duplicate := properties[key]; duplicate {
			return nil, errors.New("duplicate independent service property")
		}
		properties[key] = value
	}
	if len(properties) != 4 || properties["Id"] != unit || properties["LoadState"] != "loaded" || properties["ActiveState"] == "" || properties["UnitFileState"] == "" {
		return nil, fmt.Errorf("incomplete independent service observation: %v", properties)
	}
	return properties, nil
}
func verifyRetainedVMServiceActions(ctx context.Context, vm *guestVM, evidence *vmServiceExecutionEvidence, phase string) error {
	if evidence == nil {
		return nil
	}
	for _, previous := range evidence.Completed {
		response := new(agentv1.GetResourceExecutionResponse)
		if err := vmReadServiceRPC(ctx, vm, "resource-status", previous.GetActionId(), response); err != nil {
			return err
		}
		if !proto.Equal(previous, response.GetStatus()) {
			return errors.New("execution evidence changed after restart, revocation or package lifecycle")
		}
	}
	return vmAttestServiceActions(ctx, evidence, phase, true)
}

func vmAttestServiceActions(ctx context.Context, evidence *vmServiceExecutionEvidence, phase string, retained bool) error {
	if evidence.packages == nil || evidence.verifier == nil || evidence.identity == nil || len(evidence.Completed) == 0 {
		return errors.New("missing independently established service evidence")
	}
	if retained && (len(evidence.Attestations) == 0 || len(evidence.Attestations[0].Actions) != len(evidence.Completed)) {
		return errors.New("missing terminal service attestation baseline")
	}
	session, err := vmServiceAttestationSession(ctx, evidence.packages.vm, evidence.identity)
	if err != nil {
		return err
	}
	result := vmServiceAttestationPhase{
		Phase: phase, RootSession: session, TerminalHistoryUnchanged: retained,
		Actions: make([]vmServiceAttestationEvidence, 0, len(evidence.Completed)),
	}
	for i, previous := range evidence.Completed {
		binding, ok := evidence.bindings[previous.GetActionId()]
		if !ok {
			return errors.New("terminal action has no independently signed intent binding")
		}
		binding.SessionEpoch = session.GetCommittedSessionEpoch()
		if _, err := rand.Read(binding.Nonce[:]); err != nil {
			return err
		}
		response := new(agentv1.AttestResourceExecutionResponse)
		request := &agentv1.AttestResourceExecutionRequest{ActionId: binding.ActionID.String(), Nonce: binding.Nonce[:]}
		if err := vmServiceRPC(ctx, evidence.packages, "resource-attest", previous.GetActionId(), request, response); err != nil {
			return err
		}
		now := time.Now().UTC()
		verified, err := evidence.verifier.VerifyResourceAttestation(ctx, response.GetAttestationEnvelope(), response.GetCertificatePem(), &binding, now)
		if err != nil {
			return fmt.Errorf("%s terminal service attestation: %w", phase, err)
		}
		if !proto.Equal(previous, verified.GetStatus()) {
			return errors.New("attested service history differs from independently established root/native evidence")
		}
		if retained {
			baseline := evidence.Attestations[0].Actions[i].Attestation
			if baseline.GetActionRevision() != verified.GetActionRevision() || !proto.Equal(baseline.GetStatus(), verified.GetStatus()) {
				return errors.New("terminal action revision or status changed after revocation, reboot or reinstall")
			}
		}
		if err := vmRejectForgedServiceAttestation(ctx, evidence.verifier, response, verified, &binding, now); err != nil {
			return err
		}
		result.Actions = append(result.Actions, vmServiceAttestationEvidence{
			Attestation: verified, Envelope: response.GetAttestationEnvelope(), CertificatePEM: response.GetCertificatePem(),
			VerifiedAt: now, TamperedPayloadRejected: true, WrongNonceReplayRejected: true,
		})
	}
	evidence.Attestations = append(evidence.Attestations, result)
	return nil
}

func vmServiceAttestationSession(ctx context.Context, vm *guestVM, identity *labv1.ConnectionIdentityEvidence) (*agentv1.StatusResponse, error) {
	// Reboot/reinstall readiness precedes the network process committing its
	// current-boot session. Allow an in-flight failed acquisition, the existing
	// jittered retry, native collection and a new acquisition without shortening
	// product timers. Wait for this prerequisite, not an arbitrary attestation
	// error, and never obtain the expected epoch from the envelope.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	boot, err := vm.run(ctx, "cat /proc/sys/kernel/random/boot_id", nil, 128, 10*time.Second)
	if err != nil {
		return nil, err
	}
	currentBoot := strings.TrimSpace(string(boot))
	bootID, err := uuid.Parse(currentBoot)
	if err != nil || bootID == uuid.Nil || bootID.String() != currentBoot {
		return nil, errors.New("invalid independent guest boot identity")
	}
	for {
		status, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
		if err != nil {
			return nil, err
		}
		if status.GetDeploymentId() != identity.GetDeploymentId() || status.GetDeviceId() != identity.GetDeviceId() || status.GetEnrollmentGeneration() != identity.GetEnrollmentGeneration() || status.GetIdentityExpired() {
			return nil, errors.New("root session does not match the pinned service identity")
		}
		if status.GetSessionEpochUsable() && status.GetCommittedSessionEpoch() > 0 && status.GetCommittedBootId() == currentBoot && !status.GetSessionPending() && !status.GetRenewalPending() {
			return status, nil
		}
		if err := vmServicePause(ctx); err != nil {
			return nil, err
		}
	}
}

func vmRejectForgedServiceAttestation(ctx context.Context, verifier *devlab.ExecutionTrustExercise, response *agentv1.AttestResourceExecutionResponse, verified *agentv1.ResourceExecutionAttestation, expected *trust.ResourceAttestationBinding, now time.Time) error {
	// Preserve the valid envelope's domain, certificate and signature while
	// altering a schema-valid revision. This is result forgery, not malformed JSON.
	forged := proto.CloneOf(verified)
	forged.ActionRevision++
	if forged.GetActionRevision() == 0 {
		return errors.New("cannot construct a schema-valid forged action revision")
	}
	if err := protovalidate.Validate(forged); err != nil {
		return err
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(forged)
	if err != nil {
		return err
	}
	var envelope dsse.Envelope
	if err := json.Unmarshal(response.GetAttestationEnvelope(), &envelope); err != nil {
		return err
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	tampered, err := json.Marshal(&envelope)
	if err != nil {
		return err
	}
	if _, err := verifier.VerifyResourceAttestation(ctx, tampered, response.GetCertificatePem(), expected, now); err == nil {
		return errors.New("relay-tampered service attestation was accepted")
	}
	wrongNonce := *expected
	wrongNonce.Nonce[0] ^= 1
	if _, err := verifier.VerifyResourceAttestation(ctx, response.GetAttestationEnvelope(), response.GetCertificatePem(), &wrongNonce, now); err == nil {
		return errors.New("service attestation replay was accepted for a different nonce")
	}
	// Recheck the positive control with exactly the same inputs and time. A
	// cancelled context or broken verifier cannot masquerade as either rejection.
	_, err = verifier.VerifyResourceAttestation(ctx, response.GetAttestationEnvelope(), response.GetCertificatePem(), expected, now)
	return err
}
