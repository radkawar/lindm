//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

const trustSyncProbeMarker = "/var/lib/lindm-trust-sync-probe.started"

const trustSyncServiceDefinition = `[Unit]
Description=lindm execution-trust synchronization probe
[Service]
Type=simple
ExecStartPre=/usr/bin/touch ` + trustSyncProbeMarker + `
ExecStart=/usr/bin/sleep infinity
[Install]
WantedBy=multi-user.target
`

// Server facts and local observations are intentionally separate. A root CLI
// observation is laboratory evidence, not a server-side applied/compliance ack.
type vmControlPlaneTrustEvidence struct {
	Database                   string                                 `json:"isolated_database"`
	InitialAuthority           *adminv1.GetExecutionAuthorityResponse `json:"initial_authority"`
	RotatedAuthority           *adminv1.GetExecutionAuthorityResponse `json:"rotated_authority"`
	RevokedAuthority           *adminv1.GetExecutionAuthorityResponse `json:"revoked_authority"`
	Initial                    *agentv1.GetExecutionTrustResponse     `json:"initial_root_view"`
	Rotated                    *agentv1.GetExecutionTrustResponse     `json:"rotated_root_view"`
	Revoked                    *agentv1.GetExecutionTrustResponse     `json:"revoked_root_view"`
	InitialReceipt             *agentv1.UpdateExecutionTrustResponse  `json:"initial_receipt"`
	RestartRetryReceipt        *agentv1.UpdateExecutionTrustResponse  `json:"restart_retry_receipt"`
	WrongQuorumRejected        bool                                   `json:"wrong_quorum_rejected"`
	DelegationRollbackRejected bool                                   `json:"delegation_rollback_rejected"`
	EpochRollbackRejected      bool                                   `json:"epoch_rollback_rejected"`
	ExactRetryAfterRestart     bool                                   `json:"exact_retry_after_restart"`
	TLSIdentity                *labv1.ConnectionIdentityEvidence      `json:"tls_identity"`
	TLSIdentityUnchanged       bool                                   `json:"tls_identity_unchanged"`
	NoProbeServiceEffects      bool                                   `json:"no_probe_service_effects"`
	ProbeStartWitnessVerified  bool                                   `json:"probe_start_witness_verified"`
	RebootRetained             bool                                   `json:"reboot_retained"`
	ReinstallRetained          bool                                   `json:"reinstall_retained"`
}

func exerciseVMControlPlaneTrust(ctx context.Context, packages *nativeGuestPackages, control *vmControlPlane, isolated *devlab.AuthorityFixture, repository string) (_ *vmControlPlaneTrustEvidence, err error) {
	fixture, err := devlab.CreateExecutionTrustExercise(ctx, repository)
	if err != nil {
		return nil, err
	}
	defer fixture.Close()
	vm := packages.vm
	result := &vmControlPlaneTrustEvidence{Database: isolated.DatabaseName}
	result.TLSIdentity, err = readVMConnectionIdentity(ctx, vm)
	if err != nil {
		return nil, err
	}
	// systemd may unload an inactive unit and discard its start statistics.
	// A root-owned persistent marker detects even a completed start/stop cycle.
	unit := devlab.ResourceExecutionProbeUnit
	path := "/etc/systemd/system/" + unit
	if err := lifecycleCommand(ctx, vm, "reserve trust synchronization probe", "test ! -e "+nativeQuote(path)+" && test ! -L "+nativeQuote(path)+" && test ! -e "+nativeQuote(trustSyncProbeMarker)+" && test ! -L "+nativeQuote(trustSyncProbeMarker)); err != nil {
		return nil, err
	}
	if err := packages.uploadBytes(ctx, nativeGuestDir+"/trust-sync-service-unit", []byte(trustSyncServiceDefinition)); err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "install trust synchronization probe", "install -o root -g root -m 0644 "+nativeQuote(nativeGuestDir+"/trust-sync-service-unit")+" "+nativeQuote(path)); err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err = errors.Join(err, lifecycleCommand(cleanup, vm, "remove trust synchronization probe", "systemctl disable --now "+nativeQuote(unit)+" && rm -- "+nativeQuote(path)+" && rm -f -- "+nativeQuote(trustSyncProbeMarker)+" && systemctl daemon-reload"))
	}()
	if err := lifecycleCommand(ctx, vm, "load trust synchronization probe", "if command -v restorecon >/dev/null 2>&1; then restorecon -F "+nativeQuote(path)+"; fi; systemctl daemon-reload"); err != nil {
		return nil, err
	}
	if err := vmTrustProbeUnchanged(ctx, vm); err != nil {
		return nil, err
	}
	// Positive-control the witness before the synchronization observation window.
	if err := lifecycleCommand(ctx, vm, "verify persistent native probe witness", "systemctl start "+nativeQuote(unit)+" && systemctl stop "+nativeQuote(unit)+" && test -f "+nativeQuote(trustSyncProbeMarker)+" && rm -- "+nativeQuote(trustSyncProbeMarker)); err != nil {
		return nil, err
	}
	if err := vmTrustProbeUnchanged(ctx, vm); err != nil {
		return nil, err
	}
	result.ProbeStartWitnessVerified = true
	before, err := control.executionAuthority(ctx)
	if err != nil {
		return nil, err
	}
	if before.GetRoot().GetVersion() != 1 || before.GetDelegation() != nil {
		return nil, errors.New("isolated authority did not start with only the protected root pin")
	}
	rootBefore, err := readVMExecutionTrust(ctx, vm)
	if err != nil {
		return nil, err
	}
	if rootBefore.GetRootVersion() != 1 || rootBefore.GetDelegationVersion() != 0 {
		return nil, errors.New("upgraded root already had unexpected delegated execution authority")
	}
	initialRequest := &adminv1.UpdateExecutionAuthorityRequest{Update: fixture.Initial, Reason: "isolated native authority initial delegation"}
	accepted, err := control.session.Admin.UpdateExecutionAuthority(ctx, connect.NewRequest(initialRequest))
	if err != nil {
		return nil, vmControlPlaneError("initialize execution authority", err)
	}
	result.InitialReceipt = accepted.Msg.GetReceipt()
	if err := vmTrustVersions(result.InitialReceipt, 1, 1, 0); err != nil {
		return nil, err
	}
	result.InitialAuthority, err = control.executionAuthority(ctx)
	if err != nil {
		return nil, err
	}
	result.Initial, err = waitVMExecutionTrust(ctx, vm, result.InitialAuthority, fixture.Initial)
	if err != nil {
		return nil, err
	}
	if err := control.rejectExecutionAuthority(ctx, fixture.WrongQuorum); err != nil {
		return nil, err
	}
	result.WrongQuorumRejected = true
	if err := control.applyExecutionAuthority(ctx, fixture.Rotated, 2, 2, 1); err != nil {
		return nil, err
	}
	result.RotatedAuthority, err = control.executionAuthority(ctx)
	if err != nil {
		return nil, err
	}
	result.Rotated, err = waitVMExecutionTrust(ctx, vm, result.RotatedAuthority, fixture.Rotated)
	if err != nil {
		return nil, err
	}
	for _, update := range []*agentv1.UpdateExecutionTrustRequest{fixture.DelegationRollback, fixture.EpochRollback} {
		if err := control.rejectExecutionAuthority(ctx, update); err != nil {
			return nil, err
		}
	}
	result.DelegationRollbackRejected, result.EpochRollbackRejected = true, true
	if err := control.applyExecutionAuthority(ctx, fixture.Revoked, 2, 3, 1); err != nil {
		return nil, err
	}
	result.RevokedAuthority, err = control.executionAuthority(ctx)
	if err != nil {
		return nil, err
	}
	if len(result.RevokedAuthority.GetDelegation().GetDelegates()) != 0 {
		return nil, errors.New("authority revocation retained online delegates")
	}
	result.Revoked, err = waitVMExecutionTrust(ctx, vm, result.RevokedAuthority, fixture.Revoked)
	if err != nil {
		return nil, err
	}
	// Replay a historical update after actual process restart, not just the
	// latest update in memory. Neither revision/time nor current authority moves.
	if err := isolated.Restart(ctx); err != nil {
		return nil, err
	}
	restarted, err := control.executionAuthority(ctx)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(restarted, result.RevokedAuthority) {
		return nil, errors.New("private server restart changed durable execution authority")
	}
	retried, err := control.session.Admin.UpdateExecutionAuthority(ctx, connect.NewRequest(initialRequest))
	if err != nil {
		return nil, vmControlPlaneError("retry historical execution authority", err)
	}
	result.RestartRetryReceipt = retried.Msg.GetReceipt()
	if !proto.Equal(result.RestartRetryReceipt, result.InitialReceipt) {
		return nil, errors.New("exact authority retry after restart changed its original receipt")
	}
	after, err := control.executionAuthority(ctx)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(after, result.RevokedAuthority) {
		return nil, errors.New("historical authority retry rewound state, counters or acceptance time")
	}
	result.ExactRetryAfterRestart = true
	if err := verifyRetainedVMControlPlaneTrust(ctx, vm, result); err != nil {
		return nil, err
	}
	if err := vmTrustProbeUnchanged(ctx, vm); err != nil {
		return nil, err
	}
	result.NoProbeServiceEffects, result.TLSIdentityUnchanged = true, true
	return result, nil
}

func (c *vmControlPlane) executionAuthority(ctx context.Context) (*adminv1.GetExecutionAuthorityResponse, error) {
	response, err := c.session.Admin.GetExecutionAuthority(ctx, connect.NewRequest(&adminv1.GetExecutionAuthorityRequest{}))
	if err != nil {
		return nil, vmControlPlaneError("read execution authority", err)
	}
	if err := protovalidate.Validate(response.Msg); err != nil {
		return nil, errors.New("invalid public execution authority response")
	}
	return response.Msg, nil
}

func (c *vmControlPlane) applyExecutionAuthority(ctx context.Context, update *agentv1.UpdateExecutionTrustRequest, root, delegation, epoch uint64) error {
	response, err := c.session.Admin.UpdateExecutionAuthority(ctx, connect.NewRequest(&adminv1.UpdateExecutionAuthorityRequest{Update: update, Reason: "isolated native authority rotation or revocation"}))
	if err != nil {
		return vmControlPlaneError("update execution authority", err)
	}
	return vmTrustVersions(response.Msg.GetReceipt(), root, delegation, epoch)
}

func (c *vmControlPlane) rejectExecutionAuthority(ctx context.Context, update *agentv1.UpdateExecutionTrustRequest) error {
	before, err := c.executionAuthority(ctx)
	if err != nil {
		return err
	}
	_, err = c.session.Admin.UpdateExecutionAuthority(ctx, connect.NewRequest(&adminv1.UpdateExecutionAuthorityRequest{Update: update, Reason: "isolated native authority negative boundary proof"}))
	var denied *connect.Error
	if !errors.As(err, &denied) || denied.Code() != connect.CodePermissionDenied || denied.Message() != "execution_authority_rejected" {
		return errors.New("execution authority did not definitively reject the signed boundary violation")
	}
	after, err := c.executionAuthority(ctx)
	if err != nil {
		return err
	}
	if !proto.Equal(before, after) {
		return errors.New("rejected signed authority changed durable state, revision or acceptance time")
	}
	return nil
}

func readVMExecutionTrust(ctx context.Context, vm *guestVM) (*agentv1.GetExecutionTrustResponse, error) {
	data, err := vm.run(ctx, "sudo -n -u lindm -- "+nativeQuote(packaging.BinaryPath)+" trust-status", nil, 32<<10, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("read protected native execution trust: %w", err)
	}
	view := new(agentv1.GetExecutionTrustResponse)
	if err := protojson.Unmarshal(data, view); err != nil {
		return nil, errors.New("invalid native execution trust view JSON")
	}
	if err := protovalidate.Validate(view); err != nil {
		return nil, errors.New("invalid native execution trust view")
	}
	if err := protodata.ValidateClosed(view.ProtoReflect()); err != nil {
		return nil, errors.New("unknown native execution trust view fields")
	}
	return view, nil
}

func waitVMExecutionTrust(ctx context.Context, vm *guestVM, authority *adminv1.GetExecutionAuthorityResponse, update *agentv1.UpdateExecutionTrustRequest) (*agentv1.GetExecutionTrustResponse, error) {
	rootDigest, err := trust.ExecutionRootDigest(authority.GetRoot())
	if err != nil {
		return nil, err
	}
	delegationDigest := sha256.Sum256(update.GetDelegationEnvelope())
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last *agentv1.GetExecutionTrustResponse
	for {
		view, err := readVMExecutionTrust(ctx, vm)
		if err != nil {
			if ctx.Err() != nil && last != nil {
				return nil, fmt.Errorf("execution trust synchronization deadline: wanted root=%d delegation=%d; last observed root=%d delegation=%d: %w", authority.GetRoot().GetVersion(), authority.GetDelegation().GetVersion(), last.GetRootVersion(), last.GetDelegationVersion(), err)
			}
			return nil, err
		}
		last = view
		if view.GetRootVersion() == authority.GetRoot().GetVersion() && view.GetDelegationVersion() == authority.GetDelegation().GetVersion() {
			if !bytes.Equal(view.GetRootSha256(), rootDigest[:]) || !bytes.Equal(view.GetDelegationSha256(), delegationDigest[:]) || view.GetMinimumRecoveryEpoch() != authority.GetDelegation().GetMinimumRecoveryEpoch() || !proto.Equal(view.GetRootExpiresAt(), authority.GetRoot().GetExpiresAt()) || !proto.Equal(view.GetDelegationExpiresAt(), authority.GetDelegation().GetExpiresAt()) {
				return nil, errors.New("automatically imported trust does not match the admitted signed authority")
			}
			return view, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("installed unprivileged relay did not import authority root=%d delegation=%d: %w", authority.GetRoot().GetVersion(), authority.GetDelegation().GetVersion(), ctx.Err())
		case <-ticker.C:
		}
	}
}

func verifyRetainedVMControlPlaneTrust(ctx context.Context, vm *guestVM, evidence *vmControlPlaneTrustEvidence) error {
	view, err := readVMExecutionTrust(ctx, vm)
	if err != nil {
		return err
	}
	if !proto.Equal(view, evidence.Revoked) {
		return errors.New("native lifecycle changed retained root counters, digests, acceptance time or expiry")
	}
	return verifyVMConnectionIdentity(ctx, vm, evidence.TLSIdentity)
}

func vmTrustProbeUnchanged(ctx context.Context, vm *guestVM) error {
	if err := vmServiceNative(ctx, vm, "inactive", "disabled"); err != nil {
		return err
	}
	return lifecycleCommand(ctx, vm, "verify no native trust synchronization effect", "test ! -e "+nativeQuote(trustSyncProbeMarker)+" && test ! -L "+nativeQuote(trustSyncProbeMarker))
}
