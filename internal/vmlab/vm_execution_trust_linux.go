//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/protodata"
)

type vmExecutionTrustEvidence struct {
	Initial                    *agentv1.UpdateExecutionTrustResponse `json:"initial"`
	Rotated                    *agentv1.UpdateExecutionTrustResponse `json:"rotated"`
	Revoked                    *agentv1.UpdateExecutionTrustResponse `json:"revoked"`
	WrongQuorumRejected        bool                                  `json:"wrong_quorum_rejected"`
	DelegationRollbackRejected bool                                  `json:"delegation_rollback_rejected"`
	EpochRollbackRejected      bool                                  `json:"epoch_rollback_rejected"`
	TLSIdentity                *labv1.ConnectionIdentityEvidence     `json:"tls_identity"`
	TLSIdentityUnchanged       bool                                  `json:"tls_identity_unchanged"`
	RebootRetained             bool                                  `json:"reboot_retained"`
	ReinstallRetained          bool                                  `json:"reinstall_retained"`
	HostUTC                    time.Time                             `json:"host_utc"`
	GuestUTC                   time.Time                             `json:"guest_utc"`
}

func exerciseVMExecutionTrust(ctx context.Context, packages *nativeGuestPackages, repository string) (*vmExecutionTrustEvidence, error) {
	fixture, err := devlab.CreateExecutionTrustExercise(ctx, repository)
	if err != nil {
		return nil, err
	}
	for _, item := range []struct {
		name    string
		request *agentv1.UpdateExecutionTrustRequest
	}{{"initial", fixture.Initial}, {"wrong-quorum", fixture.WrongQuorum}, {"rotated", fixture.Rotated}, {"revoked", fixture.Revoked}, {"delegation-rollback", fixture.DelegationRollback}, {"epoch-rollback", fixture.EpochRollback}} {
		encoded, err := protojson.Marshal(item.request)
		if err != nil {
			return nil, err
		}
		if err := packages.uploadBytes(ctx, vmTrustPath(item.name), encoded); err != nil {
			return nil, err
		}
	}
	result := new(vmExecutionTrustEvidence)
	result.TLSIdentity, err = readVMConnectionIdentity(ctx, packages.vm)
	if err != nil {
		return nil, err
	}
	clock, err := packages.vm.run(ctx, "date -u +%s", nil, 64, 10*time.Second)
	if err != nil {
		return nil, err
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(string(clock)), 10, 64)
	if err != nil {
		return nil, errors.New("invalid native UTC observation")
	}
	result.HostUTC, result.GuestUTC = time.Now().UTC(), time.Unix(seconds, 0).UTC()
	result.Initial, err = vmApplyExecutionTrust(ctx, packages.vm, "initial")
	if err != nil {
		return nil, fmt.Errorf("trust clock observation host=%s guest=%s: %w", result.HostUTC.Format(time.RFC3339Nano), result.GuestUTC.Format(time.RFC3339), err)
	}
	if err := vmTrustVersions(result.Initial, 1, 1, 0); err != nil {
		return nil, err
	}
	if err := vmRejectExecutionTrust(ctx, packages.vm, "wrong-quorum"); err != nil {
		return nil, err
	}
	replayed, err := vmApplyExecutionTrust(ctx, packages.vm, "initial")
	if err != nil || !proto.Equal(replayed, result.Initial) {
		return nil, errors.Join(err, errors.New("rejected quorum changed the installed execution authority"))
	}
	result.WrongQuorumRejected = true
	result.Rotated, err = vmApplyExecutionTrust(ctx, packages.vm, "rotated")
	if err != nil {
		return nil, err
	}
	if err := vmTrustVersions(result.Rotated, 2, 2, 1); err != nil {
		return nil, err
	}
	for _, name := range []string{"delegation-rollback", "epoch-rollback"} {
		if err := vmRejectExecutionTrust(ctx, packages.vm, name); err != nil {
			return nil, err
		}
	}
	replayed, err = vmApplyExecutionTrust(ctx, packages.vm, "rotated")
	if err != nil || !proto.Equal(replayed, result.Rotated) {
		return nil, errors.Join(err, errors.New("rejected rollback changed the installed execution authority"))
	}
	result.DelegationRollbackRejected, result.EpochRollbackRejected = true, true
	result.Revoked, err = vmApplyExecutionTrust(ctx, packages.vm, "revoked")
	if err != nil {
		return nil, err
	}
	if err := vmTrustVersions(result.Revoked, 2, 3, 1); err != nil {
		return nil, err
	}
	if err := verifyVMConnectionIdentity(ctx, packages.vm, result.TLSIdentity); err != nil {
		return nil, err
	}
	result.TLSIdentityUnchanged = true
	return result, nil
}

func vmTrustPath(name string) string {
	return nativeGuestDir + "/execution-trust-" + name + ".json"
}

func vmTrustCommand(name string) string {
	return "sudo -n -u lindm -- " + nativeQuote(packaging.BinaryPath) + " trust-update -file " + nativeQuote(vmTrustPath(name))
}

func vmApplyExecutionTrust(ctx context.Context, vm *guestVM, name string) (*agentv1.UpdateExecutionTrustResponse, error) {
	data, err := vm.run(ctx, vmTrustCommand(name), nil, 32<<10, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("native execution trust %s: %w", name, err)
	}
	response := new(agentv1.UpdateExecutionTrustResponse)
	if err := protojson.Unmarshal(data, response); err != nil {
		return nil, errors.New("invalid native execution trust receipt JSON")
	}
	if err := protovalidate.Validate(response); err != nil {
		return nil, errors.New("invalid native execution trust receipt")
	}
	if err := protodata.ValidateClosed(response.ProtoReflect()); err != nil {
		return nil, errors.New("unknown native execution trust receipt fields")
	}
	return response, nil
}

func vmRejectExecutionTrust(ctx context.Context, vm *guestVM, name string) error {
	result, err := vm.runResult(ctx, vmTrustCommand(name), nil, 32<<10, 30*time.Second)
	if err != nil {
		return err
	}
	if result.ExitCode != 1 || len(bytes.TrimSpace(result.Stdout)) != 0 || !bytes.Equal(bytes.TrimSpace(result.Stderr), []byte("lindm-agent: permission_denied: execution_trust_rejected")) {
		return errors.New("native execution trust rejection was not a definitive authority denial")
	}
	return nil
}

func vmTrustVersions(receipt *agentv1.UpdateExecutionTrustResponse, root, delegation, epoch uint64) error {
	if receipt.GetRootVersion() != root || receipt.GetDelegationVersion() != delegation || receipt.GetMinimumRecoveryEpoch() != epoch {
		return errors.New("native execution trust receipt has unexpected rollback fences")
	}
	return nil
}

func verifyRetainedVMExecutionTrust(ctx context.Context, vm *guestVM, evidence *vmExecutionTrustEvidence) error {
	if evidence == nil {
		return nil
	}
	for _, name := range []string{"rotated", "delegation-rollback", "epoch-rollback"} {
		if err := vmRejectExecutionTrust(ctx, vm, name); err != nil {
			return err
		}
	}
	receipt, err := vmApplyExecutionTrust(ctx, vm, "revoked")
	if err != nil {
		return err
	}
	if !proto.Equal(receipt, evidence.Revoked) {
		return errors.New("native lifecycle replaced execution trust or extended its receipt")
	}
	return verifyVMConnectionIdentity(ctx, vm, evidence.TLSIdentity)
}

func readVMConnectionIdentity(ctx context.Context, vm *guestVM) (*labv1.ConnectionIdentityEvidence, error) {
	data, err := vm.run(ctx, "sudo -n -u lindm -- "+nativeQuote(nativeGuestDir+"/lab-probe")+" guest connection-identity", nil, 16<<10, 30*time.Second)
	if err != nil {
		return nil, err
	}
	evidence := new(labv1.ConnectionIdentityEvidence)
	if err := protojson.Unmarshal(data, evidence); err != nil {
		return nil, errors.New("invalid native TLS identity evidence JSON")
	}
	if err := protovalidate.Validate(evidence); err != nil {
		return nil, errors.New("invalid native TLS identity evidence")
	}
	return evidence, nil
}

func verifyVMConnectionIdentity(ctx context.Context, vm *guestVM, previous *labv1.ConnectionIdentityEvidence) error {
	current, err := readVMConnectionIdentity(ctx, vm)
	if err != nil {
		return err
	}
	if previous == nil || !proto.Equal(current, previous) {
		return errors.New("execution trust lifecycle changed TLS identity or pins")
	}
	return nil
}
