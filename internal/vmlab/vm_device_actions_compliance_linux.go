// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func resourceComplianceDesired() *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE, CanonicalKey: "system/root"}, State: &resourcev1.ResourceDesiredState_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionComplianceDesired{RequireLuksRoot: true, RequireEscrow: proto.Bool(true)}}}
}

// complianceOracle independently reads the root's dm-crypt ancestry and LUKS
// header keyslots; it never relies on the agent's encryption observation.
func complianceOracle(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
	command := "root=$(findmnt -n -o SOURCE /); lsblk -s -n -o NAME,TYPE,FSTYPE \"$root\"; lsblk -s -n -o TYPE \"$root\" | grep -qx crypt; " +
		"luks=$(lsblk -s -r -n -p -o NAME,FSTYPE \"$root\" | awk '$2==\"crypto_LUKS\"{print $1; exit}'); test -n \"$luks\"; cryptsetup isLuks --type luks2 \"$luks\"; cryptsetup luksDump \"$luks\" | sed -n '/^Keyslots:/,/^Tokens:/p' | grep -E '^ +[0-9]+: '"
	return resourceOracle(ctx, vm, "native-luks-root-keyslots", command)
}

// complianceFinding waits for one authenticated read-only result of the exact
// disposition. A read-only finding never acquires start authority.
func complianceFinding(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, want resourcev1.VerificationDisposition) error {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	fail := func(err error) error {
		s.Failure = err.Error()
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := r.assign(ctx, resourceComplianceDesired(), resourceCreatePolicy()); err != nil {
		return fail(err)
	}
	action, err := r.action(ctx, want != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	status := action.GetStatus()
	if !status.GetReadOnly() || action.GetStartAuthorizedAt() != nil || status.GetStartedAt() != nil || status.GetVerification().GetDisposition() != want {
		return fail(fmt.Errorf("compliance was not a read-only %s finding: %s", want, status))
	}
	native, err := complianceOracle(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	s.Native = []VMResourceNativeRecord{native}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

// nativeComplianceScenario qualifies encryption compliance on the disposable
// installed encrypted guest: missing escrow is a drifted finding, a real escrow
// rotation makes it converge, and release is a no-effect signed release.
func nativeComplianceScenario(ctx context.Context, machine *actionMachine, control *vmControlPlane, result *VMDeviceActionsResult) error {
	evidence := &VMResourceKindEvidence{Kind: resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE}
	result.Compliance = evidence
	r := &resourceDispatch{vm: machine.vm.guest, control: control, device: machine.deviceID, profile: uuid.NewString(), resource: uuid.NewString()}
	if err := complianceFinding(ctx, r, evidence, "luks-root-without-escrow-drifted", resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED); err != nil {
		return err
	}
	encryption, err := control.session.Admin.GetDeviceEncryption(ctx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: machine.deviceID}))
	if err != nil {
		return err
	}
	ownerCredential := []byte(machine.vm.InitialUnlockSecret())
	defer clear(ownerCredential)
	rotate := &agentv1.EscrowRotateAction{Target: machine.target.Identity, EscrowKeyId: encryption.Msg.GetEscrowKeyId(), EscrowPublicKey: encryption.Msg.GetEscrowPublicKey()}
	request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: rotate}})
	result.Escrow, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, ownerCredential, false)
	if err != nil {
		diagnostic := VMResourceScenario{Name: "escrow-rotate-dispatch", StartedAt: time.Now().UTC(), Failure: err.Error()}
		diagnostic.Native = append(diagnostic.Native, executorDiagnostics(ctx, machine.vm.guest))
		if inventory, runErr := machine.vm.guest.runResult(ctx, "sudo -n /usr/libexec/lindm/lindm-agent inventory-observe 2>&1 | head -c 200000", nil, 256<<10, 2*time.Minute); runErr == nil {
			diagnostic.Native = append(diagnostic.Native, resourceNativeRecord("failure-diagnostic-root-inventory", inventory.Stdout))
		}
		// Disposable guest only: bisect which executor sandbox property breaks a
		// nested systemd-run on this distribution.
		bisect := `for p in "" "-p NoNewPrivileges=yes" "-p ProtectProc=invisible" "-p PrivateDevices=yes" "-p SystemCallFilter=@system-service -p SystemCallErrorNumber=EPERM" "-p RestrictAddressFamilies=AF_UNIX" "-p RestrictSUIDSGID=yes" "-p MemoryDenyWriteExecute=yes" "-p RestrictNamespaces=yes" "-p ProtectSystem=strict" "-p ProtectHome=yes" "-p PrivateTmp=yes" "-p ProtectKernelTunables=yes -p ProtectControlGroups=yes" "-p CapabilityBoundingSet=CAP_CHOWN" "-p LockPersonality=yes -p ProtectHostname=yes -p ProtectClock=yes"; do printf "%s => " "$p"; systemd-run --quiet --wait --pipe $p /usr/bin/systemd-run --quiet --wait --pipe /usr/bin/true 2>&1 | head -c 300; echo " rc=$?"; done`
		if system, runErr := machine.vm.guest.runResult(ctx, "sudo -n sh -c "+nativeQuote(bisect), nil, 256<<10, 5*time.Minute); runErr == nil {
			diagnostic.Native = append(diagnostic.Native, resourceNativeRecord("failure-diagnostic-system", system.Stdout))
		}
		evidence.Scenarios = append(evidence.Scenarios, diagnostic)
		return err
	}
	if err := complianceFinding(ctx, r, evidence, "escrowed-luks-root-converged", resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "release-without-storage-effect", resourceComplianceDesired().GetRef(), func(ctx context.Context) (VMResourceNativeRecord, error) {
		return complianceOracle(ctx, r.vm)
	}); err != nil {
		return err
	}
	if !bytes.Equal(evidence.Scenarios[1].Native[0].Bytes, evidence.Scenarios[2].Native[0].Bytes) {
		return errors.New("compliance release changed independent LUKS root evidence")
	}
	evidence.Unproven = []string{"TPM binding requirement and physical storage are not exercised"}
	return qualifyResourceEvidence(evidence, []string{"luks-root-without-escrow-drifted", "escrowed-luks-root-converged", "release-without-storage-effect"})
}
