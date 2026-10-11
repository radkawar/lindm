//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// The managed local-admin account is created by the fixture and allowlisted
// only in the root-owned executor configuration before enrollment.
const localAdminLabAccount = "lindm-laps"

// The post-reveal delay leaves a bounded window to prove the revealed password
// with a real login before the scheduled rotation supersedes it.
const localAdminPostRevealDelay = 90 * time.Second

const localAdminFixtureScript = `set -eu
. /etc/os-release
case "$ID" in
 ubuntu) admin=sudo ;;
 fedora) admin=wheel ;;
 *) echo 'local-admin lane requires Ubuntu or Fedora' >&2; exit 1 ;;
esac
useradd --create-home --shell /bin/bash --groups "$admin" ` + localAdminLabAccount + `
if command -v restorecon >/dev/null 2>&1; then restorecon -RF /home/` + localAdminLabAccount + `; fi
`

// VMLocalAdminEvidence records server states, action IDs, denials and native
// metadata for one managed local-admin account. Passwords and hashes never
// enter it.
type VMLocalAdminEvidence struct {
	Account         string                            `json:"account"`
	AccountUID      uint32                            `json:"account_uid"`
	Policy          *adminv1.LocalAdminPasswordPolicy `json:"policy,omitempty"`
	Steps           []VMLocalAdminStep                `json:"steps"`
	NativeQualified bool                              `json:"native_qualified"`
	Unproven        []string                          `json:"unproven"`
}

type VMLocalAdminStep struct {
	Name       string                            `json:"name"`
	StartedAt  time.Time                         `json:"started_at"`
	FinishedAt time.Time                         `json:"finished_at"`
	Status     *adminv1.LocalAdminPasswordStatus `json:"status,omitempty"`
	Action     *agentv1.DeviceActionStatus       `json:"action,omitempty"`
	ActionID   string                            `json:"action_id,omitempty"`
	ApprovalID string                            `json:"approval_id,omitempty"`
	Denial     *actionDenialEvidence             `json:"denial,omitempty"`
	Native     []VMResourceNativeRecord          `json:"native_records"`
	Passed     bool                              `json:"passed"`
	Failure    string                            `json:"failure,omitempty"`
}

// validLocalAdminPassword accepts exactly crypto/rand.Text output: 26
// characters of the RFC 4648 base32 alphabet.
func validLocalAdminPassword(password []byte) bool {
	if len(password) != 26 {
		return false
	}
	for _, character := range password {
		if (character < 'A' || character > 'Z') && (character < '2' || character > '7') {
			return false
		}
	}
	return true
}

// qualifyLocalAdminEvidence rejects incomplete, failed or tampered steps
// before the managed local-admin scenario can be marked qualified.
func qualifyLocalAdminEvidence(evidence *VMLocalAdminEvidence, required []string) error {
	if evidence == nil || len(evidence.Steps) != len(required) {
		return errors.New("incomplete managed local-admin steps")
	}
	for index, name := range required {
		step := &evidence.Steps[index]
		if step.Name != name || !step.Passed || step.Failure != "" || step.StartedAt.IsZero() || step.FinishedAt.Before(step.StartedAt) || (len(step.Native) == 0 && step.Denial == nil && step.Status == nil) {
			return fmt.Errorf("managed local-admin step %s lacks completed evidence", name)
		}
		if step.Action != nil && step.Action.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
			return fmt.Errorf("managed local-admin step %s has an unsuccessful action", name)
		}
		for _, record := range step.Native {
			if record.Name == "" || len(record.Bytes) == 0 || resourceNativeRecord(record.Name, record.Bytes).SHA256 != record.SHA256 {
				return fmt.Errorf("managed local-admin step %s has invalid record digest", name)
			}
		}
	}
	evidence.NativeQualified = len(evidence.Unproven) == 0
	return nil
}

func (e *VMLocalAdminEvidence) run(ctx context.Context, vm *guestVM, name string, body func(*VMLocalAdminStep) error) error {
	e.Steps = append(e.Steps, VMLocalAdminStep{Name: name, StartedAt: time.Now().UTC()})
	step := &e.Steps[len(e.Steps)-1]
	if err := body(step); err != nil {
		step.Failure = err.Error()
		step.Native = append(step.Native, executorDiagnostics(ctx, vm))
		return fmt.Errorf("%s: %w", name, err)
	}
	step.FinishedAt = time.Now().UTC()
	step.Passed = true
	return nil
}

// localAdminShadowOracle prints account status and aging, never field 2 of
// shadow; only whether a usable password is set and its crypt identifier.
func localAdminShadowOracle(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
	account := localAdminLabAccount
	command := "passwd -S " + account + "; chage -l " + account + "; getent shadow " + account + " | cut -d: -f1,3-; hash=$(getent shadow " + account + " | cut -d: -f2); case \"$hash\" in ''|'!'*|'*'*) echo password-unusable; exit 1 ;; esac; printf 'password-usable crypt-id=%s\\n' \"$(printf '%s' \"$hash\" | cut -d'$' -f2)\""
	return resourceOracle(ctx, vm, "native-local-admin-shadow-status-aging", command)
}

func localAdminStatus(ctx context.Context, control *vmControlPlane, device string) (*adminv1.LocalAdminPasswordStatus, error) {
	response, err := control.session.Admin.GetLocalAdminPasswordStatus(ctx, connect.NewRequest(&adminv1.GetLocalAdminPasswordStatusRequest{DeviceId: device}))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetStatus(), nil
}

// waitLocalAdminCurrent waits for a CURRENT escrow minted by an action other
// than previous; a non-empty previous escrow must then be SUPERSEDED.
func waitLocalAdminCurrent(ctx context.Context, control *vmControlPlane, device, previous string) (*adminv1.LocalAdminPasswordStatus, *adminv1.LocalAdminPasswordEscrow, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	var status *adminv1.LocalAdminPasswordStatus
	for {
		var err error
		status, err = localAdminStatus(ctx, control, device)
		if err != nil {
			return status, nil, err
		}
		if status.GetBlockedReason() != "" {
			return status, nil, fmt.Errorf("managed local-admin policy blocked: %s", status.GetBlockedReason())
		}
		var current *adminv1.LocalAdminPasswordEscrow
		superseded := previous == ""
		for _, escrow := range status.GetEscrows() {
			switch {
			case escrow.GetActionId() == previous:
				superseded = escrow.GetState() == adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_SUPERSEDED
			case escrow.GetState() == adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_CURRENT:
				if current != nil {
					return status, nil, errors.New("managed local-admin status has two CURRENT escrows")
				}
				current = escrow
			case escrow.GetState() == adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_FAILED:
				return status, nil, fmt.Errorf("managed local-admin rotation %s failed", escrow.GetActionId())
			}
		}
		if current != nil && superseded {
			return status, current, nil
		}
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return status, nil, fmt.Errorf("managed local-admin rotation did not become CURRENT: %w; last=%s", err, status)
		}
	}
}

// revealLocalAdmin performs the real step-up, exact second-human approval and
// reveal. The caller owns and clears the returned password.
func revealLocalAdmin(ctx context.Context, control *vmControlPlane, device, action string) ([]byte, *adminv1.RevealLocalAdminPasswordResponse, string, error) {
	if err := control.session.StepUp(ctx); err != nil {
		return nil, nil, "", err
	}
	if control.approver == nil {
		approver, err := control.openApprover(ctx)
		if err != nil {
			return nil, nil, "", err
		}
		control.approver = approver
	}
	request := &adminv1.RevealLocalAdminPasswordRequest{RequestId: uuid.NewString(), DeviceId: device, ActionId: action, Reason: "disposable managed local-admin login qualification"}
	approval, err := control.approver.Approve(ctx, control.session, &adminv1.CreateApprovalRequest{LifetimeSeconds: 300, Payload: &adminv1.CreateApprovalRequest_RevealLocalAdminPassword{RevealLocalAdminPassword: request}})
	if err != nil {
		return nil, nil, "", fmt.Errorf("approve local-admin reveal: %w", err)
	}
	request.ApprovalId = approval.GetId()
	response, err := control.session.Admin.RevealLocalAdminPassword(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, nil, approval.GetId(), fmt.Errorf("reveal local-admin password: %w", err)
	}
	password := response.Msg.Password
	response.Msg.Password = nil
	if !validLocalAdminPassword(password) {
		clear(password)
		return nil, nil, approval.GetId(), errors.New("revealed local-admin password is not 26 base32 characters")
	}
	escrow := response.Msg.GetEscrow()
	if escrow.GetActionId() != action || escrow.GetAccountName() != localAdminLabAccount || escrow.GetLastRevealedAt() == nil || response.Msg.GetRotationDueAt() == nil {
		clear(password)
		return nil, nil, approval.GetId(), errors.New("local-admin reveal response does not describe the revealed escrow and scheduled rotation")
	}
	return password, response.Msg, approval.GetId(), nil
}

// exerciseLocalAdminPassword drives the server-minted rotation, a denied and
// an approved reveal, a real SSH login with the revealed password, and the
// post-reveal rotation that supersedes it.
func exerciseLocalAdminPassword(ctx context.Context, vm *guestVM, control *vmControlPlane, device string, evidence *VMLocalAdminEvidence) error {
	account := localAdminLabAccount
	if err := evidence.run(ctx, vm, "account-fixture", func(step *VMLocalAdminStep) error {
		sshd, err := installPasswordLoginDropIn(ctx, vm, account)
		if err != nil {
			return err
		}
		native, err := resourceOracle(ctx, vm, "native-local-admin-account-allowlist-sandbox", "id "+account+"; id -u "+account+"; passwd -S "+account+"; grep -F '\""+account+"\"' /etc/lindm/executor.json >/dev/null; printf 'executor-allowlist %s\\n' "+account+"; systemctl cat lindm-executor.service | grep -E '^(ReadWritePaths|CapabilityBoundingSet|LimitMEMLOCK)='")
		if err != nil {
			return err
		}
		step.Native = []VMResourceNativeRecord{sshd, native}
		uid, err := vm.run(ctx, "id -u "+account, nil, 64, 10*time.Second)
		if err != nil {
			return err
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(string(uid)), 10, 32)
		if err != nil || parsed == 0 {
			return errors.New("invalid managed local-admin account UID")
		}
		evidence.AccountUID = uint32(parsed)
		return nil
	}); err != nil {
		return err
	}
	var first *adminv1.LocalAdminPasswordEscrow
	if err := evidence.run(ctx, vm, "policy-first-rotation", func(step *VMLocalAdminStep) error {
		if err := control.session.StepUp(ctx); err != nil {
			return err
		}
		evidence.Policy = &adminv1.LocalAdminPasswordPolicy{AccountName: account, RotationInterval: durationpb.New(24 * time.Hour), PostRevealRotationDelay: durationpb.New(localAdminPostRevealDelay)}
		if _, err := control.session.Admin.SetLocalAdminPasswordPolicy(ctx, connect.NewRequest(&adminv1.SetLocalAdminPasswordPolicyRequest{RequestId: uuid.NewString(), DeviceId: device, Policy: evidence.Policy, Reason: "disposable managed local-admin rotation qualification"})); err != nil {
			return fmt.Errorf("set local-admin policy: %w", err)
		}
		var err error
		step.Status, first, err = waitLocalAdminCurrent(ctx, control, device, "")
		if err != nil {
			return err
		}
		step.ActionID = first.GetActionId()
		if first.GetAccountName() != account || first.GetAccountUid() != evidence.AccountUID {
			return errors.New("managed local-admin escrow names a different native account")
		}
		step.Action, err = waitPowerServerState(ctx, control.session, first.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
		if err != nil {
			return err
		}
		native, err := localAdminShadowOracle(ctx, vm)
		if err != nil {
			return err
		}
		step.Native = []VMResourceNativeRecord{native}
		return nil
	}); err != nil {
		return err
	}
	if err := evidence.run(ctx, vm, "reveal-without-approval-denied", func(step *VMLocalAdminStep) error {
		if err := control.session.StepUp(ctx); err != nil {
			return err
		}
		step.ActionID = first.GetActionId()
		response, rejected := control.session.Admin.RevealLocalAdminPassword(ctx, connect.NewRequest(&adminv1.RevealLocalAdminPasswordRequest{RequestId: uuid.NewString(), DeviceId: device, ActionId: first.GetActionId(), Reason: "unapproved managed local-admin reveal negative"}))
		if response != nil {
			clear(response.Msg.Password)
		}
		denial, err := actionDenial(step.Name, rejected, connect.CodePermissionDenied)
		if err != nil {
			return err
		}
		step.Denial = &denial
		if denial.Reason != "approval_required" {
			return fmt.Errorf("unapproved reveal denied for %q instead of approval_required", denial.Reason)
		}
		return nil
	}); err != nil {
		return err
	}
	var firstPassword []byte
	defer func() { clear(firstPassword) }()
	if err := evidence.run(ctx, vm, "approved-reveal-login", func(step *VMLocalAdminStep) error {
		step.ActionID = first.GetActionId()
		password, response, approval, err := revealLocalAdmin(ctx, control, device, first.GetActionId())
		step.ApprovalID = approval
		if err != nil {
			return err
		}
		firstPassword = password
		login, err := passwordLogin(ctx, vm, account, firstPassword)
		if err != nil {
			return err
		}
		step.Native = login
		step.Status, err = localAdminStatus(ctx, control, device)
		if err != nil {
			return err
		}
		if !step.Status.GetRotationDueAt().AsTime().Equal(response.GetRotationDueAt().AsTime()) {
			return errors.New("post-reveal rotation schedule differs between reveal and status")
		}
		return nil
	}); err != nil {
		return err
	}
	var second *adminv1.LocalAdminPasswordEscrow
	if err := evidence.run(ctx, vm, "post-reveal-rotation-supersedes", func(step *VMLocalAdminStep) error {
		var err error
		step.Status, second, err = waitLocalAdminCurrent(ctx, control, device, first.GetActionId())
		if err != nil {
			return err
		}
		step.ActionID = second.GetActionId()
		step.Action, err = waitPowerServerState(ctx, control.session, second.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
		if err != nil {
			return err
		}
		native, err := localAdminShadowOracle(ctx, vm)
		if err != nil {
			return err
		}
		refused, err := passwordLoginRefused(ctx, vm, account, firstPassword, "ssh-password-login-refused-superseded")
		if err != nil {
			return err
		}
		step.Native = []VMResourceNativeRecord{native, refused}
		return nil
	}); err != nil {
		return err
	}
	if err := evidence.run(ctx, vm, "reveal-rotated-login", func(step *VMLocalAdminStep) error {
		step.ActionID = second.GetActionId()
		password, _, approval, err := revealLocalAdmin(ctx, control, device, second.GetActionId())
		step.ApprovalID = approval
		if err != nil {
			return err
		}
		defer clear(password)
		step.Native, err = passwordLogin(ctx, vm, account, password)
		return err
	}); err != nil {
		return err
	}
	// Removing the policy stops the rotation scheduled by the last reveal.
	if err := evidence.run(ctx, vm, "remove-policy", func(step *VMLocalAdminStep) error {
		if err := control.session.StepUp(ctx); err != nil {
			return err
		}
		if _, err := control.session.Admin.RemoveLocalAdminPasswordPolicy(ctx, connect.NewRequest(&adminv1.RemoveLocalAdminPasswordPolicyRequest{RequestId: uuid.NewString(), DeviceId: device, Reason: "disposable managed local-admin policy removal"})); err != nil {
			return fmt.Errorf("remove local-admin policy: %w", err)
		}
		var err error
		step.Status, err = localAdminStatus(ctx, control, device)
		if err != nil {
			return err
		}
		if step.Status.GetPolicy() != nil {
			return errors.New("managed local-admin policy remained after removal")
		}
		return nil
	}); err != nil {
		return err
	}
	evidence.Unproven = nil
	return qualifyLocalAdminEvidence(evidence, []string{"account-fixture", "policy-first-rotation", "reveal-without-approval-denied", "approved-reveal-login", "post-reveal-rotation-supersedes", "reveal-rotated-login", "remove-policy"})
}
