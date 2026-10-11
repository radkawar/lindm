//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
)

// Managed local-admin rotation is escrow-before-effect. Phase one (after the
// consumed start grant) generates a password, seals it to the signed escrow key
// and to installation private custody, and changes nothing natively. Phase two
// runs only after the executor verified a durable escrow receipt: chpasswd reads
// "name:password\n" on stdin (never argv or environment) and hashes with the
// system's configured method. Privileges: root, shadow write access to /etc.
// Interruption after phase two starts is outcome_unknown, never retried here.

// localAdminCustody is the protected journal's private custody boundary.
type localAdminCustody interface {
	SealLocalAdminPassword(*agentv1.LocalAdminPasswordBinding, []byte) (*agentv1.PrivateCustodyEnvelope, error)
	OpenLocalAdminPassword(*agentv1.LocalAdminPasswordBinding, *agentv1.PrivateCustodyEnvelope) ([]byte, error)
}

var _ localAdminCustody = (*journal.Store)(nil)

type localAdminNative struct {
	seal     func(context.Context, *agentv1.LocalAdminPasswordBinding, *agentv1.DeviceActionSpec, []byte) ([]byte, error)
	custody  localAdminCustody
	accounts func(context.Context) (map[string]*agentv1.AccountLockSnapshot, error)
	// root is the production "/" or a root-only temporary-root test seam.
	root string
}

// Exactly crypto/rand.Text's construction (26 symbols of the RFC 4648 base32
// alphabet, ≥128 bits), built in locked memory so the plaintext can be cleared;
// rand.Text returns an immutable string that cannot be zeroized.
const (
	localAdminPasswordLength = 26
	localAdminAlphabet       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

func (p *Provider) localAdminAccount(ctx context.Context, name string) (*agentv1.LocalAdminAccountObservation, string, error) {
	accounts, err := p.localAdmin.accounts(ctx)
	if err != nil {
		return nil, "", err
	}
	account := accounts[name]
	if account == nil || account.GetShadowEntry() == "" {
		return nil, "", nil
	}
	shadow := strings.Split(account.GetShadowEntry(), ":")
	if len(shadow) != 9 {
		return nil, "", ErrUnsupported
	}
	observation := &agentv1.LocalAdminAccountObservation{AccountName: name, AccountUid: account.GetUid(), PasswordUsable: shadowPasswordUsable(shadow[1])}
	if shadow[2] != "" {
		day, err := strconv.ParseUint(shadow[2], 10, 32)
		if err != nil || day > 1000000 {
			return nil, "", ErrUnsupported
		}
		observation.PasswordChangedDay = uint32(day)
	}
	return observation, shadow[1], nil
}

// A locked ("!"/"*"-prefixed) or empty field cannot authenticate the account.
func shadowPasswordUsable(field string) bool {
	return field != "" && !strings.HasPrefix(field, "!") && !strings.HasPrefix(field, "*")
}

func (p *Provider) observeLocalAdmin(ctx context.Context, spec *agentv1.DeviceActionSpec, observation *agentv1.DeviceActionObservation) (*agentv1.DeviceActionObservation, error) {
	name := spec.GetLocalAdminPasswordRotate().GetAccountName()
	unsupported := func(reason string) (*agentv1.DeviceActionObservation, error) {
		observation.Supported, observation.Reason = false, reason
		return observation, nil
	}
	if p.localAdmin == nil || !slices.Contains(p.config.GetLocalAdminAccounts(), name) {
		return unsupported("local_admin_account_not_allowlisted")
	}
	if name == "root" {
		return unsupported("local_admin_root_refused")
	}
	account, _, err := p.localAdminAccount(ctx, name)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return unsupported("local_admin_account_missing")
	}
	observation.LocalAdmin = account
	if account.GetAccountUid() == 0 {
		return unsupported("local_admin_root_refused")
	}
	return observation, nil
}

func (p *Provider) localAdminPlan(plan *agentv1.DeviceActionPlan) (*agentv1.LocalAdminPasswordBinding, error) {
	if err := p.validatePlan(plan); err != nil {
		return nil, err
	}
	action, binding := plan.GetSpec().GetLocalAdminPasswordRotate(), plan.GetLocalAdminBinding()
	if action == nil || binding == nil || binding.GetActionId() != plan.GetActionId() || binding.GetDeviceId() == "" || binding.GetEnrollmentGeneration() == "" || binding.GetAccountName() != action.GetAccountName() || binding.GetAccountUid() == 0 || binding.GetAccountName() == "root" {
		return nil, ErrConflict
	}
	if p.localAdmin == nil {
		return nil, fmt.Errorf("%w: escrow_custody_required", ErrUnsupported)
	}
	return binding, nil
}

// freshLocalAdmin re-observes the allowlisted account immediately before an
// effect: a renamed, removed or renumbered account is a refusal.
func (p *Provider) freshLocalAdmin(ctx context.Context, plan *agentv1.DeviceActionPlan, binding *agentv1.LocalAdminPasswordBinding) (*agentv1.DeviceActionObservation, string, error) {
	observation := &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(p.clock()), Supported: true}
	fresh, err := p.observeLocalAdmin(ctx, plan.GetSpec(), observation)
	if err != nil {
		return nil, "", err
	}
	if !fresh.GetSupported() || fresh.GetLocalAdmin().GetAccountUid() != binding.GetAccountUid() {
		return nil, "", ErrConflict
	}
	_, field, err := p.localAdminAccount(ctx, binding.GetAccountName())
	if err != nil {
		return nil, "", err
	}
	return fresh, field, nil
}

// StageLocalAdminPassword is phase one. The returned envelope is the only
// local copy of the password; the escrow ciphertext opens only on the server.
func (p *Provider) StageLocalAdminPassword(ctx context.Context, plan *agentv1.DeviceActionPlan, gate func(context.Context) error) (_ *agentv1.DeviceActionVerification, _ *agentv1.PrivateCustodyEnvelope, err error) {
	ctx, done, err := p.begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer done()
	binding, err := p.localAdminPlan(plan)
	if err != nil {
		return nil, nil, err
	}
	if gate == nil {
		return nil, nil, ErrConflict
	}
	fresh, _, err := p.freshLocalAdmin(ctx, plan, binding)
	if err != nil {
		return nil, nil, err
	}
	if err := gate(ctx); err != nil {
		return nil, nil, err
	}
	password, err := lockedMemory(localAdminPasswordLength)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, releaseMemory(password)) }()
	if _, err := rand.Read(password); err != nil {
		return nil, nil, err
	}
	for i := range password {
		password[i] = localAdminAlphabet[password[i]%32]
	}
	digest := sha256.Sum256(password)
	ciphertext, err := p.localAdmin.seal(ctx, binding, plan.GetSpec(), password)
	if err != nil {
		return nil, nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext) > 16384 {
		return nil, nil, ErrUnsupported
	}
	envelope, err := p.localAdmin.custody.SealLocalAdminPassword(binding, password)
	if err != nil {
		return nil, nil, err
	}
	action := plan.GetSpec().GetLocalAdminPasswordRotate()
	return &agentv1.DeviceActionVerification{After: fresh, Evidence: "Password generated and sealed to the signed escrow key; no native change before an authenticated durable escrow receipt.", Escrow: &agentv1.DeviceActionEscrow{EscrowKeyId: action.GetEscrowKeyId(), Ciphertext: ciphertext, RecoveryKeySha256: digest[:], LocalAdmin: proto.CloneOf(binding)}}, envelope, nil
}

// SetLocalAdminPassword is phase two, called only with a verified receipt. The
// gate durably records RETIRING_ESCROW before chpasswd runs.
func (p *Provider) SetLocalAdminPassword(ctx context.Context, plan *agentv1.DeviceActionPlan, stage *agentv1.DeviceActionVerification, sealed *agentv1.PrivateCustodyEnvelope, gate func(context.Context) error) (_ *agentv1.DeviceActionVerification, err error) {
	ctx, done, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	binding, err := p.localAdminPlan(plan)
	if err != nil {
		return nil, err
	}
	if stage == nil || sealed == nil || gate == nil || !proto.Equal(stage.GetEscrow().GetLocalAdmin(), binding) || stage.GetEscrow().GetEscrowKeyId() != plan.GetSpec().GetLocalAdminPasswordRotate().GetEscrowKeyId() {
		return nil, ErrConflict
	}
	if err := p.validate.Validate(stage); err != nil {
		return nil, err
	}
	password, err := p.localAdmin.custody.OpenLocalAdminPassword(binding, sealed)
	if err != nil {
		return nil, err
	}
	defer clear(password)
	digest := sha256.Sum256(password)
	if len(password) != localAdminPasswordLength || !bytes.Equal(digest[:], stage.GetEscrow().GetRecoveryKeySha256()) || bytes.IndexFunc(password, func(r rune) bool { return !strings.ContainsRune(localAdminAlphabet, r) }) != -1 {
		return nil, ErrConflict
	}
	_, before, err := p.freshLocalAdmin(ctx, plan, binding)
	if err != nil {
		return nil, err
	}
	input, err := lockedMemory(len(binding.GetAccountName()) + 1 + len(password) + 1)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, releaseMemory(input)) }()
	n := copy(input, binding.GetAccountName())
	input[n] = ':'
	n++
	n += copy(input[n:], password)
	input[n] = '\n'
	var args []string
	if p.localAdmin.root != "/" {
		// Temporary-root tests only: PAM modules cannot load inside the chroot,
		// so an explicit method replaces the production system default.
		args = []string{"--root", p.localAdmin.root, "--crypt-method", "SHA512"}
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	if _, err := p.run(ctx, nativeRequest{command: chpasswd, args: args, input: input}); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	after, field, err := p.freshLocalAdmin(ctx, plan, binding)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if field == before || !shadowPasswordUsable(field) || !after.GetLocalAdmin().GetPasswordUsable() {
		return nil, ErrOutcomeUnknown
	}
	result := proto.CloneOf(stage)
	result.Verified = true
	result.After = after
	result.Evidence = "Escrowed password set by native chpasswd on stdin after the durable escrow receipt; shadow password field changed and is usable."
	return result, nil
}
