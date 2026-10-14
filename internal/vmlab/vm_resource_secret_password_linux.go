// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// A dedicated account in the root-approved lane range, distinct from the
// accounts kind, receives its password only as a sealed SecretRef delivery.
// Its UID is free in the host fixture, which secret-password also installs:
// rlabforeign holds 24003 for the accounts kind's UID-collision refusal.
const (
	resourceSecretUser   = "rlabsecret"
	resourceSecretUserID = 24006
)

// VMSecretPasswordEvidence is metadata only: secret identity, pinned versions
// and native sshd configuration. Passwords and hashes never enter the record.
type VMSecretPasswordEvidence struct {
	Account    string                   `json:"account"`
	AccountUID uint32                   `json:"account_uid"`
	Algorithm  string                   `json:"algorithm"`
	Secret     *adminv1.SecretSummary   `json:"secret,omitempty"`
	Refs       []*resourcev1.SecretRef  `json:"refs"`
	Fixture    []VMResourceNativeRecord `json:"fixture_records"`
}

var sha512CryptHash = regexp.MustCompile(`^[$]6[$][./A-Za-z0-9]{1,16}[$][./A-Za-z0-9]{86}$`)

// guestPasswordHash derives a SHA-512 crypt hash with the guest's own OpenSSL
// from stdin. The plaintext never enters argv, and the operation's stdout is
// kept out of failure diagnostics.
func guestPasswordHash(ctx context.Context, vm *guestVM, password []byte) ([]byte, error) {
	input := make([]byte, 0, len(password)+1)
	input = append(append(input, password...), '\n')
	defer clear(input)
	capture := vm.captureDiagnostics
	vm.captureDiagnostics = false
	defer func() { vm.captureDiagnostics = capture }()
	output, err := vm.run(ctx, "openssl passwd -6 -stdin", bytes.NewReader(input), 512, 30*time.Second)
	defer clear(output)
	if err != nil {
		return nil, fmt.Errorf("derive guest password hash: %w", err)
	}
	hash := bytes.TrimSuffix(output, []byte{'\n'})
	if !sha512CryptHash.Match(hash) {
		return nil, errors.New("guest password hash is not SHA-512 crypt")
	}
	return bytes.Clone(hash), nil
}

func resourceSecretUserDesired(ref *resourcev1.SecretRef) *resourcev1.ResourceDesiredState {
	user := &resourcev1.LocalUserDesired{
		Name: resourceSecretUser, Presence: resourcev1.Presence_PRESENCE_PRESENT, Uid: proto.Uint32(resourceSecretUserID),
		PrimaryGroup: proto.String(resourceLabPrimary), HomeDirectory: proto.String(resourceLabHomeRoot + "/" + resourceSecretUser),
		Shell:    &resourcev1.LoginShell{InstalledShell: "/bin/bash"},
		Password: &resourcev1.PasswordState{State: &resourcev1.PasswordState_Hashed{Hashed: &resourcev1.HashedPasswordPolicy{Hash: ref, Algorithm: resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT}}},
		Home:     &resourcev1.HomePolicy{Creation: resourcev1.HomeCreation_HOME_CREATION_CREATE_IF_ABSENT, Mode: proto.Uint32(0o700), ApprovedRootId: resourceLabHomeRootID},
	}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: resourceSecretUser}, State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: user}}
}

func secretRefFromSummary(summary *adminv1.SecretSummary) *resourcev1.SecretRef {
	return &resourcev1.SecretRef{SecretId: summary.GetSecretId(), Version: summary.GetCurrentVersion(), Purpose: summary.GetPurpose(), SubjectBindingId: summary.GetSubjectBindingId()}
}

// secretUserOracle compares the delivered shadow hash with the expected one
// inside the guest. The expectation arrives on stdin; only the verdict, the
// algorithm prefix and passwd/id metadata are printed.
func secretUserOracle(ctx context.Context, vm *guestVM, hash []byte) (VMResourceNativeRecord, error) {
	home := resourceLabHomeRoot + "/" + resourceSecretUser
	command := fmt.Sprintf("IFS= read -r want; have=$(getent shadow %s | cut -d: -f2); test -n \"$have\"; if [ \"$have\" != \"$want\" ]; then echo hash-differs; exit 1; fi; printf 'hash-matches %%s\\n' \"$(printf '%%s' \"$want\" | cut -c1-3)\"; passwd -S %s; test \"$(getent passwd %s)\" = '%s:x:%d:%d::%s:/bin/bash'; id %s; test \"$(stat -c '%%a %%u %%g' %s)\" = '700 %d %d'; stat -c '%%n %%a %%u %%g' %s",
		resourceSecretUser, resourceSecretUser, resourceSecretUser, resourceSecretUser, resourceSecretUserID, resourceLabPrimaryID, home, resourceSecretUser, home, resourceSecretUserID, resourceLabPrimaryID, home)
	input := make([]byte, 0, len(hash)+1)
	input = append(append(input, hash...), '\n')
	defer clear(input)
	return resourceOracleInput(ctx, vm, "native-shadow-hash-matches-delivered-secret", command, input)
}

func secretUserAbsentOracle(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
	home := resourceLabHomeRoot + "/" + resourceSecretUser
	command := "if getent passwd " + resourceSecretUser + "; then exit 1; fi; if grep -q '^" + resourceSecretUser + ":' /etc/passwd /etc/shadow; then exit 1; fi; test -d " + home + "; stat -c '%n %a %u %g' " + home + "; printf 'user-absent-home-preserved\\n'"
	return resourceOracle(ctx, vm, "native-user-database-absent", command)
}

// exerciseResourceSecretPassword proves that a password-hash SecretRef reaches
// shadow only through the sealed per-device delivery, that the resulting
// password authenticates a real SSH/PAM login, and that rotation to a new
// pinned version and release retire the previous credential.
func exerciseResourceSecretPassword(ctx context.Context, r *resourceDispatch, evidence *VMSecretPasswordEvidence, kind *VMResourceKindEvidence) error {
	evidence.Account, evidence.AccountUID = resourceSecretUser, resourceSecretUserID
	evidence.Algorithm = resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT.String()
	sshd, err := installPasswordLoginDropIn(ctx, r.vm, resourceSecretUser)
	if err != nil {
		return err
	}
	evidence.Fixture = append(evidence.Fixture, sshd)
	first := []byte(rand.Text())
	defer clear(first)
	firstHash, err := guestPasswordHash(ctx, r.vm, first)
	if err != nil {
		return err
	}
	defer clear(firstHash)
	created, err := r.control.session.Admin.CreateSecret(ctx, connect.NewRequest(&adminv1.CreateSecretRequest{RequestId: uuid.NewString(), Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, DisplayName: "Disposable lab " + resourceSecretUser + " password", Material: &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_PasswordHash{PasswordHash: firstHash}}, Reason: "disposable native secret delivery qualification"}))
	if err != nil {
		return fmt.Errorf("create password hash secret: %w", err)
	}
	evidence.Secret = created.Msg.GetSecret()
	firstRef := secretRefFromSummary(evidence.Secret)
	if firstRef.GetVersion() != 1 || firstRef.GetPurpose() != resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH {
		return errors.New("created secret is not password-hash version 1")
	}
	evidence.Refs = append(evidence.Refs, firstRef)
	if err := resourceStepRecords(ctx, r, kind, "create-hashed-password", resourceSecretUserDesired(firstRef), resourceCreatePolicy(), false, func(ctx context.Context) ([]VMResourceNativeRecord, error) {
		shadow, err := secretUserOracle(ctx, r.vm, firstHash)
		if err != nil {
			return nil, err
		}
		login, err := passwordLogin(ctx, r.vm, resourceSecretUser, first)
		if err != nil {
			return nil, err
		}
		return append([]VMResourceNativeRecord{shadow}, login...), nil
	}); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, kind, "repeat", resourceSecretUserDesired(firstRef), resourceCreatePolicy(), true, func(ctx context.Context) (VMResourceNativeRecord, error) {
		return secretUserOracle(ctx, r.vm, firstHash)
	}); err != nil {
		return err
	}
	second := []byte(rand.Text())
	defer clear(second)
	secondHash, err := guestPasswordHash(ctx, r.vm, second)
	if err != nil {
		return err
	}
	defer clear(secondHash)
	rotated, err := r.control.session.Admin.RotateSecret(ctx, connect.NewRequest(&adminv1.RotateSecretRequest{RequestId: uuid.NewString(), SecretId: firstRef.GetSecretId(), ExpectedVersion: 1, Material: &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_PasswordHash{PasswordHash: secondHash}}, Reason: "disposable native secret rotation qualification"}))
	if err != nil {
		return fmt.Errorf("rotate password hash secret: %w", err)
	}
	evidence.Secret = rotated.Msg.GetSecret()
	secondRef := secretRefFromSummary(evidence.Secret)
	if secondRef.GetVersion() != 2 || secondRef.GetSecretId() != firstRef.GetSecretId() || secondRef.GetSubjectBindingId() != firstRef.GetSubjectBindingId() {
		return errors.New("rotated secret is not version 2 of the same binding")
	}
	evidence.Refs = append(evidence.Refs, secondRef)
	if err := resourceStepRecords(ctx, r, kind, "rotate-secret-version", resourceSecretUserDesired(secondRef), resourceCreatePolicy(), false, func(ctx context.Context) ([]VMResourceNativeRecord, error) {
		shadow, err := secretUserOracle(ctx, r.vm, secondHash)
		if err != nil {
			return nil, err
		}
		login, err := passwordLogin(ctx, r.vm, resourceSecretUser, second)
		if err != nil {
			return nil, err
		}
		refused, err := passwordLoginRefused(ctx, r.vm, resourceSecretUser, first, "ssh-password-login-refused-previous-version")
		if err != nil {
			return nil, err
		}
		return append(append([]VMResourceNativeRecord{shadow}, login...), refused), nil
	}); err != nil {
		return err
	}
	if err := resourceReleaseStepRecords(ctx, r, kind, "release-removes-user", resourceSecretUserDesired(secondRef).GetRef(), func(ctx context.Context) ([]VMResourceNativeRecord, error) {
		absent, err := secretUserAbsentOracle(ctx, r.vm)
		if err != nil {
			return nil, err
		}
		refused, err := passwordLoginRefused(ctx, r.vm, resourceSecretUser, second, "ssh-password-login-refused-released-user")
		if err != nil {
			return nil, err
		}
		return []VMResourceNativeRecord{absent, refused}, nil
	}); err != nil {
		return err
	}
	kind.Unproven = nil
	return qualifyResourceEvidence(kind, []string{"create-hashed-password", "repeat", "rotate-secret-version", "release-removes-user"})
}
