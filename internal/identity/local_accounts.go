package identity

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

// Enrollment is returned once to the administrator; only its digest is stored.
type Enrollment struct {
	Secret    string
	ExpiresAt time.Time
	AccountID uuid.UUID
}

var errOwnerAuthenticationMode = errors.New("identity: owner_authentication_mode_mismatch")

// checkOwnerAuthenticationMode rejects a configuration cutover that would strand
// the initialized owner. Uninitialized deployments must remain bootstrappable.
func (s *Service) checkOwnerAuthenticationMode(ctx context.Context, q *identitydb.Queries) error {
	deployment, err := q.LockDeploymentIdentity(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	if deployment.OwnerPrincipalID == nil && !deployment.InitializedAt.Valid {
		return nil
	}
	if deployment.OwnerPrincipalID == nil || !deployment.InitializedAt.Valid {
		return errStore
	}
	owner, err := q.GetPrincipalByID(ctx, *deployment.OwnerPrincipalID)
	if err != nil {
		return s.dbErr(err)
	}
	if s.localPrimary {
		if owner.Issuer != s.localIssuer || owner.Subject != owner.ID.String() {
			return errOwnerAuthenticationMode
		}
		if _, err := q.GetLocalAccount(ctx, owner.ID); err != nil {
			if errors.Is(s.dbErr(err), errNotFound) {
				return errOwnerAuthenticationMode
			}
			return s.dbErr(err)
		}
		return nil
	}
	if owner.Issuer == s.issuer {
		return nil
	}
	if s.breakGlass == nil {
		return errOwnerAuthenticationMode
	}
	available, err := q.HasEnrolledBreakGlassOwner(ctx, s.localIssuer)
	if err != nil {
		return s.dbErr(err)
	}
	if !available {
		return errOwnerAuthenticationMode
	}
	return nil
}

// BootstrapLocalOwner claims an uninitialized deployment exactly once.
func (s *Service) BootstrapLocalOwner(ctx context.Context, username string) (Enrollment, error) {
	if !s.localPrimary {
		return Enrollment{}, ErrIssuerMismatch
	}
	var enrollment Enrollment
	err := s.withTx(ctx, func(q *identitydb.Queries) error {
		deployment, err := q.LockDeploymentIdentity(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		if deployment.InitializedAt.Valid || deployment.OwnerPrincipalID != nil {
			return ErrOwnerInitialized
		}
		enrollment, err = s.createLocalAccount(ctx, q, &authv1.CreateAccountRequest{Username: username, Role: RoleOwner})
		if err != nil {
			return err
		}
		if _, err = q.MarkDeploymentInitialized(ctx, &enrollment.AccountID); err != nil {
			return s.dbErr(err)
		}
		return s.insertSystemAudit(ctx, q, &enrollment.AccountID, auditOwnerBootstrapped, principalResource(enrollment.AccountID), reasonInitialOwner)
	})
	return enrollment, err
}

func (s *Service) createLocalAccount(ctx context.Context, q *identitydb.Queries, request *authv1.CreateAccountRequest) (Enrollment, error) {
	if err := s.rules.Validate(request); err != nil {
		return Enrollment{}, err
	}
	username, role, breakGlass := request.GetUsername(), request.GetRole(), request.GetBreakGlass()
	if s.policy.role(role) == nil {
		return Enrollment{}, ErrAuthorizationDenied
	}
	scopeBinding, err := protojson.Marshal(&authv1.RoleBinding{Scopes: request.GetScopes()})
	if err != nil {
		return Enrollment{}, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return Enrollment{}, err
	}
	_, err = q.UpsertPrincipal(ctx, identitydb.UpsertPrincipalParams{ID: id, Issuer: s.localIssuer, Subject: id.String(), DisplayName: username})
	if err != nil {
		return Enrollment{}, s.dbErr(err)
	}
	if err = q.InsertLocalAccount(ctx, identitydb.InsertLocalAccountParams{ID: id, Username: username, Role: role, BreakGlass: breakGlass, ScopeBinding: scopeBinding}); err != nil {
		return Enrollment{}, s.dbErr(err)
	}
	if err = s.bumpLocalAuthorization(ctx, q, id, role); err != nil {
		return Enrollment{}, s.dbErr(err)
	}
	return s.issueEnrollment(ctx, q, id)
}

func (s *Service) issueEnrollment(ctx context.Context, q *identitydb.Queries, id uuid.UUID) (Enrollment, error) {
	secret, err := randomToken()
	if err != nil {
		return Enrollment{}, err
	}
	expires, err := q.IssueLocalEnrollment(ctx, identitydb.IssueLocalEnrollmentParams{SecretHash: domainHash("lindm.local.enrollment.v1", secret), AccountID: id})
	if err != nil {
		return Enrollment{}, s.dbErr(err)
	}
	return Enrollment{Secret: secret, AccountID: id, ExpiresAt: expires.Time}, nil
}

func (s *Service) invalidateLocalAccount(ctx context.Context, q *identitydb.Queries, id uuid.UUID, role string) error {
	if err := s.bumpLocalAuthorization(ctx, q, id, role); err != nil {
		return s.dbErr(err)
	}
	revoked, err := q.RevokeBreakGlassSessions(ctx, id)
	if err != nil {
		return s.dbErr(err)
	}
	if revoked > 0 {
		if err := s.insertSystemAudit(ctx, q, &id, "identity.break_glass_terminated", principalResource(id), "local account authority or credentials changed"); err != nil {
			return err
		}
	}
	if _, err := q.RevokePrincipalSessions(ctx, id); err != nil {
		return s.dbErr(err)
	}
	if err := q.DeleteLocalCeremonies(ctx, id); err != nil {
		return s.dbErr(err)
	}
	return nil
}

func (s *Service) resetLocalCredentials(ctx context.Context, q *identitydb.Queries, id uuid.UUID) (Enrollment, error) {
	account, err := q.GetLocalAccount(ctx, id)
	if err != nil {
		return Enrollment{}, s.dbErr(err)
	}
	if err = s.invalidateLocalAccount(ctx, q, id, account.Role); err != nil {
		return Enrollment{}, err
	}
	if err = q.DeleteLocalCredentials(ctx, id); err != nil {
		return Enrollment{}, s.dbErr(err)
	}
	if err = q.DeleteLocalEnrollments(ctx, id); err != nil {
		return Enrollment{}, s.dbErr(err)
	}
	if err = q.SetLocalPassword(ctx, identitydb.SetLocalPasswordParams{ID: id, PasswordHash: ""}); err != nil {
		return Enrollment{}, s.dbErr(err)
	}
	return s.issueEnrollment(ctx, q, id)
}

func (s *Service) bumpLocalAuthorization(ctx context.Context, q *identitydb.Queries, id uuid.UUID, role string) error {
	account, err := q.GetLocalAccount(ctx, id)
	if err != nil {
		return s.dbErr(err)
	}
	binding := &authv1.RoleBinding{}
	if err := protojson.Unmarshal(account.ScopeBinding, binding); err != nil {
		return errStore
	}
	var bindings []*authv1.RoleBinding
	if definition := s.policy.role(role); definition != nil {
		binding.Role, binding.Permissions = role, definition.GetPermissions()
		bindings = []*authv1.RoleBinding{binding}
	}
	digest, err := bindingsDigest(bindings)
	if err != nil {
		return err
	}
	return s.dbErr(q.BumpLocalAuthorization(ctx, identitydb.BumpLocalAuthorizationParams{ID: id, AuthorizationRole: role, AuthorizationDigest: digest}))
}
