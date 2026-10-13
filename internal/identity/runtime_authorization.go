package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
	"lindm/internal/permissionupgrade"
)

var (
	ErrPolicyConflict = errors.New("identity: authorization_revision_conflict")
	ErrPolicyReplay   = errors.New("identity: authorization_request_conflict")
	ErrPolicyInvalid  = errors.New("identity: invalid_authorization_policy")
)

// GetAuthorization returns the active complete policy, not startup configuration.
// The same unrestricted account-management boundary protects reads and writes.
func (s *Service) GetAuthorization(ctx context.Context) (*adminv1.AuthorizationState, error) {
	var result *adminv1.AuthorizationState
	err := s.accountTransaction(ctx, func(q *identitydb.Queries, actor Principal) error {
		if err := s.checkAuthenticatedSession(ctx, q, actor.ID, false); err != nil {
			return err
		}
		policy, err := s.currentPolicy(ctx, q)
		if err != nil {
			return err
		}
		row, err := q.ReadRuntimeAuthorization(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		result = runtimeAuthorizationState(policy.definition, row.Revision, row.Definition != nil)
		result.UpdatedAt = timestamppb.New(row.UpdatedAt.Time)
		return nil
	})
	return result, err
}

// UpdateAuthorization serializes policy replacement before principal locks. Exact
// request replay returns the historical result only after checking current authority.
func (s *Service) UpdateAuthorization(ctx context.Context, request *adminv1.UpdateAuthorizationRequest) (*adminv1.AuthorizationState, error) {
	if request == nil || s.rules.Validate(request) != nil {
		return nil, ErrPolicyInvalid
	}
	policy, err := compilePolicy(s.policyConfiguration(request.GetPolicy()), s.rules)
	if err != nil {
		return nil, ErrPolicyInvalid
	}
	actor, ok := PrincipalFromContext(ctx)
	if !ok {
		return nil, ErrAuthorizationDenied
	}
	authorization, err := s.AuthorizeFresh(ctx, actor.ID, PermissionManageAccounts)
	if err != nil {
		return nil, err
	}
	if unrestricted, _ := DeviceScopes(authorization.principal, PermissionManageAccounts); !unrestricted {
		return nil, ErrAuthorizationDenied
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	requestID, _ := uuid.Parse(request.GetRequestId())
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, s.dbErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := identitydb.New(tx)
	current, err := q.LockRuntimeAuthorizationUpdate(ctx)
	if err != nil {
		return nil, s.dbErr(err)
	}
	if err := s.LockAuthorization(ctx, tx, authorization, PermissionManageAccounts); err != nil {
		return nil, err
	}
	if err := s.checkAuthenticatedSession(ctx, q, actor.ID, false); err != nil {
		return nil, err
	}
	replay, err := q.ReadAuthorizationRequest(ctx, identitydb.ReadAuthorizationRequestParams{ActorID: actor.ID, RequestID: requestID})
	if err == nil {
		if !bytes.Equal(replay.RequestDigest, digest[:]) {
			return nil, ErrPolicyReplay
		}
		result := new(adminv1.AuthorizationState)
		if err := proto.Unmarshal(replay.Response, result); err != nil {
			return nil, errStore
		}
		return result, s.dbErr(tx.Commit(ctx))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, s.dbErr(err)
	}
	if current.Revision != int64(request.GetExpectedRevision()) {
		return nil, ErrPolicyConflict
	}
	definition, err := proto.MarshalOptions{Deterministic: true}.Marshal(policy.definition)
	if err != nil {
		return nil, err
	}
	// PostgreSQL bytea must distinguish an empty protobuf from bootstrap NULL.
	if definition == nil {
		definition = []byte{}
	}
	updated, err := q.SetRuntimeAuthorization(ctx, identitydb.SetRuntimeAuthorizationParams{Digest: policy.digest, Definition: definition, ExpectedRevision: current.Revision})
	if err != nil {
		return nil, s.dbErr(err)
	}
	if err := q.FenceRuntimeAuthorizations(ctx); err != nil {
		return nil, s.dbErr(err)
	}
	if err := q.InvalidateRuntimeObservations(ctx); err != nil {
		return nil, s.dbErr(err)
	}
	revoked, err := q.RevokeRuntimeSessions(ctx)
	if err != nil {
		return nil, s.dbErr(err)
	}
	if err := q.RevokeRuntimeMCPTokens(ctx); err != nil {
		return nil, s.dbErr(err)
	}
	result := runtimeAuthorizationState(policy.definition, updated.Revision, true)
	result.UpdatedAt = timestamppb.New(updated.UpdatedAt.Time)
	response, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		return nil, err
	}
	if err := q.InsertAuthorizationRequest(ctx, identitydb.InsertAuthorizationRequestParams{ActorID: actor.ID, RequestID: requestID, RequestDigest: digest[:], Response: response}); err != nil {
		return nil, s.dbErr(err)
	}
	details, err := json.Marshal(map[string]string{
		"previous_revision": strconv.FormatInt(current.Revision, 10),
		"revision":          strconv.FormatInt(updated.Revision, 10),
		"policy_sha256":     hex.EncodeToString(policy.digest),
		"revoked_sessions":  strconv.FormatInt(revoked, 10),
	})
	if err != nil {
		return nil, err
	}
	if err := q.InsertAuditEvent(ctx, identitydb.InsertAuditEventParams{ID: uuid.New(), ActorID: &actor.ID, Action: auditkind.IdentityAuthorizationUpdated.String(), ResourceID: "authorization", Reason: request.GetReason(), Details: details}); err != nil {
		return nil, s.dbErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, s.dbErr(err)
	}
	return result, nil
}

// reasonPermissionUpgrade is the audit reason for a startup permission rename.
const reasonPermissionUpgrade = "server upgrade replaced retired permission names with their equivalents"

// persistPermissionUpgrade stores a runtime policy whose retired permission names
// were replaced while the caller holds the policy row lock. The replacement
// grants exactly what the retired name granted, so sessions are not revoked;
// the changed digest still makes every principal re-resolve its authority.
// Historical request receipts and audit events keep the names they recorded.
func (s *Service) persistPermissionUpgrade(ctx context.Context, q *identitydb.Queries, previous identitydb.LockRuntimeAuthorizationUpdateRow, policy *authorizationPolicy, changes []permissionupgrade.Change) error {
	definition, err := proto.MarshalOptions{Deterministic: true}.Marshal(policy.definition)
	if err != nil {
		return err
	}
	if definition == nil {
		definition = []byte{}
	}
	updated, err := q.SetRuntimeAuthorization(ctx, identitydb.SetRuntimeAuthorizationParams{Digest: policy.digest, Definition: definition, ExpectedRevision: previous.Revision})
	if err != nil {
		return s.dbErr(err)
	}
	lists := make([]string, len(changes))
	var renamed []string
	for i, change := range changes {
		lists[i] = change.List
		for _, legacy := range change.Legacy {
			current, _ := permissionupgrade.Replacement(legacy)
			if rename := legacy + "=" + strings.Join(current, "+"); !slices.Contains(renamed, rename) {
				renamed = append(renamed, rename)
			}
		}
	}
	// At most 100 roles of 64 characters plus the approval list stay within the
	// 8 KiB audit details bound.
	details, err := json.Marshal(map[string]string{
		"previous_revision":      strconv.FormatInt(previous.Revision, 10),
		"revision":               strconv.FormatInt(updated.Revision, 10),
		"previous_policy_sha256": hex.EncodeToString(previous.Digest),
		"policy_sha256":          hex.EncodeToString(policy.digest),
		"renamed":                strings.Join(renamed, ","),
		"lists":                  strings.Join(lists, ","),
	})
	if err != nil {
		return err
	}
	return s.dbErr(q.InsertAuditEvent(ctx, identitydb.InsertAuditEventParams{ID: uuid.New(), Action: auditkind.IdentityAuthorizationUpgraded.String(), ResourceID: "authorization", Reason: reasonPermissionUpgrade, Details: details}))
}
