package devlab

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// ApprovalSession owns an independently authenticated lab human. Keycloak users
// are randomly named, created with lab-admin authority and deleted at Close.
// Local authority fixtures already own their separate WebAuthn approver account.
// It never grants authority directly or changes shared group/realm configuration.
type ApprovalSession struct {
	session   *OwnerSession
	directory *freshDirectoryFixture
	transport *http.Transport
	account   *fixtureLoginAccount
	closed    bool
}

func OpenApprovalSession(ctx context.Context, repository string, isolated *AuthorityFixture) (_ *ApprovalSession, resultErr error) {
	approval := new(ApprovalSession)
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, approval.Close(ctx))
		}
	}()
	if isolated != nil && isolated.local != nil {
		var err error
		approval.session, err = isolated.OpenApproverSession(ctx)
		return approval, err
	}
	root, err := filepath.Abs(repository)
	if err != nil {
		return nil, err
	}
	dir := FixturePath(root)
	if err := validateAuthorityFixture(dir); err != nil {
		return nil, err
	}
	tlsConfig, err := trustClient(dir)
	if err != nil {
		return nil, err
	}
	secret, err := os.ReadFile(filepath.Join(dir, "lab-admin-secret"))
	if err != nil {
		return nil, errors.New("read protected lab approver credential failed")
	}
	defer clear(secret)
	approval.transport = &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	client := &http.Client{Transport: approval.transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	owned := &freshDirectoryFixture{client: client, secret: strings.TrimSpace(string(secret)), name: "lindm-approver-" + uuid.NewString()}
	approval.directory = owned
	if err := owned.authenticate(ctx); err != nil {
		return nil, err
	}
	owned.userID, err = owned.create(ctx, "users")
	if err != nil {
		return nil, err
	}
	password := rand.Text()
	if _, _, err := owned.request(ctx, http.MethodPut, "/users/"+owned.userID+"/reset-password", map[string]any{"type": "password", "value": password, "temporary": false}, http.StatusNoContent); err != nil {
		return nil, err
	}
	if err := owned.updateUser(ctx, map[string]any{"emailVerified": true, "requiredActions": []string{}}); err != nil {
		return nil, err
	}
	// Membership changes only the newly owned user. pendingGroup remains false,
	// so cleanup cannot delete or otherwise mutate this shared fixture group.
	owned.groupID = "00000000-0000-4000-8000-000000000100"
	if err := owned.membership(ctx, true); err != nil {
		return nil, err
	}
	address := ""
	if isolated != nil {
		address = isolated.AdminAddress
	}
	account := &fixtureLoginAccount{username: owned.name, password: password, subject: owned.userID, role: "admin"}
	approval.session, err = openFixtureSession(ctx, repository, address, account)
	approval.account = account
	if err != nil {
		return nil, err
	}
	approval.session.login = func(ctx context.Context) (*OwnerSession, error) {
		return openFixtureSession(ctx, repository, address, account)
	}
	return approval, nil
}

// Approve creates the exact typed request as requester, then approves it using
// the independent human's normal API session. Callers retain their request UUID
// and returned approval ID for exact mutation retries after response loss.
func (a *ApprovalSession) Approve(ctx context.Context, requester *OwnerSession, request *adminv1.CreateApprovalRequest) (*adminv1.Approval, error) {
	if err := a.distinct(requester); err != nil {
		return nil, err
	}
	created, err := requester.Admin.CreateApproval(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return a.decide(ctx, requester, created.Msg.GetApproval().GetId(), "independent approval for owned laboratory resource cleanup")
}

// ApproveRollouts decides, as the independent human, the approval each rollout
// of the given assignments awaits; requester started them and requested the
// approvals (as `lindmctl apply` does). It returns the approved rollout IDs.
// A rollout awaiting approval without a request fails: the session never
// requests on another human's behalf.
func (a *ApprovalSession) ApproveRollouts(ctx context.Context, requester *OwnerSession, assignmentIDs []string, reason string) ([]string, error) {
	if err := a.distinct(requester); err != nil {
		return nil, err
	}
	var approved []string
	for after := ""; ; {
		request := &adminv1.ListRolloutsRequest{PageSize: 100}
		if after != "" {
			request.AfterId = &after
		}
		listed, err := requester.Admin.ListRollouts(ctx, connect.NewRequest(request))
		if err != nil {
			return approved, fmt.Errorf("list rollouts: %w", err)
		}
		rollouts := listed.Msg.GetRollouts()
		for _, r := range rollouts {
			if r.GetStatus() != adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL || !slices.Contains(assignmentIDs, r.GetAssignment().GetAssignmentId()) {
				continue
			}
			if r.GetApprovalId() == "" {
				return approved, fmt.Errorf("rollout %s awaits an approval request", r.GetRollout().GetRolloutId())
			}
			if _, err := a.decide(ctx, requester, r.GetApprovalId(), reason); err != nil {
				return approved, fmt.Errorf("approve rollout %s: %w", r.GetRollout().GetRolloutId(), err)
			}
			approved = append(approved, r.GetRollout().GetRolloutId())
		}
		if len(rollouts) < 100 {
			return approved, nil
		}
		after = rollouts[len(rollouts)-1].GetRollout().GetRolloutId()
	}
}

func (a *ApprovalSession) distinct(requester *OwnerSession) error {
	if a == nil || a.closed || a.session == nil || requester == nil || requester.AccountID == a.session.AccountID {
		return errors.New("laboratory approval requires two distinct authenticated humans")
	}
	return nil
}

// decide approves one requested approval and checks it binds both humans.
func (a *ApprovalSession) decide(ctx context.Context, requester *OwnerSession, approvalID, reason string) (*adminv1.Approval, error) {
	approved, err := a.session.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: approvalID, Reason: reason}))
	if err != nil {
		return nil, err
	}
	result := approved.Msg.GetApproval()
	if result.GetState() != adminv1.ApprovalState_APPROVAL_STATE_APPROVED || result.GetRequesterId() != requester.AccountID || result.GetApproverId() != a.session.AccountID {
		return nil, errors.New("laboratory approval did not bind both expected humans")
	}
	return result, nil
}

func (a *ApprovalSession) Close(ctx context.Context) error {
	if a == nil || a.closed {
		return nil
	}
	a.closed = true
	var result error
	if a.session != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		result = a.session.Close(cleanup)
		cancel()
	}
	if a.account != nil {
		a.account.password = ""
	}
	if a.directory != nil {
		result = errors.Join(result, a.directory.close(ctx, io.Discard))
		a.directory.secret, a.directory.token = "", ""
	}
	if a.transport != nil {
		a.transport.CloseIdleConnections()
	}
	if result != nil {
		return fmt.Errorf("close laboratory approval session: %w", result)
	}
	return nil
}
