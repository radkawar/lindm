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
	account.password = ""
	if err != nil {
		return nil, err
	}
	return approval, nil
}

// Approve creates the exact typed request as requester, then approves it using
// the independent human's normal API session. Callers retain their request UUID
// and returned approval ID for exact mutation retries after response loss.
func (a *ApprovalSession) Approve(ctx context.Context, requester *OwnerSession, request *adminv1.CreateApprovalRequest) (*adminv1.Approval, error) {
	if a == nil || a.closed || a.session == nil || requester == nil || requester.AccountID == a.session.AccountID {
		return nil, errors.New("laboratory approval requires two distinct authenticated humans")
	}
	created, err := requester.Admin.CreateApproval(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	approved, err := a.session.Admin.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "independent approval for owned laboratory resource cleanup"}))
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
