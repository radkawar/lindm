// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"net/http"

	authv1 "lindm/gen/lindm/auth/v1"
)

// OpenRestrictedRecoverySession temporarily assigns the owned second human the
// operator role through the actual account API. Caller closes its existing
// approver session first and restores the account after this negative probe.
func (f *AuthorityFixture) OpenRestrictedRecoverySession(ctx context.Context) (_ *OwnerSession, err error) {
	if f.local == nil || f.local.approver == nil {
		return nil, errors.New("restricted recovery probe requires local fixture")
	}
	owner, err := f.openLocalSession(ctx, f.local.owner)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, owner.Close(context.WithoutCancel(ctx))) }()
	if err := owner.localRequest(ctx, "/auth/accounts/update", &authv1.UpdateAccountRequest{AccountId: f.local.approver.id, Enabled: true, Role: "operator"}, nil, http.StatusNoContent); err != nil {
		return nil, err
	}
	session, err := f.newLocalSession(f.local.approver)
	if err != nil {
		return nil, err
	}
	if err := session.localCeremonyRole(ctx, "", "operator"); err != nil {
		session.transport.CloseIdleConnections()
		return nil, err
	}
	return session, nil
}
