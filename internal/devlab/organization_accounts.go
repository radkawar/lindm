package devlab

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	authv1 "lindm/gen/lindm/auth/v1"
)

// ListAccounts reads the existing browser-only account endpoint. OwnerSession is
// a cookie/CSRF session; this adapter never accepts or translates CLI bearers.
func (s *OwnerSession) ListAccounts(ctx context.Context) (*authv1.ListAccountsResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.origin+"/auth/accounts", nil)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, errors.New("account fixture HTTPS request failed")
	}
	encoded, err := readFixtureResponse(response)
	err = errors.Join(err, response.Body.Close())
	defer clear(encoded)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("account fixture list: HTTP %d", response.StatusCode)
	}
	result := new(authv1.ListAccountsResponse)
	if err := protojson.Unmarshal(encoded, result); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateAccount returns the real one-time enrollment secret. Callers must keep
// this response out of logs and ordinary output and store it only with mode 0600.
func (s *OwnerSession) CreateAccount(ctx context.Context, request *authv1.CreateAccountRequest) (*authv1.AccountEnrollment, error) {
	result := new(authv1.AccountEnrollment)
	if err := s.localRequest(ctx, "/auth/accounts/create", request, result, http.StatusOK); err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateAccount uses the normal browser mutation route and its CSRF protection.
func (s *OwnerSession) UpdateAccount(ctx context.Context, request *authv1.UpdateAccountRequest) error {
	return s.localRequest(ctx, "/auth/accounts/update", request, nil, http.StatusNoContent)
}
