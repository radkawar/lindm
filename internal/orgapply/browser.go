// SPDX-License-Identifier: Apache-2.0

package orgapply

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
)

// PreviewAccounts includes the existing state of each named account in the browser
// review. It grants no account authority and never mutates or issues enrollment.
func (p *ChangePlan) PreviewAccounts(ctx context.Context, client AccountClient) error {
	if len(p.spec.GetAccounts()) == 0 {
		return nil
	}
	accounts, err := client.ListAccounts(ctx)
	if err != nil {
		return err
	}
	p.accountSnapshot = nil
	byName := make(map[string]*authv1.LocalAccount, len(accounts.GetAccounts()))
	for _, account := range accounts.GetAccounts() {
		byName[account.GetUsername()] = account
	}
	for i, operation := range p.operations {
		request, ok := operation.request.(*authv1.CreateAccountRequest)
		if !ok {
			continue
		}
		outcome := operation.outcome
		current := byName[request.GetUsername()]
		if current == nil {
			outcome.Status, outcome.Detail = "created", "Enrollment required; save the shown-once secret."
		} else {
			p.accountSnapshot = append(p.accountSnapshot, proto.CloneOf(current))
			outcome.ID = current.GetId()
			if current.GetEnabled() && proto.Equal(request, &authv1.CreateAccountRequest{Username: current.GetUsername(), Role: current.GetRole(), BreakGlass: current.GetBreakGlass(), Scopes: current.GetScopes()}) {
				outcome.Status, outcome.Detail = "unchanged", ""
			} else {
				outcome.Status, outcome.Detail = "updated", "Enable account and replace its access; existing sessions will end."
			}
		}
		p.Outcomes[i] = outcome
	}
	return nil
}

// Digest binds the reviewed document, observed CAS versions and account state.
// Individual mutations still enforce their own authority and replay boundaries.
func (p *ChangePlan) Digest() ([]byte, error) {
	hash := sha256.New()
	if err := hashMessage(hash, p.spec); err != nil {
		return nil, err
	}
	for _, operation := range p.operations {
		if operation.request != nil {
			if err := hashMessage(hash, operation.request); err != nil {
				return nil, err
			}
		}
	}
	for _, account := range p.accountSnapshot {
		if err := hashMessage(hash, account); err != nil {
			return nil, err
		}
	}
	return hash.Sum(nil), nil
}

func hashMessage(hash hash.Hash, message proto.Message) error {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return err
	}
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(data)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(data)
	return nil
}
