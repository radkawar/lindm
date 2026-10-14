// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/executionauthority"
)

// firstOwnerExecution admits only a separately quorum-signed update. Identity
// calls this after the first owner's user-verifying ceremony, under its principal
// fence and in the same transaction as credentials, code consumption and session.
// Startup, package hooks and password-only requests never call it.
func firstOwnerExecution(store *executionauthority.Store, request *agentv1.UpdateExecutionTrustRequest) func(context.Context, pgx.Tx, uuid.UUID) error {
	captured := proto.CloneOf(request)
	return func(ctx context.Context, tx pgx.Tx, owner uuid.UUID) error {
		if _, err := store.ApplyInitial(ctx, tx, captured, owner, "First owner admitted the installation execution delegation"); err != nil {
			return fmt.Errorf("admit first-owner execution delegation: %w", err)
		}
		return nil
	}
}
