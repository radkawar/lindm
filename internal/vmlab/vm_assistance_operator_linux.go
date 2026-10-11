//go:build linux

package vmlab

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/devlab"
)

// createAssistanceOperator creates the browser's own account, never the retained
// human owner or lane authority. Named runs retain disabled account audit history,
// so each scenario invocation needs a distinct username as well as account ID.
func createAssistanceOperator(ctx context.Context, fixture *devlab.AuthorityFixture, persistent bool) (string, *authv1.AccountEnrollment, error) {
	username := assistanceOperator
	if persistent {
		username += "-" + strings.ToLower(rand.Text()[:12])
	}
	enrollment, err := fixture.CreateAcceptanceEnrollment(ctx, username)
	if err != nil {
		return "", nil, fmt.Errorf("issue assistance operator enrollment: %w", err)
	}
	return username, enrollment, nil
}

func retireAssistanceOperator(ctx context.Context, fixture *devlab.AuthorityFixture, accountID string) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	return fixture.DisableAcceptanceAccount(cleanup, accountID)
}
