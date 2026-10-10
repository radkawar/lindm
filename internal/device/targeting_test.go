package device

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgconn"

	"lindm/internal/identity"
)

func TestTargetingErrorPreservesAuthorizationAndConflict(t *testing.T) {
	for _, err := range []error{identity.ErrAuthorizationDenied, identity.ErrAuthorizationChanged, identity.ErrAuthorizationExpired} {
		if got := connect.CodeOf(targetingError(err)); got != connect.CodePermissionDenied {
			t.Fatalf("authorization error became %v", got)
		}
	}
	conflict := rpcError(connect.CodeFailedPrecondition, "resource_resolution_conflict")
	if !errors.Is(targetingError(conflict), conflict) {
		t.Fatal("domain RPC failure was replaced")
	}
	for _, code := range []string{"40001", "40P01"} {
		if got := connect.CodeOf(targetingError(&pgconn.PgError{Code: code})); got != connect.CodeAborted {
			t.Fatalf("snapshot conflict became %v", got)
		}
	}
}
