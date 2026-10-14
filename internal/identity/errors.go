// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"errors"
	"time"
)

var (
	errInvalidConfig     = errors.New("identity: configuration is invalid")
	errUnavailable       = errors.New("identity: unavailable")
	errUnauthenticated   = errors.New("identity: unauthenticated")
	errNotFound          = errors.New("identity: not found")
	errStore             = errors.New("identity: store operation failed")
	errUnique            = errors.New("identity: unique violation")
	errDirectoryResponse = errors.New("identity: directory response rejected")
	errStaleObservation  = errors.New("identity: stale directory observation")
)

// directoryUnavailable is the error of a directory read that produced no
// answer. Once the caller's context has ended, whatever the transport still
// delivers (a response that raced the cancellation, or a body it cut short)
// answers nobody, so it is never classified as a directory rejection; the
// context's error is kept for callers that tell cancellation apart.
func directoryUnavailable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrDirectoryUnavailable, err)
	}
	return ErrDirectoryUnavailable
}

const (
	connectorKeycloak = "keycloak"
	connectorEntra    = "entra"
	deactivationSCIM  = "scim"

	reasonInitialOwner = "initial owner"
	reasonDisabled     = "authoritative directory reported disabled"
	reasonAbsent       = "authoritative directory user absent"
	reasonReactivated  = "authoritative directory reactivated"
	reasonUnqualified  = "unqualified identity lineage"
	reasonConflict     = "immutable lineage conflict"
	reasonTombstone    = "deactivation tombstone"
	reasonAdminGranted = "administrator membership granted"
	reasonAdminRemoved = "administrator membership removed"
	reasonStale        = "stale directory observation"

	maxOpenAuthFlows      = 10000
	maxDirectoryBody      = 1 << 20
	maxGroupPaths         = 500
	groupPageSize         = 100
	directoryFetchTimeout = 10 * time.Second
)
