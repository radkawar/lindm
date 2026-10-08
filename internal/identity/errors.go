package identity

import (
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

const (
	connectorKeycloak = "keycloak"
	deactivationSCIM  = "scim"

	auditOwnerBootstrapped    = "identity.owner_bootstrapped"
	auditLogin                = "identity.login"
	auditLoginDenied          = "identity.login_denied"
	auditLogout               = "identity.logout"
	auditDisabled             = "identity.disabled"
	auditReactivated          = "identity.reactivated"
	auditLineageDenied        = "identity.lineage_denied"
	auditAuthorizationChanged = "identity.authorization_changed"

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
