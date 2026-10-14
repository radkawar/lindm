// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"time"

	"github.com/google/uuid"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/auditkind"
)

const (
	directoryRefreshInterval = 30 * time.Second
	directoryFreshnessLimit  = 60 * time.Second
	observedFutureSkew       = time.Minute
)

type accessKind int

const (
	accessOK accessKind = iota
	accessUnauthenticated
	accessForbidden
)

type accessDecision struct {
	Kind           accessKind
	Role           string
	RevokeSessions bool
	AuditAction    auditkind.Kind
	AuditReason    string
}

// directorySnapshot is the authorization input. ObservedAt is when this
// process successfully read the authoritative directory, not a token timestamp
// and not a broker import read.
type directorySnapshot struct {
	policy               *authorizationPolicy
	PrincipalID          uuid.UUID
	Issuer               string
	Subject              string
	DisplayName          string
	PinnedRole           string
	Enabled              bool
	Deactivated          bool
	DeactivationSource   string
	Observed             bool
	ObservedAt           time.Time
	Qualified            bool
	Groups               []string
	RefreshFailed        bool
	AuthorizationVersion int64
	AuthorizationRole    string
	Local                bool
	BreakGlass           bool
	Scopes               []*authv1.DeviceScope
	ServiceAccount       bool
}

func needsRefresh(now time.Time, snap directorySnapshot) bool {
	if snap.Local {
		return false
	}
	if snap.RefreshFailed || !snap.Observed || snap.ObservedAt.IsZero() {
		return true
	}
	return now.Sub(snap.ObservedAt) >= directoryRefreshInterval
}

func decideAccess(now time.Time, configuredIssuer string, policy *authorizationPolicy, snap directorySnapshot) accessDecision {
	if !snap.Local && (snap.RefreshFailed || !fresh(now, snap)) {
		return accessDecision{Kind: accessForbidden}
	}
	if !snap.Qualified || snap.Issuer != configuredIssuer || snap.Issuer == "" || snap.Subject == "" {
		return accessDecision{
			Kind:           accessUnauthenticated,
			RevokeSessions: true,
			AuditAction:    auditkind.IdentityLineageDenied,
			AuditReason:    reasonUnqualified,
		}
	}
	if snap.Deactivated || !snap.Enabled {
		return accessDecision{
			Kind:           accessUnauthenticated,
			RevokeSessions: true,
			AuditAction:    auditkind.IdentityDisabled,
			AuditReason:    reasonDisabled,
		}
	}
	return accessDecision{Kind: accessOK, Role: snapshotRole(policy, snap)}
}

// snapshotRole is the role an admitted snapshot's grants resolve to: a local
// account's assigned role when the policy defines it, otherwise the directory
// pin or group bindings. It does not admit the snapshot.
func snapshotRole(policy *authorizationPolicy, snap directorySnapshot) string {
	if snap.Local {
		if policy.role(snap.AuthorizationRole) == nil {
			return ""
		}
		return snap.AuthorizationRole
	}
	return effectiveRole(snap.PinnedRole, snap.Groups, policy)
}

func fresh(now time.Time, snap directorySnapshot) bool {
	if !snap.Observed || snap.ObservedAt.IsZero() {
		return false
	}
	if snap.ObservedAt.After(now.Add(observedFutureSkew)) {
		return false
	}
	return now.Sub(snap.ObservedAt) <= directoryFreshnessLimit
}

func (s *Service) qualifiedLineage(issuer, subject, connector, upstreamProvider, upstreamSubject, brokerIssuer, brokerSubject string) bool {
	if s.broker != nil {
		return issuer == s.issuer && s.broker.qualified(&brokerLineage{
			BrokerIssuer: brokerIssuer, BrokerSubject: brokerSubject, UpstreamProvider: upstreamProvider,
			UpstreamSubject: upstreamSubject, Connector: connector,
		}, subject)
	}
	return connector == s.connector() &&
		brokerIssuer == "" &&
		brokerSubject == "" &&
		upstreamProvider == issuer &&
		upstreamSubject == subject &&
		issuer != "" &&
		subject != ""
}

func (s *Service) connector() string {
	if s.broker != nil {
		return s.broker.connector
	}
	if s.okta != nil {
		return "okta"
	}
	if s.google != nil {
		return "google"
	}
	if s.entraTenant != uuid.Nil {
		return connectorEntra
	}
	return connectorKeycloak
}
