package identity

import (
	"time"

	"github.com/google/uuid"
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
	AuditAction    string
	AuditReason    string
}

// directorySnapshot is the authorization input. ObservedAt is when this
// process successfully read the authoritative directory, not a token timestamp
// and not a broker import read.
type directorySnapshot struct {
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

func decideAccess(now time.Time, configuredIssuer string, adminGroups []string, snap directorySnapshot) accessDecision {
	if !snap.Local && (snap.RefreshFailed || !fresh(now, snap)) {
		return accessDecision{Kind: accessForbidden}
	}
	if !snap.Qualified || snap.Issuer != configuredIssuer || snap.Issuer == "" || snap.Subject == "" {
		return accessDecision{
			Kind:           accessUnauthenticated,
			RevokeSessions: true,
			AuditAction:    auditLineageDenied,
			AuditReason:    reasonUnqualified,
		}
	}
	if snap.Deactivated || !snap.Enabled {
		return accessDecision{
			Kind:           accessUnauthenticated,
			RevokeSessions: true,
			AuditAction:    auditDisabled,
			AuditReason:    reasonDisabled,
		}
	}
	if snap.Local {
		return accessDecision{Kind: accessOK, Role: snap.AuthorizationRole}
	}
	return accessDecision{Kind: accessOK, Role: effectiveRole(snap.PinnedRole, snap.Groups, adminGroups)}
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

func effectiveRole(pinned string, groups, adminGroups []string) string {
	if pinned == RoleOwner {
		return RoleOwner
	}
	if pinned != "" {
		return ""
	}
	have := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		have[g] = struct{}{}
	}
	for _, want := range adminGroups {
		if want == "" {
			continue
		}
		if _, ok := have[want]; ok {
			return RoleAdmin
		}
	}
	return ""
}

func (s *Service) qualifiedLineage(issuer, subject, connector, upstreamProvider, upstreamSubject, brokerIssuer, brokerSubject string) bool {
	return connector == s.connector() &&
		brokerIssuer == "" &&
		brokerSubject == "" &&
		upstreamProvider == issuer &&
		upstreamSubject == subject &&
		issuer != "" &&
		subject != ""
}

func (s *Service) connector() string {
	if s.entraTenant != uuid.Nil {
		return connectorEntra
	}
	return connectorKeycloak
}
