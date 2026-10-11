package identity

import (
	"context"
	"net/http"

	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "lindm/gen/lindm/auth/v1"
)

func (s *Service) observeLoginDirectory(ctx context.Context, subject string, lineage *brokerLineage) (directoryObservation, error) {
	if s.broker == nil {
		return s.observeDirectory(ctx, subject)
	}
	acquired, err := s.databaseTime(ctx)
	if err != nil {
		return directoryObservation{}, err
	}
	observation, err := s.broker.ObserveLogin(ctx, subject, lineage)
	if err != nil {
		return directoryObservation{}, err
	}
	observation.AcquiredAt = acquired
	return observation, nil
}

// Settings reports configuration and only the requesting principal's observation.
// It is not evidence that every principal in a directory has been refreshed.
func (s *Service) handleIdentitySettings(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	unrestricted, _ := DeviceScopes(principal, PermissionManageAccounts)
	if !ok || !unrestricted {
		writeStatus(w, http.StatusForbidden)
		return
	}
	snapshot, err := s.loadSnapshot(r.Context(), principal.ID)
	if err != nil {
		writeStatus(w, statusFor(err))
		return
	}
	result := &authv1.IdentitySettings{
		PrimarySource: s.connector(), Issuer: s.issuer,
		RefreshIntervalSeconds: uint32(directoryRefreshInterval.Seconds()),
		MaxSnapshotAgeSeconds:  uint32(directoryFreshnessLimit.Seconds()),
		ScimEnabled:            s.scim != nil && len(s.scim.connectors) != 0, BrokerEnabled: s.broker != nil,
		BreakGlassEnabled: s.breakGlass != nil, LocalAuthority: snapshot.Local,
		Current: decideAccess(s.clock(), s.accessIssuer(snapshot), snapshot.policy, snapshot).Kind == accessOK,
	}
	if s.localPrimary {
		result.PrimarySource = "local"
		result.RefreshIntervalSeconds = 0
		result.MaxSnapshotAgeSeconds = 0
	}
	if s.broker != nil {
		result.PrimarySource = "keycloak"
		result.UpstreamSource = s.broker.connector
	}
	if snapshot.Observed {
		result.ObservedAt = timestamppb.New(snapshot.ObservedAt)
	}
	writeProto(w, result)
}
