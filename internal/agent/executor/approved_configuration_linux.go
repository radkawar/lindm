//go:build linux

package executor

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// GetApprovedConfiguration publishes the root-local approvals profiles name by
// identity: approved home roots and approved package sources. It reads only the
// configuration the executor was started with and never changes or widens it.
func (s *Service) GetApprovedConfiguration(ctx context.Context, req *connect.Request[agentv1.GetApprovedConfigurationRequest]) (*connect.Response[agentv1.GetApprovedConfigurationResponse], error) {
	if err := ctx.Err(); err != nil {
		return nil, mapError(err)
	}
	if req == nil || req.Msg == nil {
		return nil, mapError(errInvalid)
	}
	if err := s.admit(req.Msg); err != nil {
		return nil, mapError(err)
	}
	response := &agentv1.GetApprovedConfigurationResponse{Observation: s.approvedConfiguration()}
	if err := s.admit(response); err != nil {
		return nil, mapError(errInternal)
	}
	return noStore(response), nil
}

// approvedConfiguration copies the effective approvals (root-local ones and
// those derived from the accepted capability policy); the package source's
// local signing key file and fingerprints stay private to the executor.
func (s *Service) approvedConfiguration() *agentv1.ApprovedConfigurationObservation {
	observation := &agentv1.ApprovedConfigurationObservation{ObservedAt: timestamppb.New(s.now())}
	providers := s.currentProviders()
	for _, root := range providers.native.Accounts.GetApprovedHomeRoots() {
		observation.HomeRoots = append(observation.HomeRoots, proto.CloneOf(root))
	}
	for _, source := range providers.packages.GetSources() {
		observation.PackageSources = append(observation.PackageSources, proto.CloneOf(source.GetRepository()))
	}
	return observation
}
