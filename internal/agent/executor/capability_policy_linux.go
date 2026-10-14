// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/capabilitypolicy"
	"lindm/internal/agent/config"
)

// firewallRestoreUnit is the packaged boot-time restore of the last
// committed lindm firewall. FIREWALL is effective only while it is enabled.
const firewallRestoreUnit = "lindm-firewall-restore.service"

var (
	errCapabilityPolicyRejected = errors.New("capability_policy_rejected")
	errCapabilityPolicyRollback = errors.New("capability_policy_rollback")
	errCapabilityPolicyRefused  = errors.New("capability_policy_refused_locally")
)

// providerSnapshot is one immutable effective provider configuration. An
// action opens its provider from the snapshot current at open time and keeps
// that instance; a later policy change installs a new snapshot without
// touching providers already opened.
type providerSnapshot struct {
	config   *agentv1.AgentConfig
	packages *agentv1.NativePackageProviderConfig
	native   NativeResourceProviders
	status   []*agentv1.CapabilityObservation
	host     capabilitypolicy.Host
}

// capabilityRefusal names the capability an intent's provider needs.
type capabilityRefusal struct{ capability agentv1.ManagementCapability }

func (e *capabilityRefusal) Error() string {
	return "capability_not_enabled: " + e.capability.String()
}

// WithCapabilityPolicy installs the root-owned executor.json document whose
// providers are merged with the active signed capability policy. Without it
// the executor uses only the providers given by the other options.
func WithCapabilityPolicy(local *config.Document) Option {
	return func(s *Service) {
		if local != nil {
			s.capabilityLocal = local
		}
	}
}

// WithCapabilityHost replaces host detection used by derivation (tests).
func WithCapabilityHost(detect func(context.Context) (capabilitypolicy.Host, error)) Option {
	return func(s *Service) {
		if detect != nil {
			s.detectHost = detect
		}
	}
}

// WithUnitEnabler replaces the systemd EnableUnitFiles call (tests).
func WithUnitEnabler(enable func(context.Context, string) error) Option {
	return func(s *Service) {
		if enable != nil {
			s.enableUnit = enable
		}
	}
}

func (s *Service) localDocument() *config.Document {
	if s.capabilityLocal == nil {
		s.capabilityLocal = &config.Document{Proto: new(agentv1.AgentConfig), StateDirectory: s.directory}
	}
	return s.capabilityLocal
}

func (s *Service) refuseRemote() bool {
	return s.localDocument().Proto.GetCapabilityPolicy().GetRefuseRemote()
}

func (s *Service) currentProviders() *providerSnapshot {
	if snapshot := s.providers.Load(); snapshot != nil {
		return snapshot
	}
	return &providerSnapshot{config: new(agentv1.AgentConfig)}
}

// installProviders derives and atomically installs the effective providers
// for record (nil or inactive grants nothing remote). When FIREWALL is granted
// but its restore unit is disabled, it enables the unit over systemd D-Bus and
// derives once more; a failed enable leaves FIREWALL UNAVAILABLE.
func (s *Service) installProviders(ctx context.Context, record *agentv1.CapabilityPolicyRecord) error {
	effective, host, err := s.deriveProviders(ctx, record)
	if err != nil {
		return err
	}
	if firewallRestoreDisabled(effective.Status) {
		if err := s.enableUnit(ctx, firewallRestoreUnit); err != nil {
			slog.Warn("enable firewall restore unit failed", "unit", firewallRestoreUnit, "error", err)
		} else if effective, host, err = s.deriveProviders(ctx, record); err != nil {
			return err
		}
	}
	document := effective.Document
	if document == nil {
		return errors.New("capability derivation returned no document")
	}
	merged := document.Proto
	s.providers.Store(&providerSnapshot{
		config: merged, packages: merged.GetPackageProvider(), status: effective.Status, host: host,
		native: NativeResourceProviders{
			Files: merged.GetFileProvider(), Accounts: merged.GetAccountProvider(), Sysctl: merged.GetSysctlProvider(),
			Firewall: merged.GetFirewallProvider(), Password: merged.GetPasswordProvider(), OSUpdate: merged.GetOsUpdateProvider(),
			ProtectedPaths: slices.Clone(document.ProtectedPaths),
		},
	})
	return nil
}

func (s *Service) deriveProviders(ctx context.Context, record *agentv1.CapabilityPolicyRecord) (*capabilitypolicy.Effective, capabilitypolicy.Host, error) {
	host, err := s.detectHost(ctx)
	if err != nil {
		return nil, host, fmt.Errorf("detect capability host: %w", err)
	}
	if record != nil && !record.GetActive() {
		record = nil
	}
	effective, err := capabilitypolicy.Effect(ctx, s.localDocument(), record, host)
	if err != nil {
		return nil, host, fmt.Errorf("derive effective providers: %w", err)
	}
	return effective, host, nil
}

func firewallRestoreDisabled(status []*agentv1.CapabilityObservation) bool {
	for _, observed := range status {
		if observed.GetCapability() == agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL &&
			observed.GetStatus() == agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE &&
			observed.GetDetail() == "firewall_restore_unit_disabled" {
			return true
		}
	}
	return false
}

// requiredCapability is the admission gate: nil when the intent's provider is
// effective in the current snapshot.
func (s *Service) requiredCapability(desired *resourcev1.ResourceDesiredState) error {
	snapshot := s.currentProviders()
	if capability := capabilitypolicy.RequiredCapability(desired, snapshot.config, snapshot.host); capability != agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_UNSPECIFIED {
		return &capabilityRefusal{capability: capability}
	}
	return nil
}

func (s *Service) UpdateCapabilityPolicy(ctx context.Context, req *connect.Request[agentv1.UpdateCapabilityPolicyRequest]) (*connect.Response[agentv1.UpdateCapabilityPolicyResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	observation, err := s.updateCapabilityPolicy(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.UpdateCapabilityPolicyResponse{Observation: observation}), nil
}

func (s *Service) GetCapabilityPolicy(ctx context.Context, req *connect.Request[agentv1.GetCapabilityPolicyRequest]) (*connect.Response[agentv1.GetCapabilityPolicyResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	record, err := capabilitypolicy.LoadRecord(s.directory)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.GetCapabilityPolicyResponse{Observation: s.capabilityObservation(record)}), nil
}

func (s *Service) updateCapabilityPolicy(ctx context.Context, req *agentv1.UpdateCapabilityPolicyRequest) (*agentv1.CapabilityPolicyObservation, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.refuseRemote() {
		return nil, errCapabilityPolicyRefused
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.execution.delegation == nil {
		return nil, errExecutionTrustRejected
	}
	stored, err := capabilitypolicy.LoadRecord(s.directory)
	if err != nil {
		return nil, err
	}
	now := s.now()
	envelope := req.GetPolicyEnvelope()
	policy, err := loaded.execution.verifier.VerifyCapabilityPolicy(ctx, loaded.execution.root, loaded.execution.delegation, envelope, now)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %w", errCapabilityPolicyRejected, err)
	}
	if !boundToEnrollment(policy, loaded) {
		return nil, errCapabilityPolicyRejected
	}
	digest := sha256.Sum256(envelope)
	if stored != nil && boundToEnrollment(stored.GetPolicy(), loaded) {
		previous := stored.GetPolicy().GetVersion()
		storedDigest := sha256.Sum256(stored.GetPolicyEnvelope())
		switch {
		case policy.GetVersion() < previous:
			return nil, errCapabilityPolicyRollback
		case policy.GetVersion() == previous && storedDigest != digest:
			return nil, errCapabilityPolicyRollback
		case policy.GetVersion() == previous && stored.GetActive():
			// Exact retransmission: no rewrite, no new acceptance time.
			return s.capabilityObservation(stored), nil
		}
	}
	record := &agentv1.CapabilityPolicyRecord{
		FormatVersion: 1, PolicyEnvelope: bytes.Clone(envelope), Policy: policy,
		AcceptedAt: protoTimestamp(now), Active: true,
	}
	if err := s.validator.Validate(record); err != nil {
		return nil, errInternal
	}
	// Derive before persisting so an underivable policy never becomes durable.
	if _, _, err := s.deriveProviders(ctx, record); err != nil {
		return nil, err
	}
	if err := capabilitypolicy.StoreRecord(s.directory, record); err != nil {
		return nil, err
	}
	if err := s.installProviders(ctx, record); err != nil {
		return nil, err
	}
	return s.capabilityObservation(record), nil
}

func boundToEnrollment(policy *agentv1.AgentCapabilityPolicy, loaded *bound) bool {
	return policy.GetDeploymentId() == loaded.bootstrap.Root.GetDeploymentId() &&
		policy.GetDeviceId() == loaded.state.GetDeviceId() &&
		policy.GetEnrollmentGeneration() == loaded.state.GetEnrollmentGeneration()
}

// reverifyCapabilityPolicy runs under the authority lock at startup and after
// every accepted execution trust update. A record the current delegation (or
// enrollment) no longer authorizes is rewritten inactive; it grants nothing
// until the server issues a newly signed version. The effective providers are
// reinstalled from the result either way.
func (s *Service) reverifyCapabilityPolicy(ctx context.Context, loaded *bound) error {
	record, err := capabilitypolicy.LoadRecord(s.directory)
	if err != nil {
		return err
	}
	if record != nil && record.GetActive() && !s.capabilityPolicyAuthorized(ctx, loaded, record) {
		if err := ctx.Err(); err != nil {
			return err
		}
		inert := proto.CloneOf(record)
		inert.Active = false
		if err := capabilitypolicy.StoreRecord(s.directory, inert); err != nil {
			return err
		}
		slog.Warn("capability policy no longer authorized; inert", "version", record.GetPolicy().GetVersion())
		record = inert
	}
	return s.installProviders(ctx, record)
}

func (s *Service) capabilityPolicyAuthorized(ctx context.Context, loaded *bound, record *agentv1.CapabilityPolicyRecord) bool {
	if s.refuseRemote() || loaded == nil || loaded.execution.delegation == nil || !boundToEnrollment(record.GetPolicy(), loaded) {
		return false
	}
	// The question is whether the current delegation authorizes the signer,
	// not whether it has since expired: expiry blocks new effects elsewhere.
	at := s.now()
	delegation := loaded.execution.delegation
	if !at.Before(delegation.GetExpiresAt().AsTime()) || at.Before(delegation.GetNotBefore().AsTime()) {
		at = loaded.execution.state.GetAcceptedAt().AsTime()
	}
	policy, err := loaded.execution.verifier.VerifyCapabilityPolicy(ctx, loaded.execution.root, delegation, record.GetPolicyEnvelope(), at)
	return err == nil && proto.Equal(policy, record.GetPolicy())
}

// initializeCapabilityPolicy installs providers at startup. An unenrolled or
// held executor grants only local providers until it can verify the record.
func (s *Service) initializeCapabilityPolicy(ctx context.Context) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return s.installProviders(ctx, nil)
	}
	return s.reverifyCapabilityPolicy(ctx, loaded)
}

func (s *Service) capabilityObservation(record *agentv1.CapabilityPolicyRecord) *agentv1.CapabilityPolicyObservation {
	observation := &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_NONE}
	switch {
	case s.refuseRemote():
		observation.State = agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_REFUSED_LOCALLY
	case record != nil && record.GetActive():
		observation.State = agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE
	case record != nil:
		observation.State = agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_INERT
	}
	if record != nil && !s.refuseRemote() {
		digest := sha256.Sum256(record.GetPolicyEnvelope())
		observation.AppliedVersion = record.GetPolicy().GetVersion()
		observation.AppliedSha256 = digest[:]
		observation.AcceptedAt = proto.CloneOf(record.GetAcceptedAt())
	}
	for _, status := range s.currentProviders().status {
		observation.Capabilities = append(observation.Capabilities, proto.CloneOf(status))
	}
	return observation
}

// refreshCapabilityPolicy re-verifies the record after an accepted execution
// trust update (caller holds the authority lock). Failure fails closed to
// local-only providers: a revoked signer must never keep remote grants.
func (s *Service) refreshCapabilityPolicy(ctx context.Context) {
	loaded, err := s.enrolled(ctx)
	if err == nil {
		err = s.reverifyCapabilityPolicy(ctx, loaded)
	}
	if err == nil {
		return
	}
	slog.Warn("capability policy reverification failed; remote grants withdrawn", "error", err)
	if err := s.installProviders(ctx, nil); err != nil {
		slog.Error("local provider derivation failed; all providers withdrawn", "error", err)
		s.providers.Store(nil)
	}
}
