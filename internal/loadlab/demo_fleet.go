// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// fleetState belongs only to the explicitly synthetic fleet-pilot hosts. It is
// mutated after the normal signed start grant is verified, never while previewing
// or preparing. Its observations describe this model, not a native Linux host.
type fleetState map[string]*resourcev1.ResourceDesiredState

func (s *demoDevice) fleetSupports(desired *resourcev1.ResourceDesiredState) bool {
	if !s.fleetPilot {
		return false
	}
	if ssh := desired.GetSshServer(); ssh != nil {
		// This model performs the banner exchange, not account authentication.
		return ssh.BannerText != nil && ssh.Port == nil && ssh.RootLogin == nil &&
			ssh.PasswordAuthentication == nil && ssh.KeyboardInteractiveAuthentication == nil &&
			ssh.PublicKeyAuthentication == nil && ssh.PermitEmptyPasswords == nil &&
			ssh.MaxAuthTries == nil && ssh.ClientAliveIntervalSeconds == nil &&
			ssh.ClientAliveCountMax == nil && ssh.AllowTcpForwarding == nil &&
			ssh.X11Forwarding == nil && ssh.AllowUsers == nil && ssh.AllowGroups == nil && len(ssh.Match) == 0
	}
	if zone := desired.GetFirewallZone(); zone != nil {
		return len(zone.GetRules()) == 0
	}
	return desired.GetNativePackage() != nil || desired.GetOsUpdate() != nil
}

func (s *demoDevice) fleetSource(desired *resourcev1.NativePackageDesired) *agentv1.NativePackageSource {
	if s.agent == nil || s.agent.effective == nil {
		return nil
	}
	repository, apt := strings.CutPrefix(desired.GetRepository().GetCanonicalKey(), "apt/")
	if !apt {
		return nil
	}
	for _, source := range s.agent.effective.Config.GetPackageProvider().GetSources() {
		if source.GetRepository().GetRepositoryId() == repository && source.GetRepository().GetApt() != nil && desired.GetPackage().GetEcosystem() == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
			return source
		}
	}
	return nil
}

func fleetDigest(message proto.Message) ([]byte, error) {
	body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	return digest[:], nil
}

func fleetProbe(observation *resourcev1.ResourceObservation, name string, passed bool) *resourcev1.ProbeReceipt {
	return &resourcev1.ProbeReceipt{ProbeId: uuid.NewSHA1(uuid.NameSpaceOID, []byte("loadlab-synthetic/"+name)).String(), ObservedAt: observation.GetMetadata().GetObservedAt(), Passed: passed, EvidenceSha256: observation.GetMetadata().GetNativeRevision(), Reason: "Synthetic fleet model " + name + "; not native execution evidence"}
}

func (s *demoDevice) fleetObservation(wanted *resourcev1.ResourceDesiredState, metadata *resourcev1.ObservationMetadata) (*resourcev1.ResourceObservation, error) {
	stored := s.fleet[serviceKey(wanted.GetRef())]
	digest, err := fleetDigest(stored)
	if err != nil {
		return nil, err
	}
	observation := &resourcev1.ResourceObservation{Ref: proto.CloneOf(wanted.GetRef()), Metadata: proto.CloneOf(metadata)}
	observation.Metadata.NativeRevision = digest
	observation.Metadata.Backend.NativeVersion = "synthetic"
	observation.Metadata.Backend.ProviderVersion = "loadlab-synthetic-fleet"
	switch {
	case wanted.GetNativePackage() != nil:
		observation.Metadata.Backend.Backend = resourcev1.Backend_BACKEND_APT
		identity := proto.CloneOf(wanted.GetNativePackage().GetPackage())
		if identity.Architecture == "" {
			// These two fixtures are Ubuntu x86-64, whose native architecture is amd64.
			identity.Architecture = "amd64"
		}
		value := &resourcev1.NativePackageObservation{Package: identity, DatabaseRevisionSha256: digest}
		if applied := stored.GetNativePackage(); applied != nil && applied.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
			source := s.fleetSource(applied)
			if source == nil {
				return nil, errors.New("synthetic fleet package source is not approved")
			}
			version := proto.CloneOf(applied.GetExact())
			if version == nil {
				version = &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: "1.0+loadlab.synthetic"}}
			}
			metadataDigest, err := fleetDigest(source.GetRepository())
			if err != nil {
				return nil, err
			}
			value.Installed = true
			value.Record = &resourcev1.NativePackageRecord{Package: identity, Version: version, Source: proto.CloneOf(applied.GetRepository()), SignerSha256: bytes.Clone(source.GetSigningKeySha256()), MetadataRevisionSha256: metadataDigest, ProvenanceKnown: true, NativeIdentitySha256: digest}
		}
		observation.Observed = &resourcev1.ResourceObservation_NativePackage{NativePackage: value}
	case wanted.GetSshServer() != nil:
		observation.Metadata.Backend.Backend = resourcev1.Backend_BACKEND_OPENSSH
		effective := proto.CloneOf(stored.GetSshServer())
		if effective == nil {
			effective = &resourcev1.SSHServerDesired{BannerText: proto.String("Synthetic pilot host. No fleet profile applied.")}
		}
		banner := sha256.Sum256([]byte(effective.GetBannerText()))
		observation.Observed = &resourcev1.ResourceObservation_SshServer{SshServer: &resourcev1.SSHServerObservation{Effective: effective, IncludeGraphSha256: digest, EffectiveConfigurationSha256: digest, ServiceUnit: "ssh.service", ReceivedBannerSha256: banner[:], Syntax: fleetProbe(observation, "SSH syntax", true), Connection: fleetProbe(observation, "SSH banner exchange", true)}}
	case wanted.GetFirewallZone() != nil:
		observation.Metadata.Backend.Backend = resourcev1.Backend_BACKEND_NFTABLES
		zone := wanted.GetFirewallZone()
		value := &resourcev1.FirewallZoneObservation{NativeOwner: "loadlab-synthetic-fleet", NativeVersion: "synthetic", ZoneId: zone.GetZoneId(), Table: "lindm_z_" + strings.ReplaceAll(zone.GetZoneId(), "-", ""), DefaultIngress: zone.GetDefaultIngress(), DefaultEgress: zone.GetDefaultEgress(), PersistentSha256: digest, KernelRulesSha256: digest, NativeIdentitySha256: digest, NetworkNamespaceSha256: digest}
		if applied := stored.GetFirewallZone(); applied != nil {
			value.Exists = applied.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT
			value.PersistentRules = applied.GetRules()
			value.ActiveRules = applied.GetRules()
			value.BoundInterfaces = applied.GetInterfaces()
			value.DefaultIngress, value.DefaultEgress = applied.GetDefaultIngress(), applied.GetDefaultEgress()
			value.PersistentReady = true
		}
		observation.Observed = &resourcev1.ResourceObservation_FirewallZone{FirewallZone: value}
	case wanted.GetOsUpdate() != nil:
		observation.Metadata.Backend.Backend = resourcev1.Backend_BACKEND_APT
		applied := proto.CloneOf(stored.GetOsUpdate())
		observation.Observed = &resourcev1.ResourceObservation_OsUpdate{OsUpdate: &resourcev1.OSUpdateObservation{Backend: resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES, NativeVersion: "loadlab-synthetic", Effective: applied, TimerActive: applied != nil, TimerCalendar: "loadlab-synthetic policy schedule", RebootOracleAvailable: true}}
	default:
		return nil, errors.New("unsupported synthetic fleet resource kind")
	}
	return observation, nil
}

func (s *demoDevice) fleetPlan(intent *agentv1.ResourceExecutionIntent, before *resourcev1.ResourceObservation, intentDigest []byte) (*resourcev1.ResourcePlan, error) {
	desired := intent.GetDesired()
	if desired.GetNativePackage() != nil && s.fleetSource(desired.GetNativePackage()) == nil {
		return nil, errors.New("synthetic fleet package requires an approved APT source")
	}
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		return nil, err
	}
	observationDigest, err := resource.ObservationDigest(before)
	if err != nil {
		return nil, err
	}
	plan := &resourcev1.ResourcePlan{Ref: desired.GetRef(), Operation: intent.GetOperation(), DesiredSha256: desiredDigest[:], ObservationSha256: observationDigest[:], Backend: before.GetMetadata().GetBackend(), Before: before, OwnershipRevisionSha256: intentDigest, Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_NONE, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED}}
	switch {
	case desired.GetNativePackage() != nil:
		body, err := proto.Marshal(desired.GetNativePackage())
		if err != nil {
			return nil, err
		}
		// The model's closed single-package transaction is not a vendor artifact.
		manifest := sha256.Sum256(body)
		plan.Plan = &resourcev1.ResourcePlan_NativePackage{NativePackage: &resourcev1.NativePackagePlan{Desired: desired.GetNativePackage(), TransactionManifest: &resourcev1.ArtifactRef{ArtifactId: uuid.NewString(), Sha256: manifest[:], SizeBytes: uint64(len(body))}, NativeDatabaseRevision: before.GetNativePackage().GetDatabaseRevisionSha256(), NativeLockIdentity: "loadlab-synthetic-fleet", ChangePackages: true}}
	case desired.GetSshServer() != nil:
		plan.Plan = &resourcev1.ResourcePlan_SshServer{SshServer: &resourcev1.SSHServerPlan{Desired: desired.GetSshServer(), ChangedDirectives: []resourcev1.SSHDirective{resourcev1.SSHDirective_SSH_DIRECTIVE_BANNER}, CandidateGraphSha256: desiredDigest[:], Reload: resourcev1.ReloadMechanism_RELOAD_MECHANISM_SYSTEMD_RELOAD, SyntaxValidation: fleetProbe(before, "SSH syntax", true)}}
	case desired.GetFirewallZone() != nil:
		plan.Plan = &resourcev1.ResourcePlan_FirewallZone{FirewallZone: &resourcev1.FirewallZonePlan{Desired: desired.GetFirewallZone(), CompiledRulesetSha256: desiredDigest[:], ExpectedPersistentSha256: before.GetFirewallZone().GetPersistentSha256(), ExpectedKernelSha256: before.GetFirewallZone().GetKernelRulesSha256(), Before: before.GetFirewallZone(), Change: resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE, Generation: uuid.NewString(), TargetPersistentSha256: desiredDigest[:], ConfigurationSha256: desiredDigest[:]}}
	case desired.GetOsUpdate() != nil:
		plan.Plan = &resourcev1.ResourcePlan_OsUpdate{OsUpdate: &resourcev1.OSUpdatePlan{Desired: desired.GetOsUpdate(), Backend: resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES, CandidateSha256: desiredDigest[:], ChangedFiles: []resourcev1.OSUpdateNativeFile{resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER}, TimerCalendar: "loadlab-synthetic policy schedule", TimerChange: true}}
	}
	return plan, nil
}

// applyFleet runs only after VerifyResourceStart in startService. Check results
// come from a fresh read of the retained model, not from a publication or request.
func (s *demoDevice) applyFleet(p *pendingService) error {
	if s.fleet == nil {
		s.fleet = make(fleetState)
	}
	desired := p.intent.GetDesired()
	s.fleet[serviceKey(desired.GetRef())] = proto.CloneOf(desired)
	after, err := s.fleetObservation(desired, p.status.GetBefore().GetMetadata())
	if err != nil {
		return err
	}
	after.Metadata.ObservedAt = stamp()
	digest, err := resource.DesiredDigest(desired)
	if err != nil {
		return err
	}
	verification := &resourcev1.ResourceVerification{Ref: desired.GetRef(), DesiredSha256: digest[:], PlanSha256: p.challenge.GetNativePlanSha256(), After: after, Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED}
	converged := false
	switch {
	case desired.GetNativePackage() != nil:
		value := after.GetNativePackage()
		matches := value.GetInstalled() == (desired.GetNativePackage().GetPresence() == resourcev1.Presence_PRESENCE_PRESENT)
		versionMatches := !value.GetInstalled() || desired.GetNativePackage().GetExact() == nil || proto.Equal(value.GetRecord().GetVersion(), desired.GetNativePackage().GetExact())
		sourceMatches := s.fleetSource(desired.GetNativePackage()) != nil
		converged = matches && versionMatches && sourceMatches
		verification.Checks = &resourcev1.ResourceVerification_NativePackage{NativePackage: &resourcev1.NativePackageChecks{NativeDatabaseMatches: matches, ExactVersionMatches: versionMatches, ApprovedSourceMatches: sourceMatches, NativeConfigurationReadiness: fleetProbe(after, "package configuration", matches), SideEffectsMatchManifest: proto.Equal(s.fleet[serviceKey(desired.GetRef())], desired), Converged: converged}}
	case desired.GetSshServer() != nil:
		matches := proto.Equal(after.GetSshServer().GetEffective(), desired.GetSshServer())
		converged = matches
		verification.Checks = &resourcev1.ResourceVerification_SshServer{SshServer: &resourcev1.SSHServerChecks{Syntax: fleetProbe(after, "SSH syntax", matches), EffectiveSettingsMatch: matches, MatchContextsMatch: matches, Connectivity: fleetProbe(after, "SSH connectivity", matches), BannerExchange: fleetProbe(after, "SSH banner exchange", matches), BannerContentMatch: matches, Converged: matches}}
	case desired.GetFirewallZone() != nil:
		matches := proto.Equal(s.fleet[serviceKey(desired.GetRef())].GetFirewallZone(), desired.GetFirewallZone())
		allow, deny := s.fleetFirewallProbes(s.fleet[serviceKey(desired.GetRef())].GetFirewallZone())
		converged = matches && allow && deny
		verification.Checks = &resourcev1.ResourceVerification_FirewallZone{FirewallZone: &resourcev1.FirewallZoneChecks{PersistentMatches: matches, RuntimeMatches: matches, InterfaceBindingsMatch: matches, AllowPacketProbe: fleetProbe(after, "firewall allow", allow), DenyPacketProbe: fleetProbe(after, "firewall deny", deny), Converged: converged}}
	case desired.GetOsUpdate() != nil:
		matches := proto.Equal(after.GetOsUpdate().GetEffective(), desired.GetOsUpdate())
		converged = matches && after.GetOsUpdate().GetTimerActive() && len(after.GetOsUpdate().GetConflictingUnits()) == 0
		verification.Checks = &resourcev1.ResourceVerification_OsUpdate{OsUpdate: &resourcev1.OSUpdateChecks{PolicyMatches: matches, ScheduleActive: after.GetOsUpdate().GetTimerActive(), NativeConfigurationMatches: matches, NoConflictingScheduler: len(after.GetOsUpdate().GetConflictingUnits()) == 0, Converged: converged}}
	}
	p.status.Verification = verification
	p.status.State, p.status.Failure = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_POSTCONDITION
	if converged {
		p.status.State, p.status.Failure = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE
		verification.Disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	}
	p.status.CompletedAt = after.GetMetadata().GetObservedAt()
	return nil
}

// Evaluate the model's management exemptions and zone ingress for each signed
// fixture target. No packets or peer signatures are claimed: receipts identify
// this synthetic model explicitly.
func (s *demoDevice) fleetFirewallProbes(zone *resourcev1.FirewallZoneDesired) (allow, deny bool) {
	allow, deny = true, true
	for _, target := range s.agent.effective.Config.GetConnectivityGuard().GetProbes() {
		permitted := true
		for _, network := range zone.GetSourceNetworks() {
			prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", network.GetNetworkAddress(), network.GetPrefixLength()))
			address, addressErr := netip.ParseAddr(target.GetSourceAddress())
			if err != nil || addressErr != nil {
				return false, false
			}
			if prefix.Contains(address) {
				permitted = zone.GetDefaultIngress() == resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT
			}
		}
		for _, endpoint := range s.agent.effective.Config.GetFirewallProvider().GetManagementEndpoints() {
			if endpoint.GetAddress() == target.GetAddress() && endpoint.GetPort() == target.GetPort() {
				permitted = true
			}
		}
		if target.GetExpected() == agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW {
			allow = allow && permitted
		} else {
			deny = deny && !permitted
		}
	}
	return allow, deny
}
