package loadlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/escrow"
	"lindm/internal/platform"
	"lindm/internal/rpcreason"
)

// DemoOptions selects optional inputs for the console demo dataset.
type DemoOptions struct {
	// HostObservationFile replays a captured host report on one demo device,
	// with the same semantics as PopulateOptions.HostObservationFile.
	HostObservationFile string
}

// Demo holds no credentials; safe to print/store as evidence.
type Demo struct {
	Devices            []DemoDevice
	Routes             DemoRoutes
	HistoricalDeviceID string
}

// DemoDevice is one seeded device. State is enrolled, pending, stale or
// revoked; a pending enrollment has no host report, hostname or OS yet.
type DemoDevice struct{ ID, Hostname, OS, State string }

// DemoRoutes are seeded IDs for every parameterised console route.
type DemoRoutes struct {
	DeviceID            string // richest enrolled device: encryption, findings, actions, assistance, assignments
	ProfileID           string // for /profiles/$profileId
	SecretID            string // for /secrets/$secretId
	ActionID            string // device action on DeviceID, for /devices/$deviceId/actions/$actionId
	AssistanceSessionID string // on DeviceID, for /devices/$deviceId/assistance/$sessionId
	RecoveryActionID    string // escrow action on DeviceID for /devices/$deviceId/recovery/$actionId
}

// demoSeed drives the real Admin, Enrollment and Device APIs for one fixture.
type demoSeed struct {
	*runner
	devices  []*simulatedDevice
	approver *devlab.ApprovalSession
	origin   *devlab.ConsoleDemo
	demo     Demo
}

// DemoPresence keeps the route device checking in after seeding, so the console
// can request remote assistance and inventory refreshes from it. Stop ends it
// and releases the device.
type DemoPresence struct {
	cancel context.CancelFunc
	done   chan error
}

// demoPresenceInterval keeps the device inside the server's two-minute
// assistance online window.
const demoPresenceInterval = 30 * time.Second

// Stop ends the presence loop and returns its check-in failure, if any.
func (p *DemoPresence) Stop() error {
	p.cancel()
	return <-p.done
}

// SeedDemo builds the deterministic console review dataset on a caller-owned
// dynamic local console fixture: real profile, enrollment, advisory, action,
// assistance, approval, secret and integration state reached only through
// product RPCs and simulated devices. Devices are labelled synthetic. All but
// the route device stop reporting afterwards; that one keeps polling its
// assistance state and action work (real check-ins) and completes requested
// inventory refreshes until the caller stops the returned presence, which it
// must do before closing the fixture. It reconfigures the
// fixture once through ConfigureConsoleDemo, never returns or logs secret
// material, and releases its sessions and other device transports before
// return. The caller must not concurrently close or reconfigure the fixture.
func SeedDemo(ctx context.Context, fixture *devlab.AuthorityFixture, options DemoOptions) (_ Demo, presence *DemoPresence, resultErr error) {
	// Registered first so it runs last: a cleanup failure must not leak the presence loop.
	defer func() {
		if resultErr != nil && presence != nil {
			resultErr = errors.Join(resultErr, presence.Stop())
			presence = nil
		}
	}()
	seedCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var historical *inventoryv1.HostObservation
	if options.HostObservationFile != "" {
		var err error
		if historical, err = readHistoricalHost(options.HostObservationFile); err != nil {
			return Demo{}, nil, err
		}
	}
	devices, err := demoDevices()
	if err != nil {
		return Demo{}, nil, err
	}
	origin, err := fixture.ConfigureConsoleDemo(seedCtx)
	if err != nil {
		return Demo{}, nil, fmt.Errorf("configure console demo: %w", err)
	}
	r := &runner{fixture: fixture, metrics: &measurements{}, historicalHost: historical, demo: devices, options: Options{Packages: 1, EnrollmentWorkers: 4}}
	if err := r.prepare(seedCtx); err != nil {
		return Demo{}, nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, r.owner.Close(cleanup))
	}()
	defer r.enrollmentTransport.CloseIdleConnections()
	enrolled, err := r.enrollBatch(seedCtx, 0, len(devices))
	var present *simulatedDevice
	defer func() {
		for _, device := range enrolled {
			if device != present {
				device.close()
			}
		}
	}()
	if err != nil {
		return Demo{}, nil, fmt.Errorf("enroll demo devices: %w", err)
	}
	// The demo approver reads as what it is: an admin, the least built-in role
	// that can decide every approval kind, not a second owner.
	if err := fixture.UseAdminApprover(seedCtx); err != nil {
		return Demo{}, nil, fmt.Errorf("make demo approver an admin: %w", err)
	}
	approver, err := devlab.OpenApprovalSession(seedCtx, "", fixture)
	if err != nil {
		return Demo{}, nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, approver.Close(cleanup))
	}()
	s := &demoSeed{runner: r, devices: enrolled, approver: approver, origin: origin}
	if err := s.seed(seedCtx, historical); err != nil {
		return Demo{}, nil, err
	}
	present = enrolled[0]
	presenceCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	presence = &DemoPresence{cancel: stop, done: done}
	go func() {
		defer present.close()
		done <- s.checkIns(presenceCtx, present)
	}()
	return s.demo, presence, nil
}

// checkIns polls the device's assistance state, action work and resource
// work, as an idle agent does, until cancelled. Requested sessions stay
// unanswered: no user is present. A requested inventory refresh completes, so
// console flows waiting for fresh storage can finish; any other action is left
// to expire unstarted. Profile items assigned from the console run through the
// simulated executor, so assignments and removals progress as on a live agent.
func (s *demoSeed) checkIns(ctx context.Context, d *simulatedDevice) error {
	ticker := time.NewTicker(demoPresenceInterval)
	defer ticker.Stop()
	for {
		call, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, err := d.client.SyncAssistance(call, connect.NewRequest(&devicev1.SyncAssistanceRequest{SessionEpoch: d.epoch}))
		cancel()
		if err == nil {
			call, cancel = context.WithTimeout(ctx, time.Minute)
			err = s.answerRefresh(call, d)
			if err == nil {
				err = s.drainResourceWork(call, d)
			}
			cancel()
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return fmt.Errorf("demo device check-in: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// demoResourceBatch bounds one check-in's resource work; anything left waits
// for the next tick, as an agent's bounded poll does.
const demoResourceBatch = 32

// drainResourceWork completes assigned and released profile items through the
// simulated executor until the server has no more resource work.
func (s *demoSeed) drainResourceWork(ctx context.Context, d *simulatedDevice) error {
	if err := s.syncTrust(ctx, d); err != nil {
		return err
	}
	for range demoResourceBatch {
		before := d.serviceReports
		if err := s.dispatch(ctx, d); err != nil {
			return err
		}
		if d.serviceReports == before && d.pending == nil {
			return nil
		}
	}
	return nil
}

// answerRefresh completes delivered, unstarted refresh-inventory work and
// leaves every other action untouched.
func (s *demoSeed) answerRefresh(ctx context.Context, d *simulatedDevice) error {
	response, err := d.client.GetDeviceActionWork(ctx, connect.NewRequest(&devicev1.GetDeviceActionWorkRequest{SessionEpoch: d.epoch}))
	if err != nil {
		return err
	}
	work := response.Msg.GetWork()
	if work == nil || len(work.GetStartGrantEnvelope()) > 0 {
		return nil
	}
	// As an agent does, pick up any trust update before verifying the intent.
	if err := s.syncTrust(ctx, d); err != nil {
		return err
	}
	intent, err := s.verifier.VerifyDeviceActionIntent(ctx, d.root, d.delegation, work.GetIntentEnvelope(), time.Now())
	if err != nil {
		return errors.Join(errProtocolViolation, err)
	}
	if intent.GetSpec().GetRefreshInventory() == nil {
		return nil
	}
	_, err = s.completeDeviceAction(ctx, d, work, intent.GetSpec())
	return err
}

func (s *demoSeed) seed(ctx context.Context, historical *inventoryv1.HostObservation) error {
	rich := s.devices[0]
	s.demo.Routes.DeviceID = rich.id
	for _, d := range s.devices {
		if err := s.describe(ctx, d, historical); err != nil {
			return err
		}
	}
	profiles, err := s.publishProfiles(ctx)
	if err != nil {
		return err
	}
	s.demo.Routes.ProfileID = profiles[0].GetProfileId()
	// The kiosk's short verification age starts lapsing while the rest seeds.
	assigned := slices.Clone(s.devices)
	slices.SortStableFunc(assigned, func(a, b *simulatedDevice) int { return b.demo.profile - a.demo.profile })
	for _, d := range assigned {
		if d.demo.profile >= 0 {
			if err := s.converge(ctx, d, profiles[d.demo.profile]); err != nil {
				return fmt.Errorf("converge %s: %w", d.demo.hostname, err)
			}
		}
	}
	if err := s.richDevice(ctx, rich); err != nil {
		return err
	}
	for _, d := range s.devices {
		if d.demo.state == "revoked" {
			if err := s.revoke(ctx, d); err != nil {
				return err
			}
		}
	}
	if err := s.enrollments(ctx, profiles[0]); err != nil {
		return err
	}
	if err := s.catalog(ctx); err != nil {
		return err
	}
	if err := s.scale(ctx); err != nil {
		return err
	}
	if err := s.acceptFinding(ctx, rich); err != nil {
		return err
	}
	for _, d := range s.devices {
		if d.demo.proposal {
			if err := s.proposeAdvisoryAcceptance(ctx, d); err != nil {
				return err
			}
		}
	}
	if err := s.awaitScaleFindings(ctx); err != nil {
		return err
	}
	for _, d := range s.devices {
		if d.demo.state == "stale" {
			if err := s.awaitStale(ctx, d); err != nil {
				return err
			}
		}
	}
	return nil
}

// describe labels the device and records its summary row.
func (s *demoSeed) describe(ctx context.Context, d *simulatedDevice, historical *inventoryv1.HostObservation) error {
	row := DemoDevice{ID: d.id, Hostname: d.demo.hostname, OS: d.demo.release.Name, State: d.demo.state}
	metadata := &adminv1.DeviceMetadata{Labels: append([]string{"synthetic-demo"}, d.demo.labels...), Owner: &adminv1.DeviceMetadata_OwnerText{OwnerText: "Synthetic demo device, not a live host"}}
	if d.demo.historical && historical != nil {
		row.Hostname, row.OS = historical.GetHostname().GetValue(), platform.Identify(platform.OSRelease{ID: historical.GetOsId().GetValue(), VersionID: historical.GetOsVersion().GetValue()}).Name
		metadata.Labels = append(metadata.Labels, "historical-inventory-replay")
		metadata.Owner = &adminv1.DeviceMetadata_OwnerText{OwnerText: "Historical inventory replay, not a live device"}
		s.demo.HistoricalDeviceID = d.id
	}
	s.demo.Devices = append(s.demo.Devices, row)
	_, err := s.owner.Admin.SetDeviceMetadata(ctx, connect.NewRequest(&adminv1.SetDeviceMetadataRequest{RequestId: uuid.NewString(), DeviceId: d.id, Metadata: metadata, Reason: "Label synthetic console demo device"}))
	if err != nil {
		return fmt.Errorf("label demo device: %w", err)
	}
	return nil
}

// demoProfiles are the published catalog: profile 0 is the workstation
// baseline, 1 server hardening and 2 a kiosk whose 30 s verification age
// makes a silent device's compliance stale.
func demoProfiles() []*policyv1.ResourceProfile {
	ownership := func(release resourcev1.ReleaseBehavior) *resourcev1.OwnershipPolicy {
		return &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: release}
	}
	verification := func(age uint32) *resourcev1.VerificationPolicy {
		return &resourcev1.VerificationPolicy{MaxAgeSeconds: age, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}}
	}
	service := func(unit string, age uint32) *policyv1.ProfileResource {
		return &policyv1.ProfileResource{Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: unit}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: unit, Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED}}}, Ownership: ownership(resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN), Verification: verification(age)}
	}
	week := uint32(7 * 24 * 3600)
	profiles := []*policyv1.ResourceProfile{
		{Name: "Workstation baseline", Description: "Printing service and LUKS root encryption compliance for staff laptops.", Resources: []*policyv1.ProfileResource{
			service("cups.service", week),
			{Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE, CanonicalKey: "system/root"}, State: &resourcev1.ResourceDesiredState_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionComplianceDesired{RequireLuksRoot: true}}}, Ownership: ownership(resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED), Verification: verification(week)},
		}},
		{Name: "Server hardening", Description: "Audit daemon and a pre-login legal banner for shared servers.", Resources: []*policyv1.ProfileResource{
			service("auditd.service", week),
			{Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: "/etc/issue.net"}, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: "/etc/issue.net", Presence: resourcev1.Presence_PRESENCE_PRESENT, Content: []byte("Authorized use only. Activity may be monitored.\n"), Mode: proto.Uint32(0o644)}}}, Ownership: ownership(resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED), Verification: verification(week)},
		}},
		{Name: "Lobby kiosk", Description: "Single-application browser session, verified every 30 seconds.", Resources: []*policyv1.ProfileResource{service("kiosk-browser.service", 30)}},
	}
	for _, profile := range profiles {
		ids := make([]string, len(profile.GetResources()))
		for i := range ids {
			ids[i] = uuid.NewString()
		}
		slices.Sort(ids)
		for i, item := range profile.GetResources() {
			item.ResourceId = ids[i]
		}
	}
	return profiles
}

func (s *demoSeed) publishProfiles(ctx context.Context) ([]*adminv1.ProfileRevision, error) {
	var revisions []*adminv1.ProfileRevision
	for _, spec := range demoProfiles() {
		published, err := s.owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Spec: spec, Reason: "Publish console demo profile"}))
		if err != nil {
			return nil, fmt.Errorf("publish demo profile: %w", err)
		}
		revisions = append(revisions, published.Msg.GetRevision())
	}
	return revisions, nil
}

// converge assigns the profile and runs the simulated executor until every
// resource has one admitted terminal report.
func (s *demoSeed) converge(ctx context.Context, d *simulatedDevice, profile *adminv1.ProfileRevision) error {
	reconcile := uint32(86400)
	if d.demo.state == "stale" {
		reconcile = 300
	}
	if _, err := s.owner.Admin.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: d.id, Target: &adminv1.ResourceAssignmentTarget{ProfileId: profile.GetProfileId(), RevisionId: profile.GetRevisionId()}, ReconcileIntervalSeconds: proto.Uint32(reconcile), Reason: "Assign console demo profile"})); err != nil {
		return fmt.Errorf("assign demo profile: %w", err)
	}
	want := d.serviceReports + len(profile.GetSpec().GetResources())
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for d.serviceReports < want {
		if err := s.syncTrust(ctx, d); err != nil {
			return err
		}
		before := d.serviceReports
		if err := s.dispatch(ctx, d); err != nil {
			return err
		}
		if d.serviceReports > before {
			continue
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for demo resource work: %w", ctx.Err())
		case <-ticker.C:
		}
	}
	return nil
}

// richDevice gives the route device its action, escrow and assistance history.
func (s *demoSeed) richDevice(ctx context.Context, d *simulatedDevice) error {
	var err error
	if s.demo.Routes.ActionID, err = s.deviceAction(ctx, d, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}); err != nil {
		return fmt.Errorf("refresh demo inventory: %w", err)
	}
	targets, err := s.owner.Admin.ListDeviceStorageTargets(ctx, connect.NewRequest(&adminv1.ListDeviceStorageTargetsRequest{DeviceId: d.id, ActionKind: "escrow_rotate"}))
	if err != nil {
		return fmt.Errorf("list demo storage targets: %w", err)
	}
	index := slices.IndexFunc(targets.Msg.GetTargets(), func(t *adminv1.DeviceStorageTarget) bool { return t.GetRootBacking() })
	if index < 0 {
		return errors.New("demo device reported no root LUKS target")
	}
	target := targets.Msg.GetTargets()[index].GetTarget()
	custody, err := s.owner.Admin.GetDeviceEncryption(ctx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: d.id}))
	if err != nil {
		return fmt.Errorf("read demo escrow key: %w", err)
	}
	rotate := &agentv1.EscrowRotateAction{Target: target, EscrowKeyId: custody.Msg.GetEscrowKeyId(), EscrowPublicKey: custody.Msg.GetEscrowPublicKey()}
	if s.demo.Routes.RecoveryActionID, err = s.deviceAction(ctx, d, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: rotate}}); err != nil {
		return fmt.Errorf("escrow demo recovery key: %w", err)
	}
	if s.demo.Routes.AssistanceSessionID, err = s.assistance(ctx, d, true); err != nil {
		return fmt.Errorf("complete demo assistance: %w", err)
	}
	if _, err := s.assistance(ctx, d, false); err != nil {
		return fmt.Errorf("decline demo assistance: %w", err)
	}
	if _, err := s.deviceAction(ctx, d, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{AllHumanAccounts: true}}}); err != nil {
		return fmt.Errorf("lock demo sessions: %w", err)
	}
	// The erase stays a pending approval for a second human; no action exists.
	wipe := &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: d.id, EnrollmentGeneration: d.generation, ExpiresAt: timestamppb.New(time.Now().Add(10 * time.Minute)), Reason: "Laptop reported stolen; erase its disk encryption keys",
		Spec: &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_OFFLINE, Target: target}}}}
	if _, err := s.owner.Admin.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: wipe}})); err != nil {
		return fmt.Errorf("request demo wipe approval: %w", err)
	}
	return nil
}

// deviceAction admits spec through the Admin API and completes it with the
// simulated executor protocol: signed challenge, start grant, device result.
func (s *demoSeed) deviceAction(ctx context.Context, d *simulatedDevice, spec *agentv1.DeviceActionSpec) (string, error) {
	// Admission requires contact within the production one-minute fence.
	if _, err := d.client.GetSyncState(ctx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: d.epoch})); err != nil {
		return "", err
	}
	created, err := s.owner.Admin.CreateDeviceAction(ctx, connect.NewRequest(&adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: d.id, EnrollmentGeneration: d.generation, Spec: spec, ExpiresAt: timestamppb.New(time.Now().Add(5 * time.Minute)), Reason: "Console demo device action"}))
	if err != nil {
		return "", err
	}
	id := created.Msg.GetAction().GetActionId()
	work, err := s.actionWork(ctx, d, id)
	if err != nil {
		return "", err
	}
	return s.completeDeviceAction(ctx, d, work, spec)
}

// completeDeviceAction runs the simulated executor protocol for delivered work
// and returns its action ID.
func (s *demoSeed) completeDeviceAction(ctx context.Context, d *simulatedDevice, work *devicev1.DeviceActionWork, spec *agentv1.DeviceActionSpec) (string, error) {
	id := work.GetActionId()
	rotate := spec.GetEscrowRotate()
	p, err := s.prepareDeviceAction(ctx, d, work, func(intent *agentv1.DeviceActionIntent, plan *agentv1.DeviceActionPlan) bool {
		if rotate != nil {
			// A fresh install's passphrase occupies slot 0; rotation adds lindm's slot 1.
			plan.Before.Target, plan.Before.Encrypted, plan.Before.OccupiedKeyslots = rotate.GetTarget(), true, []uint32{0}
			plan.RecoveryBinding = &agentv1.RecoveryKeyBinding{DeviceId: d.id, EnrollmentGeneration: d.generation, ActionId: id, LuksUuid: rotate.GetTarget().GetLuksUuid(), NewKeyslot: 1}
		}
		return proto.Equal(intent.GetSpec(), spec)
	})
	if err != nil {
		return "", err
	}
	started, err := d.client.AuthorizeDeviceActionStart(ctx, connect.NewRequest(&devicev1.AuthorizeDeviceActionStartRequest{SessionEpoch: d.epoch, ActionId: id, ChallengeProof: p.proof}))
	if err != nil {
		return "", err
	}
	now := time.Now()
	if _, err := s.verifier.VerifyDeviceActionStart(ctx, d.root, d.delegation, started.Msg.GetStartGrantEnvelope(), p.intent, p.challenge, now); err != nil {
		return "", err
	}
	digest := sha256.Sum256(work.GetIntentEnvelope())
	verification := &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{ObservedAt: stamp(), Supported: true, BootId: d.boot}}
	status := &agentv1.DeviceActionStatus{ActionId: id, IntentSha256: digest[:], State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE, AcceptedAt: p.plan.GetBefore().GetObservedAt(), StartedAt: timestamppb.New(now), Before: p.plan.GetBefore(), Verification: verification}
	revision := uint64(1)
	switch {
	case spec.GetRefreshInventory() != nil:
		if err := s.inventory(ctx, d, 0); err != nil {
			return "", err
		}
		if _, err := d.client.ConfirmRefreshInventoryPublication(ctx, connect.NewRequest(&devicev1.ConfirmRefreshInventoryPublicationRequest{SessionEpoch: d.epoch, ActionId: id})); err != nil {
			return "", err
		}
		verification.InventorySequence = d.packageSequence
	case spec.GetLockSessions() != nil:
		verification.After.SessionsLocked = true
	case rotate != nil:
		// Custody commits before the executor may report success.
		if verification.Escrow, err = demoEscrow(p.plan.GetRecoveryBinding(), rotate); err != nil {
			return "", err
		}
		verification.Verified, verification.After.Target, verification.After.Encrypted = false, rotate.GetTarget(), true
		verification.After.LindmKeyslots, verification.After.OccupiedKeyslots = []uint32{1}, []uint32{0, 1}
		status.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW
		if err := s.attestDeviceAction(ctx, d, p, status, revision); err != nil {
			return "", err
		}
		stored, err := d.client.ReportDeviceActionResult(ctx, connect.NewRequest(p.report))
		if err != nil {
			return "", err
		}
		if len(stored.Msg.GetEscrowReceiptEnvelope()) == 0 {
			return "", errors.New("server returned no escrow receipt")
		}
		if p.work, err = s.actionWork(ctx, d, id); err != nil {
			return "", err
		}
		verification.Verified, status.State, revision = true, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, 2
	}
	status.CompletedAt = stamp()
	if err := s.attestDeviceAction(ctx, d, p, status, revision); err != nil {
		return "", err
	}
	reported, err := d.client.ReportDeviceActionResult(ctx, connect.NewRequest(p.report))
	if err != nil {
		return "", err
	}
	if !reported.Msg.GetClosed() {
		return "", errors.New("demo device action was not closed")
	}
	return id, nil
}

func (s *demoSeed) actionWork(ctx context.Context, d *simulatedDevice, id string) (*devicev1.DeviceActionWork, error) {
	response, err := d.client.GetDeviceActionWork(ctx, connect.NewRequest(&devicev1.GetDeviceActionWorkRequest{SessionEpoch: d.epoch}))
	if err != nil {
		return nil, err
	}
	if response.Msg.GetWork().GetActionId() != id {
		return nil, errors.New("server did not deliver the admitted demo action")
	}
	return response.Msg.GetWork(), nil
}

// demoEscrow seals a fresh synthetic recovery key to the plan-authenticated
// server key. The plaintext is cleared here and never leaves this function.
func demoEscrow(binding *agentv1.RecoveryKeyBinding, rotate *agentv1.EscrowRotateAction) (*agentv1.DeviceActionEscrow, error) {
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(binding)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	secret := []byte(hex.EncodeToString(raw))
	clear(raw)
	defer clear(secret)
	ciphertext, err := escrow.SealForServer(rotate.GetEscrowPublicKey(), canonical, secret)
	if err != nil {
		return nil, err
	}
	digest, metadata := sha256.Sum256(secret), sha256.Sum256(canonical)
	return &agentv1.DeviceActionEscrow{EscrowKeyId: rotate.GetEscrowKeyId(), Ciphertext: ciphertext, RecoveryKeySha256: digest[:], NewKeyslot: binding.GetNewKeyslot(), LuksUuid: binding.GetLuksUuid(), MetadataSha256: metadata[:]}, nil
}

// assistance requests a view session and answers as the device's local user:
// declined at the prompt, or consented, connected and stopped by the user.
// Offers and answers are synthetic relay-only SDP; no media flows.
func (s *demoSeed) assistance(ctx context.Context, d *simulatedDevice, accept bool) (string, error) {
	if _, err := d.client.GetSyncState(ctx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: d.epoch})); err != nil {
		return "", err
	}
	// The completed session requests control so the review covers the viewer's control button.
	mode := agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW
	if accept {
		mode = agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
	}
	created, err := s.owner.Admin.CreateAssistanceSession(ctx, connect.NewRequest(&adminv1.CreateAssistanceSessionRequest{RequestId: uuid.NewString(), DeviceId: d.id, Mode: mode, MaxDurationSeconds: 900, Reason: "Help the user with a printer queue"}))
	if err != nil {
		return "", err
	}
	id := created.Msg.GetSession().GetId()
	report := &agentv1.AssistanceReport{SessionId: id, LocalSession: &agentv1.AssistanceLocalSession{Username: "demo", Uid: 1000, LogindSessionId: "2", SessionType: "wayland", Desktop: d.demo.release.Desktop.Name}}
	sync := func(phase agentv1.AssistancePhase, cause agentv1.AssistanceEndCause) error {
		report.Phase, report.EndCause = phase, cause
		_, err := d.client.SyncAssistance(ctx, connect.NewRequest(&devicev1.SyncAssistanceRequest{SessionEpoch: d.epoch, Reports: []*agentv1.AssistanceReport{report}}))
		return err
	}
	if err := sync(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED); err != nil {
		return "", err
	}
	if !accept {
		return id, sync(agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED)
	}
	report.ControlGranted = true
	if report.OfferSdp, err = demoSDP(); err != nil {
		return "", err
	}
	if err := sync(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED); err != nil {
		return "", err
	}
	if _, err := s.owner.Admin.JoinAssistanceSession(ctx, connect.NewRequest(&adminv1.JoinAssistanceSessionRequest{SessionId: id})); err != nil {
		return "", err
	}
	answer, err := demoSDP()
	if err != nil {
		return "", err
	}
	if _, err := s.owner.Admin.AnswerAssistanceSession(ctx, connect.NewRequest(&adminv1.AnswerAssistanceSessionRequest{SessionId: id, AnswerSdp: answer})); err != nil {
		return "", err
	}
	if err := sync(agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED); err != nil {
		return "", err
	}
	return id, sync(agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED)
}

// demoSDP is a minimal non-trickle relay-only description with a fresh
// DTLS fingerprint on the demo relay's loopback address.
func demoSDP() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	octets := make([]string, len(raw))
	for i, b := range raw {
		octets[i] = fmt.Sprintf("%02X", b)
	}
	return "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 127.0.0.1\r\na=fingerprint:sha-256 " + strings.Join(octets, ":") + "\r\na=candidate:1 1 udp 16777215 127.0.0.1 50000 typ relay raddr 0.0.0.0 rport 0\r\n", nil
}

// revoke uses the two-person approval revocation always requires.
func (s *demoSeed) revoke(ctx context.Context, d *simulatedDevice) error {
	request := &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: d.id, Reason: "Workstation retired and wiped by IT"}
	approval, err := s.approver.Approve(ctx, s.owner, &adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RevokeDevice{RevokeDevice: request}})
	if err != nil {
		return fmt.Errorf("approve demo revocation: %w", err)
	}
	request.ApprovalId = approval.GetId()
	if _, err := s.owner.Admin.RevokeDevice(ctx, connect.NewRequest(request)); err != nil {
		return fmt.Errorf("revoke demo device: %w", err)
	}
	return nil
}

// enrollments leaves one provisioned device awaiting approval, an automatic
// provisioning token and an unused one-time grant. Secrets are discarded.
func (s *demoSeed) enrollments(ctx context.Context, baseline *adminv1.ProfileRevision) error {
	pending, err := s.owner.Admin.CreateProvisioningToken(ctx, connect.NewRequest(&adminv1.CreateProvisioningTokenRequest{RequestId: uuid.NewString(), LifetimeSeconds: 86400, MaxUses: 1, ApprovalRequired: true, Reason: "Contractor laptop; approve after identity check",
		Metadata: &adminv1.DeviceMetadata{Labels: []string{"synthetic-demo", "contractor"}, Owner: &adminv1.DeviceMetadata_OwnerText{OwnerText: "Synthetic demo laptop awaiting approval"}}}))
	if err != nil {
		return fmt.Errorf("create demo approval token: %w", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(key)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	provisioned, err := s.enrollment.Provision(ctx, connect.NewRequest(&enrollmentv1.ProvisionRequest{ProvisioningToken: pending.Msg.GetSecret(), TransactionId: uuid.NewString(), InstallationId: uuid.NewString(), CsrPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})}))
	pending.Msg.Secret = ""
	if err != nil {
		return fmt.Errorf("provision demo pending device: %w", err)
	}
	if provisioned.Msg.GetState() != "pending_approval" || len(provisioned.Msg.GetCertificatePem()) != 0 {
		return errors.New("approval-required provisioning issued device authority")
	}
	s.demo.Devices = append(s.demo.Devices, DemoDevice{ID: provisioned.Msg.GetDeviceId(), State: "pending"})
	automatic, err := s.owner.Admin.CreateProvisioningToken(ctx, connect.NewRequest(&adminv1.CreateProvisioningTokenRequest{RequestId: uuid.NewString(), LifetimeSeconds: 86400, MaxUses: 25, Reason: "Imaging batch for the spring laptop refresh",
		Metadata: &adminv1.DeviceMetadata{Labels: []string{"synthetic-demo", "laptop-refresh"}}, ProfileRevisionIds: []string{baseline.GetRevisionId()}}))
	if err != nil {
		return fmt.Errorf("create demo automatic token: %w", err)
	}
	automatic.Msg.Secret = ""
	grant, err := s.owner.Admin.CreateEnrollmentGrant(ctx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{RequestId: uuid.NewString(), LifetimeSeconds: 900, Reason: "Replacement laptop for the support desk"}))
	if err != nil {
		return fmt.Errorf("create demo enrollment grant: %w", err)
	}
	grant.Msg.Secret = ""
	return nil
}

// catalog seeds a device group and rollout, a managed secret and the
// integration destination, report schedule and audit export.
func (s *demoSeed) catalog(ctx context.Context) error {
	group := uuid.NewString()
	var members []string
	for _, d := range s.devices {
		if slices.Contains(d.demo.labels, "workstation") && d.demo.state == "enrolled" {
			members = append(members, d.id)
		}
	}
	if _, err := s.owner.Admin.SetDeviceGroup(ctx, connect.NewRequest(&adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: group, Name: "Engineering workstations", DeviceIds: members, Reason: "Group staff workstations for staged rollouts"})); err != nil {
		return fmt.Errorf("create demo device group: %w", err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	ring := func(name string, basis uint32, manual bool) *policyv1.RolloutRing {
		return &policyv1.RolloutRing{Name: name, Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_StaticGroupId{StaticGroupId: group}}, CumulativeBasisPoints: basis, MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 86400, FailureBasisPoints: 500, UnknownBasisPoints: 1000, UnavailableBasisPoints: 1000, ManualPromotion: manual, HealthMaxAgeSeconds: 3600}
	}
	if _, err := s.owner.Admin.PutRollout(ctx, connect.NewRequest(&adminv1.PutRolloutRequest{RequestId: uuid.NewString(), Rollout: &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: salt, Rings: []*policyv1.RolloutRing{ring("pilot", 2500, false), ring("fleet", 10000, true)}}, Reason: "Stage workstation baseline changes"})); err != nil {
		return fmt.Errorf("create demo rollout: %w", err)
	}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		return err
	}
	psk := []byte(hex.EncodeToString(material))
	clear(material)
	secret, err := s.owner.Admin.CreateSecret(ctx, connect.NewRequest(&adminv1.CreateSecretRequest{RequestId: uuid.NewString(), Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_WIFI_PSK, DisplayName: "Office Wi-Fi", Material: &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_WifiPsk{WifiPsk: psk}}, Reason: "Office wireless network credential"}))
	clear(psk)
	if err != nil {
		return fmt.Errorf("create demo secret: %w", err)
	}
	s.demo.Routes.SecretID = secret.Msg.GetSecret().GetSecretId()
	if err := s.officeNetwork(ctx, secret.Msg.GetSecret()); err != nil {
		return err
	}
	signing := make([]byte, 32)
	if _, err := rand.Read(signing); err != nil {
		return err
	}
	_, err = s.owner.Integrations().CreateDestination(ctx, connect.NewRequest(&integrationsv1.CreateDestinationRequest{RequestId: uuid.NewString(), SigningSecret: signing, Reason: "Forward security events to the SOC",
		Config: &integrationsv1.DestinationConfig{DisplayName: "SOC webhook", Kind: integrationsv1.DestinationKind_DESTINATION_KIND_WEBHOOK, Endpoint: s.origin.WebhookURL, PinnedCaPem: s.origin.CAPEM, Enabled: true}}))
	clear(signing)
	if err != nil {
		return fmt.Errorf("create demo webhook: %w", err)
	}
	reports := s.owner.Reports()
	if _, err := reports.UpsertReportSchedule(ctx, connect.NewRequest(&integrationsv1.UpsertReportScheduleRequest{RequestId: uuid.NewString(), Reason: "Weekly compliance report for audit",
		Schedule: &integrationsv1.ReportSchedule{Id: uuid.NewString(), Name: "Weekly compliance", Kind: integrationsv1.ReportKind_REPORT_KIND_COMPLIANCE, Format: integrationsv1.ReportFormat_REPORT_FORMAT_CSV, IntervalSeconds: 7 * 24 * 3600, RetentionDays: 90, Enabled: true}})); err != nil {
		return fmt.Errorf("create demo report schedule: %w", err)
	}
	if _, err := reports.CreateAuditExport(ctx, connect.NewRequest(&integrationsv1.CreateAuditExportRequest{RequestId: uuid.NewString(), AfterHash: make([]byte, 32), MaxEvents: 1000, RetentionDays: 30, Reason: "Quarterly audit evidence export"})); err != nil {
		return fmt.Errorf("create demo audit export: %w", err)
	}
	return nil
}

// acceptFinding waits for the server's own evaluation of the route device
// against the served vendor fixtures, then accepts one finding.
func (s *demoSeed) acceptFinding(ctx context.Context, d *simulatedDevice) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		findings, err := s.owner.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: d.id, PageSize: 50}))
		if err == nil && len(findings.Msg.GetFindings()) > 0 {
			request := &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: d.id, FindingId: findings.Msg.GetFindings()[0].GetId(), ExpiresAt: timestamppb.New(time.Now().Add(30 * 24 * time.Hour)), Reason: "SSH is firewalled to the VPN until the maintenance window"}
			approval, err := s.approver.Approve(ctx, s.owner, &adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}})
			if err != nil {
				return fmt.Errorf("independently approve demo advisory acceptance: %w", err)
			}
			request.ApprovalId = approval.GetId()
			_, err = s.owner.Admin.AcceptAdvisoryFinding(ctx, connect.NewRequest(request))
			// Background evaluation can replace the finding between list and accept;
			// that rejection is definitive, so accept the re-listed finding instead.
			if rpcreason.Get(err) != "advisory_evidence_changed" {
				if err != nil {
					return fmt.Errorf("accept demo finding: %w", err)
				}
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("wait for demo advisory findings: %w", ctx.Err()), err)
		case <-ticker.C:
		}
	}
}

// awaitStale waits until the server itself projects the silent kiosk's
// lapsed verification as stale compliance.
func (s *demoSeed) awaitStale(ctx context.Context, d *simulatedDevice) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		devices, err := s.owner.Admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 200}))
		if err != nil {
			return fmt.Errorf("list demo devices: %w", err)
		}
		if slices.ContainsFunc(devices.Msg.GetDevices(), func(device *adminv1.Device) bool {
			return device.GetId() == d.id && device.GetCompliance() == adminv1.DeviceCompliance_DEVICE_COMPLIANCE_STALE
		}) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for stale demo compliance: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
