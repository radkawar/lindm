// SPDX-License-Identifier: Apache-2.0

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
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/escrow"
	"lindm/internal/orgapply"
	"lindm/internal/platform"
	"lindm/internal/rpcreason"
)

// DemoOptions selects optional inputs for the console demo dataset.
type DemoOptions struct {
	// HostObservationFile replays a captured host report on one demo device,
	// with the same semantics as PopulateOptions.HostObservationFile.
	HostObservationFile string
	// SourceDirectory holds lab/demo/org.json; defaults to the current checkout.
	SourceDirectory string
	// AdvisoryCache retains vendor exports across runs; defaults beneath SourceDirectory/.cache.
	AdvisoryCache string
	// FixtureFeeds serves the small checked-in vendor documents instead of
	// real vendor exports, so the seed finishes in minutes. AdvisoryCache is
	// then unused. Only the Fedora controlled repository is complete, so
	// accepted and proposed findings come from Fedora devices.
	FixtureFeeds bool
	// Progress, when set, receives one line per seed step with elapsed time,
	// so a slow host shows where the time goes. It never receives secrets.
	Progress io.Writer
	// BackgroundPackageFailure returns once the console is usable and finishes
	// the refused package scan state after return, under the presence: the
	// server admits that report only five minutes after the device's enrollment
	// inventory, which would otherwise dominate an interactive seed. Failures
	// go to Progress and to DemoPresence.Stop. Review seeds leave it false so
	// the state exists before any check runs.
	BackgroundPackageFailure bool
}

// demoProgress names the current seed step for progress lines and errors.
type demoProgress struct {
	out   io.Writer
	start time.Time
	mu    sync.Mutex
	step  string
}

func (p *demoProgress) begin(step string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.step = step
	if p.out != nil {
		// Progress is advisory; a closed terminal must not fail the seed.
		_, _ = fmt.Fprintf(p.out, "demo seed +%s: %s\n", time.Since(p.start).Round(time.Second), step)
	}
}

func (p *demoProgress) wrap(err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Errorf("demo seed step %q failed after %s: %w", p.step, time.Since(p.start).Round(time.Second), err)
}

// Demo holds no credentials; safe to print/store as evidence.
type Demo struct {
	Devices            []DemoDevice
	Routes             DemoRoutes
	HistoricalDeviceID string
	Organization       []orgapply.Outcome
}

// DemoDevice is one seeded device. State is enrolled, pending (a provisioning
// enrollment awaiting approval), awaiting-inventory (enrolled, no host report
// yet), stale or revoked; pending and awaiting-inventory have no hostname or OS.
type DemoDevice struct{ ID, Hostname, OS, State string }

// DemoRoutes are seeded IDs for every parameterised console route.
type DemoRoutes struct {
	DeviceID            string // richest enrolled device: encryption, findings, actions, assistance, assignments
	ProfileID           string // for /profiles/$profileId
	FirewallProfileID   string // unassigned profile with a firewall zone, for zone naming
	SecretID            string // for /secrets/$secretId
	ActionID            string // device action on DeviceID, for /devices/$deviceId/actions/$actionId
	AssistanceSessionID string // on DeviceID, for /devices/$deviceId/assistance/$sessionId
	RecoveryActionID    string // escrow action on DeviceID for /devices/$deviceId/recovery/$actionId
	// FactsPendingDeviceID has not reported its platform, so its profile's
	// platform-limited item waits for device facts (/devices/$deviceId).
	FactsPendingDeviceID string
	// Headless server whose agent reports remote assistance turned off; the
	// console must offer it no assistance request.
	AssistanceOffDeviceID string
	// A request an older agent refused before anything was shared, on
	// RefusedAssistanceDeviceID: "Couldn't start", never "Ended".
	RefusedAssistanceDeviceID, RefusedAssistanceSessionID string
	// Active staged rollout with an in-progress pilot, for /rollouts.
	RolloutID string
}

// demoSeed drives the real Admin, Enrollment and Device APIs for one fixture.
type demoSeed struct {
	*runner
	devices      []*simulatedDevice
	approver     *devlab.ApprovalSession
	origin       *devlab.ConsoleDemo
	demo         Demo
	organization *orgv1.Organization
	fixtureFeeds bool
	progress     *demoProgress
	// backgroundPackageFailure: see DemoOptions.BackgroundPackageFailure.
	backgroundPackageFailure bool
}

// DemoPresence keeps the route device and the isolated fleet pilot checking in
// after seeding, and finishes any background seed step. Stop ends these workers
// and releases their devices.
type DemoPresence struct {
	cancel  context.CancelFunc
	done    chan error
	workers int
}

// demoPresenceInterval keeps the device inside the server's two-minute
// assistance online window.
const demoPresenceInterval = 30 * time.Second

// Stop ends the presence loop and returns its check-in failure, if any.
func (p *DemoPresence) Stop() error {
	p.cancel()
	var err error
	for range p.workers {
		err = errors.Join(err, <-p.done)
	}
	return err
}

// SeedDemo applies the maintained organization and adds synthetic review history
// on a caller-owned dynamic local fixture. Organization and device mutations use
// product APIs; advisory publications come from current real vendor exports.
// Devices are labelled synthetic. The route device and isolated fleet-pilot hosts
// keep polling action and resource work through real check-ins until the caller
// stops the returned presence, which it must do before closing the fixture.
// Other devices stop reporting after population. It configures the fixture's demo
// feeds, relay and organization authorization, never returns or logs secret
// material, and releases its sessions and other device transports before return.
// The caller must not concurrently close or reconfigure the fixture.
func SeedDemo(ctx context.Context, fixture *devlab.AuthorityFixture, options DemoOptions) (_ Demo, presence *DemoPresence, resultErr error) {
	// Registered first so it runs last: a cleanup failure must not leak the presence loop.
	defer func() {
		if resultErr != nil && presence != nil {
			resultErr = errors.Join(resultErr, presence.Stop())
			presence = nil
		}
	}()
	progress := &demoProgress{out: options.Progress, start: time.Now()}
	// Every failure, including a step's deadline, names the step that overran.
	defer func() {
		if resultErr != nil {
			resultErr = progress.wrap(resultErr)
		}
	}()
	if options.SourceDirectory == "" {
		options.SourceDirectory = "."
	}
	if options.AdvisoryCache == "" {
		options.AdvisoryCache = filepath.Join(options.SourceDirectory, ".cache", "lab", "advisories")
	}
	body, err := os.ReadFile(filepath.Join(options.SourceDirectory, "lab", "demo", "org.json"))
	if err != nil {
		return Demo{}, nil, fmt.Errorf("read demo organization: %w", err)
	}
	organization, err := orgapply.Decode(body)
	if err != nil {
		return Demo{}, nil, err
	}
	if len(organization.GetProfiles()) == 0 {
		return Demo{}, nil, errors.New("console demo organization requires a profile route")
	}
	var historical *inventoryv1.HostObservation
	if options.HostObservationFile != "" {
		var err error
		if historical, err = readHistoricalHost(options.HostObservationFile); err != nil {
			return Demo{}, nil, err
		}
	}
	devices, err := demoDevices(options.SourceDirectory)
	if err != nil {
		return Demo{}, nil, err
	}
	var feeds *configv1.AdvisoryConfig
	if !options.FixtureFeeds {
		feeds = &configv1.AdvisoryConfig{RefreshEnabled: true}
		seen := make(map[string]bool)
		for _, device := range devices {
			if device.authoredCritical {
				continue
			}
			if seen[device.release.Key] {
				continue
			}
			cfg, err := devlab.HeldAdvisories(*device.release, "amd64")
			if err != nil {
				return Demo{}, nil, err
			}
			feeds.Feeds = append(feeds.Feeds, cfg.GetFeeds()...)
			seen[device.release.Key] = true
		}
	}
	// Feed configuration has its own bound: real exports may need the first
	// vendor download, fixtures are local. The device seed after it has its own
	// twenty minutes (enrollment, scale writes and evaluation waits). Nil feeds
	// select the checked-in fixtures.
	configureWait := 15 * time.Minute
	if !options.FixtureFeeds {
		configureWait = 2*time.Hour + 30*time.Minute
	}
	configureCtx, cancelConfigure := context.WithTimeout(ctx, configureWait)
	defer cancelConfigure()
	progress.begin("configure advisory feeds, relay and webhook")
	origin, err := fixture.ConfigureConsoleDemo(configureCtx, feeds, options.SourceDirectory, options.AdvisoryCache)
	if err != nil {
		return Demo{}, nil, fmt.Errorf("configure console demo: %w", err)
	}
	progress.begin("configure organization authorization")
	if err := fixture.ConfigureAuthorization(configureCtx, organization.GetAuthorization()); err != nil {
		return Demo{}, nil, err
	}
	seedCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	progress.begin("open owner session")
	r := &runner{fixture: fixture, metrics: &measurements{}, historicalHost: historical, demo: devices, options: Options{Packages: 1, EnrollmentWorkers: 4}}
	if err := r.prepare(seedCtx); err != nil {
		return Demo{}, nil, err
	}
	// An interactive seed hands the owner session to its background step.
	ownerHandedOff := false
	defer func() {
		if ownerHandedOff {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, r.owner.Close(cleanup))
	}()
	defer r.enrollmentTransport.CloseIdleConnections()
	s := &demoSeed{runner: r, origin: origin, organization: organization, fixtureFeeds: options.FixtureFeeds, backgroundPackageFailure: options.BackgroundPackageFailure, progress: progress}
	progress.begin("apply enrollment organization")
	// Provision enrollment prerequisites through the same organization engine.
	// Rollouts freeze a real cohort at creation and cannot precede enrollment;
	// their assignments are applied with the full spec after inventory arrives.
	enrollment := proto.CloneOf(organization)
	enrollment.Rollouts, enrollment.Assignments = nil, nil
	applied, err := s.applyOrganization(seedCtx, enrollment)
	if err != nil {
		return Demo{}, nil, err
	}
	defer clear(applied.Secrets)
	for _, device := range devices {
		for _, token := range organization.GetProvisioningTokens() {
			if token.GetName() == device.department {
				device.labels = append(device.labels, token.GetRequest().GetMetadata().GetLabels()...)
			}
		}
		for _, secret := range applied.Secrets {
			if secret.Kind == "provisioning_token" && secret.Name == device.department {
				device.provisioningToken = secret.Value
			}
		}
	}
	defer func() {
		for _, device := range devices {
			device.provisioningToken = ""
		}
	}()
	progress.begin("enroll demo devices")
	enrolled, err := r.enrollBatch(seedCtx, 0, len(devices))
	var present []*simulatedDevice
	var background []*simulatedDevice
	defer func() {
		for _, device := range enrolled {
			if !slices.Contains(present, device) && !slices.Contains(background, device) {
				device.close()
			}
		}
	}()
	if err != nil {
		return Demo{}, nil, fmt.Errorf("enroll demo devices: %w", err)
	}
	// The demo approver reads as what it is: an admin, the least built-in role
	// that can decide every approval kind, not a second owner.
	progress.begin("open approver session")
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
	s.devices, s.approver = enrolled, approver
	if err := s.seed(seedCtx, historical); err != nil {
		return Demo{}, nil, err
	}
	progress.begin("ready")
	present = append(present, enrolled[0])
	for _, device := range enrolled[1:] {
		if device.demo.fleetPilot {
			present = append(present, device)
		}
	}
	presenceCtx, stop := context.WithCancel(ctx)
	done := make(chan error, len(present)+1)
	presence = &DemoPresence{cancel: stop, done: done, workers: len(present)}
	for _, device := range present {
		go func() {
			defer device.close()
			done <- s.checkIns(presenceCtx, device)
		}()
	}
	if s.backgroundPackageFailure {
		background = slices.DeleteFunc(slices.Clone(enrolled), func(d *simulatedDevice) bool { return !d.demo.packageScanDenied })
		ownerHandedOff = true
		presence.workers++
		go func() { done <- s.packageFailureInBackground(presenceCtx, background) }()
	}
	return s.demo, presence, nil
}

// applyOrganization keeps all organization mutations in the product engine.
// Account operations use the fixture owner's existing cookie/CSRF session.
// Live demo check-ins can change a device's targeting revision between preview
// and activation; that definitive targeting_revision_conflict rejection is
// re-planned against current state. An attempt that issued credentials is never
// retried, because a re-plan could not show them again.
func (s *demoSeed) applyOrganization(ctx context.Context, organization *orgv1.Organization) (*orgapply.Result, error) {
	const attempts = 5
	for attempt := 1; ; attempt++ {
		plan, err := orgapply.Plan(ctx, s.owner.Admin, organization)
		if err != nil {
			return nil, err
		}
		result, err := orgapply.Apply(ctx, s.owner.Admin, plan, orgapply.Options{AccountClient: s.owner})
		if err == nil {
			return result, nil
		}
		issued := result != nil && len(result.Secrets) > 0
		if result != nil {
			clear(result.Secrets)
		}
		if issued || attempt == attempts || rpcreason.Get(err) != "targeting_revision_conflict" {
			return nil, err
		}
	}
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
		_, err := d.syncAssistance(call)
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
		if d.demo.factsWithheld {
			s.demo.Routes.FactsPendingDeviceID = d.id
		}
	}
	s.progress.begin("label devices and report assistance")
	for _, d := range s.devices {
		if err := s.describe(ctx, d, historical); err != nil {
			return err
		}
		// The idle check-in every agent makes, reporting its assistance setting.
		if d.demo.assistance != agentv1.AssistanceEnablement_ASSISTANCE_ENABLEMENT_UNSPECIFIED {
			if _, err := d.syncAssistance(ctx); err != nil {
				return fmt.Errorf("report %s assistance policy: %w", d.demo.hostname, err)
			}
		}
		if d.demo.headless && d.demo.assistance == assistanceOff && s.demo.Routes.AssistanceOffDeviceID == "" {
			s.demo.Routes.AssistanceOffDeviceID = d.id
		}
	}
	// Re-plan after enrollment/metadata so targeting activates actual members
	// and exceptions resolve actual inventory. This is not an idempotency probe;
	// the integration test reapplies the finished organization independently.
	s.progress.begin("roll out organization")
	if err := s.rollOutOrganization(ctx); err != nil {
		return err
	}
	// Organization assignments roll out asynchronously through the promoter.
	s.progress.begin("await organization rollouts")
	if err := s.awaitRollouts(ctx); err != nil {
		return err
	}
	s.demo.Routes.ProfileID = s.organization.GetProfiles()[0].GetId()
	var err error
	if s.demo.Routes.FirewallProfileID, err = s.publishFirewallReviewProfile(ctx); err != nil {
		return err
	}
	s.progress.begin("converge profiles")
	for _, d := range s.devices {
		switch {
		case d.demo.state == "stale":
			if err := s.seedStaleProfile(ctx, d); err != nil {
				return err
			}
		case d.demo.factsWithheld:
			if err := s.assignFactsPending(ctx, d); err != nil {
				return err
			}
		default:
			if err := s.converge(ctx, d); err != nil {
				return fmt.Errorf("converge %s: %w", d.demo.hostname, err)
			}
		}
	}
	s.progress.begin("route device actions and assistance")
	if err := s.richDevice(ctx, rich); err != nil {
		return err
	}
	for _, d := range s.devices {
		if d.demo.assistance == agentv1.AssistanceEnablement_ASSISTANCE_ENABLEMENT_UNSPECIFIED && !d.demo.historical && s.demo.Routes.RefusedAssistanceSessionID == "" {
			if s.demo.Routes.RefusedAssistanceSessionID, err = s.refusedAssistance(ctx, d); err != nil {
				return fmt.Errorf("refused demo assistance: %w", err)
			}
			s.demo.Routes.RefusedAssistanceDeviceID = d.id
		}
	}
	for _, d := range s.devices {
		if d.demo.state == "revoked" {
			if err := s.revoke(ctx, d); err != nil {
				return err
			}
		}
	}
	s.progress.begin("enrollments, catalog and adoption rollout")
	if err := s.enrollments(ctx); err != nil {
		return err
	}
	if err := s.catalog(ctx); err != nil {
		return err
	}
	if err := s.adoptionRollout(ctx); err != nil {
		return err
	}
	s.progress.begin("scale fixtures")
	if err := s.scale(ctx); err != nil {
		return err
	}
	// Real exports report AFFECTED on the Ubuntu route device. Fixture feeds are
	// complete only for the Fedora controlled repository, whose sudo node
	// affects the Fedora baseline, so Fedora devices carry both exceptions.
	accepted := rich
	proposed := slices.DeleteFunc(slices.Clone(s.devices), func(d *simulatedDevice) bool { return !d.demo.proposal })
	if s.fixtureFeeds {
		accepted, proposed = nil, nil
		for _, d := range s.devices {
			switch d.demo.hostname {
			case "fedora-ws-03":
				accepted = d
			case demoScaleHostname:
				proposed = append(proposed, d)
			}
		}
		if accepted == nil || len(proposed) == 0 {
			return errors.New("fixture feeds require the Fedora demo devices")
		}
	}
	s.progress.begin("accept and propose advisory findings")
	if err := s.acceptFinding(ctx, accepted); err != nil {
		return err
	}
	for _, d := range proposed {
		if err := s.proposeAdvisoryAcceptance(ctx, d); err != nil {
			return err
		}
	}
	s.progress.begin("await scale and authored Critical findings")
	for _, d := range s.devices {
		if d.demo.hostname == demoScaleHostname || d.demo.authoredCritical {
			if err := s.awaitAffectedFindings(ctx, d); err != nil {
				return err
			}
		}
	}
	if !s.backgroundPackageFailure {
		s.progress.begin("refused package scan")
		for _, d := range s.devices {
			if d.demo.packageScanDenied {
				if err := s.denyPackageScan(ctx, d); err != nil {
					return err
				}
			}
		}
	}
	s.progress.begin("await stale kiosk")
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
	if d.demo.factsWithheld {
		row.Hostname, row.OS = "", ""
	}
	metadata := &adminv1.DeviceMetadata{Labels: append([]string{"synthetic-demo"}, d.demo.labels...), Owner: &adminv1.DeviceMetadata_OwnerText{OwnerText: "Synthetic demo device, not a real device"}}
	if d.demo.state == "stale" {
		// Preserve token-created static RBAC membership, but keep this explicit
		// history-only device outside department policy targeting.
		metadata.Labels = slices.DeleteFunc(metadata.Labels, func(label string) bool {
			return label == "department/"+d.demo.department
		})
		metadata.Labels = append(metadata.Labels, "synthetic-history-only")
	}
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

// assignFactsPending gives a device that has never reported inventory the
// organization profile with platform-limited rows. Organization targeting
// activates only active devices, so this one synthetic assignment is direct;
// those rows then wait for the device's facts while unrestricted rows apply.
// The profile adopts native state, so the independent approver approves the
// exact assignment first, as for any direct adoption.
func (s *demoSeed) assignFactsPending(ctx context.Context, d *simulatedDevice) error {
	index := slices.IndexFunc(s.organization.GetProfiles(), func(profile *orgv1.Profile) bool {
		return slices.ContainsFunc(profile.GetSpec().GetResources(), func(item *policyv1.ProfileResource) bool { return item.GetApplicability() != nil })
	})
	if index < 0 {
		return errors.New("organization declares no platform-limited profile row")
	}
	head, err := s.owner.Admin.GetProfileRevision(ctx, connect.NewRequest(&adminv1.GetProfileRevisionRequest{ProfileId: s.organization.GetProfiles()[index].GetId()}))
	if err != nil {
		return fmt.Errorf("read platform-limited organization profile: %w", err)
	}
	profile := head.Msg.GetRevision()
	request := &adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: d.id, Target: &adminv1.ResourceAssignmentTarget{ProfileId: profile.GetProfileId(), RevisionId: profile.GetRevisionId()}, ReconcileIntervalSeconds: proto.Uint32(86400), Reason: "Seed a device awaiting its first inventory"}
	if slices.ContainsFunc(profile.GetSpec().GetResources(), func(item *policyv1.ProfileResource) bool {
		return item.GetOwnership().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	}) {
		approval, err := s.approver.Approve(ctx, s.owner, &adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_SetResourceAssignment{SetResourceAssignment: request}})
		if err != nil {
			return fmt.Errorf("independently approve %s adoption assignment: %w", d.demo.hostname, err)
		}
		request.ApprovalId = approval.GetId()
	}
	if _, err := s.owner.Admin.SetResourceAssignment(ctx, connect.NewRequest(request)); err != nil {
		return fmt.Errorf("assign %s: %w", d.demo.hostname, err)
	}
	return s.converge(ctx, d)
}

// seedStaleProfile is a synthetic-only observation history, not an organization
// baseline. Its short verification lifetime makes the stale UI state observable
// without waiting an hour or forging collection timestamps.
func (s *demoSeed) seedStaleProfile(ctx context.Context, d *simulatedDevice) error {
	spec := &policyv1.ResourceProfile{Name: "Synthetic kiosk observation", Description: "Synthetic review history, not an organization policy.", Resources: []*policyv1.ProfileResource{{
		ResourceId:   uuid.NewString(),
		Desired:      &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "kiosk-browser.service"}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: "kiosk-browser.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED}}},
		Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN},
		Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 30, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
	}}}
	published, err := s.owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Spec: spec, Reason: "Seed synthetic stale observation history"}))
	if err != nil {
		return err
	}
	profile := published.Msg.GetRevision()
	if _, err := s.owner.Admin.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: d.id, Target: &adminv1.ResourceAssignmentTarget{ProfileId: profile.GetProfileId(), RevisionId: profile.GetRevisionId()}, ReconcileIntervalSeconds: proto.Uint32(300), Reason: "Seed synthetic stale observation history"})); err != nil {
		return err
	}
	return s.converge(ctx, d)
}

// publishFirewallReviewProfile publishes a synthetic-only, never-assigned guest
// Wi-Fi firewall zone so console review sees an unnamed zone identified by its
// binding rather than its UUID. It is not part of the organization policy.
func (s *demoSeed) publishFirewallReviewProfile(ctx context.Context) (string, error) {
	zone := uuid.NewString()
	spec := &policyv1.ResourceProfile{Name: "Guest Wi-Fi firewall", Description: "Discards incoming traffic from the guest network.", Resources: []*policyv1.ProfileResource{{
		ResourceId: uuid.NewString(),
		Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, CanonicalKey: zone}, State: &resourcev1.ResourceDesiredState_FirewallZone{FirewallZone: &resourcev1.FirewallZoneDesired{
			ZoneId: zone, Presence: resourcev1.Presence_PRESENCE_PRESENT, Interfaces: []*resourcev1.InterfaceSelector{{Identity: &resourcev1.InterfaceSelector_PermanentMac{PermanentMac: "02:00:00:00:50:01"}, Ifname: proto.String("wlan0")}},
			SourceNetworks: []*resourcev1.CIDR{{NetworkAddress: "192.168.50.0", PrefixLength: 24}}, DefaultIngress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_DROP, DefaultEgress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT,
		}}},
		Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED},
		Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 7 * 24 * 3600, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
	}}}
	published, err := s.owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Spec: spec, Reason: "Publish synthetic firewall zone review profile"}))
	if err != nil {
		return "", fmt.Errorf("publish firewall review profile: %w", err)
	}
	return published.Msg.GetRevision().GetProfileId(), nil
}

// converge reports actual simulator outcomes for the product's effective
// assignment. Unsupported resource kinds remain refused, never compliant.
func (s *demoSeed) converge(ctx context.Context, d *simulatedDevice) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		state, err := s.owner.Admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: d.id}))
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(state.Msg.GetResources(), func(r *adminv1.ResourceState) bool {
			return r.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_PENDING || r.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_IN_PROGRESS
		}) {
			return nil
		}
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
	lockID, err := s.deviceAction(ctx, d, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{AllHumanAccounts: true}}})
	if err != nil {
		return fmt.Errorf("lock demo sessions: %w", err)
	}
	// An undo the device never picks up: it expires unstarted, leaving the
	// accounts locked, as when a device goes quiet after an undo is sent.
	if _, err := d.client.GetSyncState(ctx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: d.epoch})); err != nil {
		return fmt.Errorf("refresh demo contact: %w", err)
	}
	if _, err := s.owner.Admin.CreateDeviceAction(ctx, connect.NewRequest(&adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: d.id, EnrollmentGeneration: d.generation, Spec: &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: lockID}}}, ExpiresAt: timestamppb.New(time.Now().Add(5 * time.Second)), Reason: "Console demo undo that expires unstarted"})); err != nil {
		return fmt.Errorf("send demo undo: %w", err)
	}
	// The wipe stays a pending approval for a second human; no action exists.
	wipe := &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: d.id, EnrollmentGeneration: d.generation, ExpiresAt: timestamppb.New(time.Now().Add(10 * time.Minute)), Reason: "Someone reported this laptop stolen. Wipe its disk encryption keys.",
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
	request := &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: d.id, EnrollmentGeneration: d.generation, Spec: spec, ExpiresAt: timestamppb.New(time.Now().Add(5 * time.Minute)), Reason: "Synthetic console demo device action"}
	created, err := s.owner.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
	if rpcreason.Get(err) == "approval_required" {
		approval, approvalErr := s.approver.Approve(ctx, s.owner, &adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}})
		if approvalErr != nil {
			return "", approvalErr
		}
		request.ApprovalId = approval.GetId()
		created, err = s.owner.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
	}
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

// refusedAssistance is a request to an older agent that does not report its
// assistance setting, so the server cannot refuse it in advance; the device
// ends it DISABLED before any prompt. Its check-in first proves it online.
func (s *demoSeed) refusedAssistance(ctx context.Context, d *simulatedDevice) (string, error) {
	if _, err := d.syncAssistance(ctx); err != nil {
		return "", err
	}
	created, err := s.owner.Admin.CreateAssistanceSession(ctx, connect.NewRequest(&adminv1.CreateAssistanceSessionRequest{RequestId: uuid.NewString(), DeviceId: d.id, Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, MaxDurationSeconds: 900, Reason: "Check why the shared printer is offline"}))
	if err != nil {
		return "", err
	}
	id := created.Msg.GetSession().GetId()
	_, err = d.syncAssistance(ctx, &agentv1.AssistanceReport{SessionId: id, Phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED, EndCause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DISABLED})
	return id, err
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
	report := &agentv1.AssistanceReport{SessionId: id, LocalSession: &agentv1.AssistanceLocalSession{Username: "demo", Uid: 1000, LogindSessionId: "2", SessionType: "wayland", Desktop: d.demo.release.Desktop.Name}, InputState: &agentv1.AssistanceInputState{Epoch: 1}}
	sync := func(phase agentv1.AssistancePhase, cause agentv1.AssistanceEndCause) error {
		report.Phase, report.EndCause = phase, cause
		_, err := d.syncAssistance(ctx, report)
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

// syncAssistance is one agent assistance exchange: its session reports and,
// as every current agent sends, its applied assistance setting.
func (d *simulatedDevice) syncAssistance(ctx context.Context, reports ...*agentv1.AssistanceReport) (*devicev1.SyncAssistanceResponse, error) {
	response, err := d.client.SyncAssistance(ctx, connect.NewRequest(&devicev1.SyncAssistanceRequest{SessionEpoch: d.epoch, Reports: reports, Policy: d.demo.assistance}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
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

// enrollments leaves one synthetic device awaiting approval. Organization tokens
// and grants are issued exclusively by orgapply.
func (s *demoSeed) enrollments(ctx context.Context) error {
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
	return nil
}

// catalog seeds synthetic secret custody and integration/report history.
func (s *demoSeed) catalog(ctx context.Context) error {
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

// rollOutOrganization applies the full organization and has the independent
// approver decide each adoption rollout's one approval, as a second admin does
// in the console, applying again after the approved rollouts start so devices
// a later activation changed are reviewed again (devlab.RollOutOrganization).
// The demo report keeps the final apply's outcomes.
func (s *demoSeed) rollOutOrganization(ctx context.Context) error {
	assignments := make([]string, 0, len(s.organization.GetAssignments()))
	for _, a := range s.organization.GetAssignments() {
		assignments = append(assignments, a.GetAssignment().GetAssignmentId())
	}
	_, err := s.approver.RollOutOrganization(ctx, s.owner, assignments, "Second admin approves the organization's reviewed adoption rollout", func(ctx context.Context, _ int) error {
		applied, err := s.applyOrganization(ctx, s.organization)
		if err != nil {
			return err
		}
		if len(applied.Secrets) != 0 {
			clear(applied.Secrets)
			return errors.New("post-enrollment organization apply unexpectedly reissued credentials")
		}
		s.demo.Organization = applied.Outcomes
		return nil
	})
	if err != nil {
		return fmt.Errorf("roll out demo organization: %w", err)
	}
	return nil
}

// awaitRollouts waits for the promoter to activate every admitted device of
// the organization's rollouts, so later convergence observes their heads.
func (s *demoSeed) awaitRollouts(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		listed, err := s.owner.Admin.ListRollouts(ctx, connect.NewRequest(&adminv1.ListRolloutsRequest{PageSize: 100}))
		if err != nil {
			return fmt.Errorf("list demo rollouts: %w", err)
		}
		starting := false
		for _, r := range listed.Msg.GetRollouts() {
			if r.GetStatus() != adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE {
				continue
			}
			// A rollout whose drifted devices a follow-up rollout reviewed again
			// may have activated none; the route names one that activated some.
			if s.demo.Routes.RolloutID == "" && r.GetActivatedCount() > 0 {
				s.demo.Routes.RolloutID = r.GetRollout().GetRolloutId()
			}
			starting = starting || (!r.GetPaused() && r.GetStartingCount() > 0)
		}
		if !starting {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for demo rollout activation: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// adoptionRollout seeds a kernel-setting adoption awaiting its one approval,
// reviewed and requested through the real rollout RPCs.
func (s *demoSeed) adoptionRollout(ctx context.Context) error {
	target := s.organization.GetAssignments()[0].GetAssignment().GetTarget()
	kernel, err := s.owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "Publish console demo profile", Spec: &policyv1.ResourceProfile{
		Name: "Kernel hardening", Description: "Hide kernel pointers from unprivileged users.",
		Resources: []*policyv1.ProfileResource{{ResourceId: uuid.NewString(),
			Desired:      &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: "kernel.kptr_restrict"}, State: &resourcev1.ResourceDesiredState_Sysctl{Sysctl: &resourcev1.SysctlDesired{Key: "kernel.kptr_restrict", Value: "2"}}},
			Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED},
			Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 7 * 24 * 3600, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
		}},
	}}))
	if err != nil {
		return fmt.Errorf("publish demo adoption profile: %w", err)
	}
	assignment := &policyv1.TargetAssignment{AssignmentId: uuid.NewString(), ProfileRevisionId: kernel.Msg.GetRevision().GetRevisionId(), Target: target}
	review, err := s.owner.Admin.PreviewTargetAssignmentImpact(ctx, connect.NewRequest(&adminv1.PreviewTargetAssignmentImpactRequest{Assignment: assignment, PageSize: 20}))
	if err != nil {
		return fmt.Errorf("review demo adoption rollout: %w", err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	request := &adminv1.StartRolloutRequest{
		RequestId: uuid.NewString(), PreviewId: review.Msg.GetPreviewId(), ReviewSha256: review.Msg.GetReviewSha256(), Assignment: assignment,
		Rollout: &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: salt, Name: "Kernel hardening v1 to Engineering", Rings: []*policyv1.RolloutRing{{
			Name: "everyone", Cohort: target, CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 3600,
			FailureBasisPoints: 500, UnknownBasisPoints: 10000, UnavailableBasisPoints: 10000, HealthMaxAgeSeconds: 86400,
		}}},
		Reason: "Adopt the existing kernel pointer restriction",
	}
	started, err := s.owner.Admin.StartRollout(ctx, connect.NewRequest(request))
	if err != nil {
		return fmt.Errorf("start demo adoption rollout: %w", err)
	}
	if started.Msg.GetRollout().GetStatus() != adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL {
		return fmt.Errorf("demo adoption rollout did not wait for approval: %v", started.Msg.GetRollout().GetStatus())
	}
	if _, err := s.owner.Admin.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_StartRollout{StartRollout: request}})); err != nil {
		return fmt.Errorf("request demo rollout approval: %w", err)
	}
	return nil
}

// demoEvaluationWait bounds each wait for the server's own advisory evaluation.
// Real vendor exports hold millions of claims, and the route and scale devices
// carry thousands of packages, so a loaded shared host can need minutes.
const demoEvaluationWait = 8 * time.Minute

// acceptFinding waits for the server's own evaluation, then accepts one finding.
func (s *demoSeed) acceptFinding(ctx context.Context, d *simulatedDevice) error {
	ctx, cancel := context.WithTimeout(ctx, demoEvaluationWait)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		finding, freshness, err := s.demoFinding(ctx, d, false)
		if err == nil && finding != nil {
			request := &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: d.id, FindingId: finding.GetId(), ExpiresAt: timestamppb.New(time.Now().Add(30 * 24 * time.Hour)), Reason: "Synthetic review exception; no production risk acceptance"}
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
			return errors.Join(fmt.Errorf("wait for demo advisory findings on %s (last freshness %v %q): %w", d.demo.hostname, freshness.GetState(), freshness.GetReason(), ctx.Err()), err)
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
