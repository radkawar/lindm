package loadlab

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
)

// Console scale fixtures: realistic volumes so list pagination, pickers and
// long-content layouts are exercised by console review, not only the small
// curated fleet. All values are synthetic and deterministic in shape.
const (
	// demoScaleHostname is a 70-character FQDN (longest label 25 characters).
	demoScaleHostname = "fedora-ci-gpu-runner-0042.build-farm.eu-central-1.lab.example.internal"
	// The route device's bulk packages beside its curated Ubuntu baseline.
	demoRoutePackages = 2400
	// The scale device's unaffected bulk packages beside its 2,000 synthetic
	// AFFECTED builds (devlab.ConsoleDemoAffectedPackages).
	demoScalePackages = 1000
	demoScaleGroups   = 120
	// Each scale group gets this many later membership changes (audited).
	demoScaleGroupEdits = 4
	demoScaleProfiles   = 110
	// One scale profile gets this many revisions, so version history pages.
	demoScaleRevisions = 25
	demoScaleAccounts  = 40
	// Audited label changes on the scale device.
	demoScaleRelabels = 150
	// Concurrent scale requests; each record's own changes stay ordered.
	demoScaleWorkers = 8
)

// bulkPackages returns count synthetic packages for manager "dpkg" or "rpm".
func bulkPackages(manager string, count int) []*inventoryv1.Package {
	packages := make([]*inventoryv1.Package, count)
	for i := range packages {
		name, version := devlab.SyntheticPackageName(manager, i), devlab.SyntheticPackageVersion(manager, i)
		if manager == "rpm" {
			packages[i] = rpm(name, version, false)
		} else {
			packages[i] = dpkg(name, version, name, version)
		}
	}
	return packages
}

// affectedPackages installs every build the console demo's synthetic Fedora
// updates fix, so the scale device reports 2,000 AFFECTED findings.
func affectedPackages() []*inventoryv1.Package {
	affected := devlab.ConsoleDemoAffectedPackages()
	packages := make([]*inventoryv1.Package, len(affected))
	for i, pkg := range affected {
		packages[i] = rpm(pkg.Name, pkg.Installed, false)
	}
	return packages
}

var (
	demoTeams = []string{"Design", "Support desk", "Data science", "Facilities", "Legal", "Sales", "Customer success", "Platform", "Research", "Security operations", "Quality assurance", "People operations"}
	demoSites = []string{"Lisbon studio", "Berlin office", "Toronto hub", "Remote", "Nairobi lab", "Osaka branch", "Warehouse floor", "Reception"}
)

// scale seeds the large-volume fixtures through product RPCs: many device
// groups with audited membership changes, many profiles (one with a long
// revision history), many local accounts and audited label changes. Records
// are independent, so up to demoScaleWorkers requests run at once; each
// record's own changes stay ordered. Enrollment secrets returned for new
// accounts are discarded.
func (s *demoSeed) scale(ctx context.Context) error {
	var members []string
	var scaleDevice *simulatedDevice
	for _, d := range s.devices {
		if d.demo.state == "enrolled" || d.demo.state == "stale" {
			members = append(members, d.id)
		}
		if d.demo.hostname == demoScaleHostname {
			scaleDevice = d
		}
	}
	if scaleDevice == nil || len(members) < 3 {
		return errors.New("scale fixtures need the scale device and enrolled members")
	}
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(demoScaleWorkers)
	g.Go(func() error { return s.relabel(ctx, scaleDevice) })
	for i := range demoScaleGroups {
		g.Go(func() error { return s.scaleGroup(ctx, i, members) })
	}
	for i := range demoScaleProfiles {
		g.Go(func() error { return s.scaleProfile(ctx, i) })
	}
	for i := range demoScaleAccounts {
		g.Go(func() error { return s.scaleAccount(ctx, i) })
	}
	return g.Wait()
}

func (s *demoSeed) scaleGroup(ctx context.Context, i int, members []string) error {
	name := fmt.Sprintf("%s, %s %d", demoTeams[i%len(demoTeams)], demoSites[(i/len(demoTeams))%len(demoSites)], i/len(demoTeams)/len(demoSites)+1)
	if i%17 == 5 {
		name = fmt.Sprintf("%s laptops awaiting the quarterly hardware refresh and disk encryption review, %s", demoTeams[i%len(demoTeams)], demoSites[i%len(demoSites)])
	}
	group := uuid.NewString()
	for edit := range demoScaleGroupEdits + 1 {
		reason := "Group devices for scoped support and staged changes"
		if edit > 0 {
			reason = fmt.Sprintf("Membership review %d for %s", edit, demoTeams[i%len(demoTeams)])
		}
		start := (i + edit) % len(members)
		chosen := slices.Concat(members[start:], members[:start])[:1+(i+edit)%len(members)]
		if _, err := s.owner.Admin.SetDeviceGroup(ctx, connect.NewRequest(&adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: group, Name: name, DeviceIds: chosen, Reason: reason})); err != nil {
			return fmt.Errorf("set scale device group: %w", err)
		}
	}
	return nil
}

func (s *demoSeed) scaleProfile(ctx context.Context, i int) error {
	team, site := demoTeams[i%len(demoTeams)], demoSites[(i/len(demoTeams))%len(demoSites)]
	name := fmt.Sprintf("%s message of the day, %s", team, site)
	if i >= len(demoTeams)*len(demoSites) {
		name = fmt.Sprintf("%s message of the day, %s %d", team, site, i/(len(demoTeams)*len(demoSites))+1)
	}
	revisions := 1
	if i == 0 {
		revisions = demoScaleRevisions
	}
	profileID, expected := uuid.NewString(), ""
	for revision := range revisions {
		path := fmt.Sprintf("/etc/motd.d/%02d-%s", i, strings.ReplaceAll(strings.ToLower(team), " ", "-"))
		text := fmt.Sprintf("%s devices at %s are managed by IT. Notice revision %d.\n", team, site, revision+1)
		spec := &policyv1.ResourceProfile{Name: name, Description: fmt.Sprintf("Sign-in notice for %s devices at %s.", strings.ToLower(team), site), Resources: []*policyv1.ProfileResource{{
			ResourceId:   uuid.NewString(),
			Desired:      &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: path}, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: path, Presence: resourcev1.Presence_PRESENCE_PRESENT, Content: []byte(text), Mode: proto.Uint32(0o644)}}},
			Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 7 * 24 * 3600, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
			Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED},
		}}}
		request := &adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: profileID, Spec: spec, Reason: fmt.Sprintf("Publish %s sign-in notice", strings.ToLower(team))}
		if expected != "" {
			request.ExpectedRevisionId = proto.String(expected)
		}
		published, err := s.owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(request))
		if err != nil {
			return fmt.Errorf("publish scale profile: %w", err)
		}
		expected = published.Msg.GetRevision().GetRevisionId()
	}
	return nil
}

func (s *demoSeed) scaleAccount(ctx context.Context, i int) error {
	roles := []string{"admin", "operator", "helpdesk", "auditor"}
	team := strings.ReplaceAll(strings.ToLower(demoTeams[i%len(demoTeams)]), " ", "-")
	username := fmt.Sprintf("%s.%s-%02d", team, roles[i%len(roles)], i+1)
	if i%13 == 7 {
		username = fmt.Sprintf("contractor.%s-temporary-access-until-the-end-of-the-quarter-%02d", team, i+1)
		username = username[:min(len(username), 64)]
	}
	enrollment, err := s.owner.CreateAccount(ctx, &authv1.CreateAccountRequest{Username: username, Role: roles[i%len(roles)]})
	if err != nil {
		return fmt.Errorf("create scale account: %w", err)
	}
	enrollment.Secret = ""
	return nil
}

// relabel records the scale device's rack moves one after another.
func (s *demoSeed) relabel(ctx context.Context, d *simulatedDevice) error {
	for i := range demoScaleRelabels {
		labels := []string{"synthetic-demo", "server", "ci-runner", "gpu", fmt.Sprintf("rack-%c%d", 'a'+rune(i%6), 1+i%12)}
		metadata := &adminv1.DeviceMetadata{Labels: labels, Owner: &adminv1.DeviceMetadata_OwnerText{OwnerText: "Synthetic demo device, not a live host"}}
		if _, err := s.owner.Admin.SetDeviceMetadata(ctx, connect.NewRequest(&adminv1.SetDeviceMetadataRequest{RequestId: uuid.NewString(), DeviceId: d.id, Metadata: metadata, Reason: fmt.Sprintf("Rack move %d during the build farm rebalance", i+1)})); err != nil {
			return fmt.Errorf("relabel scale device: %w", err)
		}
	}
	return nil
}

// awaitScaleFindings waits until the server's own evaluation of the scale
// device lists at least the synthetic AFFECTED builds, so console review never
// sees the fleet before its large findings set exists.
func (s *demoSeed) awaitScaleFindings(ctx context.Context) error {
	var device *simulatedDevice
	for _, d := range s.devices {
		if d.demo.hostname == demoScaleHostname {
			device = d
		}
	}
	if device == nil {
		return fmt.Errorf("scale device missing")
	}
	want := len(devlab.ConsoleDemoAffectedPackages())
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		affected, err := s.countAffected(ctx, device, want)
		if err == nil && affected >= want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for %d scale findings on %s (have %d): %w", want, demoScaleHostname, affected, errors.Join(ctx.Err(), err))
		case <-ticker.C:
		}
	}
}

func (s *demoSeed) countAffected(ctx context.Context, d *simulatedDevice, enough int) (int, error) {
	count := 0
	for token := ""; ; {
		response, err := s.owner.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: d.id, PageSize: 200, PageToken: token}))
		if err != nil {
			return count, err
		}
		for _, finding := range response.Msg.GetFindings() {
			if finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
				count++
			}
		}
		token = response.Msg.GetNextPageToken()
		if token == "" || count >= enough {
			return count, nil
		}
	}
}
