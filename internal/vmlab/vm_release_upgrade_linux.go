// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// The release upgrade lane upgrades an enrolled, converged device in place
// with the vendor's supported unattended upgrader against the real archive,
// then re-proves identity, confinement, resource ownership and advisory
// matching on the target release. SSH only starts the upgrader, reboots and
// reads independent native oracles; every resource effect is server-assigned.
const (
	releaseUpgradeUnit = "lindm-lab-release-upgrade.service"
	// releaseUpgradeCommand is ubuntu-release-upgrader's documented unattended
	// frontend; it runs in a transient unit so a lost lab session cannot stop it.
	releaseUpgradeCommand = "/usr/bin/do-release-upgrade -f DistUpgradeViewNonInteractive"
	// releaseUpgradeSources is the operator-installed deb822 agent source that
	// the published packaging contract describes (dedicated Signed-By key).
	releaseUpgradeSources = "/etc/apt/sources.list.d/lindm-agent.sources"
	releaseUpgradeFile    = "release-upgrade.conf"
	releaseUpgradeSysctl  = "31"
	releaseUpgradeBudget  = 170 * time.Minute
	// releaseUpgradeFeedBytes bounds both vendor OSV exports (one revalidated
	// download serves both releases of the same vendor archive).
	releaseUpgradeFeedBytes = 4 << 30
	// releaseUpgradeBusyReason is the server's recorded reason for a package
	// change refused while another native frontend held the dpkg lock.
	releaseUpgradeBusyReason = "native_package_manager_busy"
)

type VMReleaseUpgradeEvidence struct {
	SourceRelease   string                  `json:"source_release"`
	TargetRelease   string                  `json:"target_release"`
	SourceGate      string                  `json:"source_gate,omitempty"`
	Command         string                  `json:"command"`
	UpgraderVersion string                  `json:"upgrader_version,omitempty"`
	StartedAt       time.Time               `json:"started_at"`
	FinishedAt      time.Time               `json:"finished_at"`
	DurationSeconds float64                 `json:"duration_seconds"`
	Before          *VMReleaseUpgradeHost   `json:"before,omitempty"`
	After           *VMReleaseUpgradeHost   `json:"after,omitempty"`
	IdentityBefore  *agentv1.StatusResponse `json:"identity_before,omitempty"`
	IdentityAfter   *agentv1.StatusResponse `json:"identity_after,omitempty"`
	ServerBefore    *adminv1.Device         `json:"server_before,omitempty"`
	ServerAfter     *adminv1.Device         `json:"server_after,omitempty"`
	// Converged and Reconverged are the server's resource read model with
	// device-attested actions before the upgrade and after the target boot.
	Converged   *adminv1.GetDeviceResourceStateResponse `json:"converged,omitempty"`
	Reconverged *adminv1.GetDeviceResourceStateResponse `json:"reconverged,omitempty"`
	// Window is the package change assigned while the upgrader held the dpkg
	// frontend lock, and the server's recorded outcome for it.
	Window         *VMReleaseUpgradeWindow      `json:"window,omitempty"`
	Feeds          *devlab.AcceptanceFeedResult `json:"feeds,omitempty"`
	FindingsBefore *VMReleaseUpgradeFindings    `json:"findings_before,omitempty"`
	FindingsAfter  *VMReleaseUpgradeFindings    `json:"findings_after,omitempty"`
	Native         []VMResourceNativeRecord     `json:"native_records"`
	Failures       []string                     `json:"failures,omitempty"`
}

// VMReleaseUpgradeHost is parsed from the independent native host oracle.
type VMReleaseUpgradeHost struct {
	ID        string            `json:"id"`
	VersionID string            `json:"version_id"`
	Codename  string            `json:"codename"`
	Kernel    string            `json:"kernel"`
	Installed string            `json:"installed_packages"`
	Packages  map[string]string `json:"packages"`
	Tools     map[string]string `json:"tools"`
	Units     map[string]string `json:"units"`
}

type VMReleaseUpgradeWindow struct {
	LockHolder string                         `json:"lock_holder"`
	AssignedAt time.Time                      `json:"assigned_at"`
	Action     *adminv1.ResourceActionSummary `json:"action,omitempty"`
	// LockHeldAfter proves the action finished inside the locked window.
	LockHeldAfter string `json:"lock_held_after,omitempty"`
	Disposition   string `json:"disposition,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type VMReleaseUpgradeFindings struct {
	FeedID   string `json:"feed_id"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	Findings int    `json:"findings"`
	Affected int    `json:"affected"`
	// ForeignFeedFindings counts findings attributed to any other feed.
	ForeignFeedFindings int `json:"foreign_feed_findings"`
}

// releaseUpgradePath resolves the manifest's registry row and the vendor
// upgrade target. A row without a modelled path is refused with its gate.
func releaseUpgradePath(manifest *labv1.ImageManifest) (source, target *platform.Release, err error) {
	source = manifestRelease(manifest)
	if source.UpgradeTo == "" {
		if gate := source.Gate(platform.ReleaseUpgrade); gate != nil {
			return nil, nil, gate
		}
		return nil, nil, fmt.Errorf("%s has no modelled release upgrade target", source.Name)
	}
	target, ok := platform.Lookup(source.UpgradeTo)
	if !ok || target.ID != source.ID || !slices.Contains(source.Advisory.Feeds, platform.FeedOSV) || !slices.Contains(target.Advisory.Feeds, platform.FeedOSV) {
		return nil, nil, fmt.Errorf("%s upgrade target %q is not an OSV-covered release of the same distribution", source.Name, source.UpgradeTo)
	}
	return source, target, nil
}

// releaseUpgradeFeed is the vendor's complete OSV export bound to one release.
func releaseUpgradeFeed(r *platform.Release, architecture string) *advisoryv1.FeedSource {
	vendor, _, _ := strings.Cut(r.Advisory.Ecosystem, ":")
	return &advisoryv1.FeedSource{Id: "release-upgrade-" + r.Key, Distro: r.ID, Release: r.Version.Value, Architecture: architecture, Url: "https://osv-vulnerabilities.storage.googleapis.com/" + vendor + "/all.zip", Format: advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP, MaxAgeSeconds: 86400}
}

// releaseUpgradeHostCommand prints one key=value fact per line. Absent
// packages are omitted by dpkg-query; the parser records what exists.
const releaseUpgradeHostCommand = `set -u
. /etc/os-release
printf 'id=%s\nversion_id=%s\ncodename=%s\n' "$ID" "$VERSION_ID" "$VERSION_CODENAME"
printf 'kernel=%s\n' "$(uname -r)"
printf 'installed=%s\n' "$(dpkg-query -W -f='${db:Status-Status}\n' | grep -cx installed)"
dpkg-query -W -f='package ${Package}=${Version} ${db:Status-Status}\n' apt dpkg systemd sudo sudo-rs coreutils rust-coreutils coreutils-from-uutils gnu-coreutils python3 openssl openssh-server cloud-init ubuntu-release-upgrader-core gpgv sqv dracut initramfs-tools lindm-agent "linux-image-$(uname -r)" 2>/dev/null || true
printf 'tool sudo=%s\n' "$(sudo --version 2>&1 | head -n1)"
printf 'tool ls=%s\n' "$(ls --version 2>&1 | head -n1)"
printf 'tool systemd=%s\n' "$(systemctl --version | head -n1)"
printf 'tool apt=%s\n' "$(apt-get --version | head -n1)"
for unit in lindm-executor.service lindm-agent.service; do
 printf 'unit %s=%s\n' "$unit" "$(systemctl show -p ActiveState -p User -p ProtectSystem -p ProtectHome -p PrivateDevices -p ProtectProc -p NoNewPrivileges -p PrivateTmp -p RestrictAddressFamilies -p CapabilityBoundingSet -p AmbientCapabilities "$unit" | sort | tr '\n' ' ')"
 printf 'unit %s.fragment=%s\n' "$unit" "$(sha256sum "$(systemctl show -P FragmentPath "$unit")" | cut -d' ' -f1)"
done
`

func parseReleaseUpgradeHost(data []byte) (*VMReleaseUpgradeHost, error) {
	host := &VMReleaseUpgradeHost{Packages: map[string]string{}, Tools: map[string]string{}, Units: map[string]string{}}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("malformed native host fact %q", line)
		}
		switch {
		case key == "id":
			host.ID = value
		case key == "version_id":
			host.VersionID = value
		case key == "codename":
			host.Codename = value
		case key == "kernel":
			host.Kernel = value
		case key == "installed":
			host.Installed = value
		case strings.HasPrefix(key, "package "):
			host.Packages[strings.TrimPrefix(key, "package ")] = value
		case strings.HasPrefix(key, "tool "):
			host.Tools[strings.TrimPrefix(key, "tool ")] = value
		case strings.HasPrefix(key, "unit "):
			host.Units[strings.TrimPrefix(key, "unit ")] = value
		default:
			return nil, fmt.Errorf("unexpected native host fact %q", key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if host.ID == "" || host.VersionID == "" || host.Kernel == "" || len(host.Units) != 4 {
		return nil, errors.New("incomplete native host facts")
	}
	return host, nil
}

// releaseUpgradeLockCommand names the process holding dpkg's POSIX frontend
// write lock (dpkg's documented protocol), or prints "free".
const releaseUpgradeLockCommand = `ino=$(stat -c %i /var/lib/dpkg/lock-frontend)
pid=$(awk -v ino="$ino" '$2 == "POSIX" && $4 == "WRITE" { n = split($6, a, ":"); if (a[n] == ino) { print $5; exit } }' /proc/locks)
if test -n "$pid"; then printf 'holder %s %s\n' "$pid" "$(tr '\0' ' ' < /proc/$pid/cmdline)"; else printf 'free\n'; fi`

type releaseUpgrade struct {
	vm       *guestVM
	control  *vmControlPlane
	device   string
	profile  string
	revision string
	head     string
	evidence *VMReleaseUpgradeEvidence
}

func (u *releaseUpgrade) fail(format string, args ...any) {
	u.evidence.Failures = append(u.evidence.Failures, fmt.Sprintf(format, args...))
}

// native runs a read-only (or lab-fixture) native command whose output and
// exit status are recorded; a failure names the command's output tail.
func (u *releaseUpgrade) native(ctx context.Context, name, command string) (VMResourceNativeRecord, error) {
	return u.nativeWithin(ctx, name, command, time.Minute)
}

func (u *releaseUpgrade) nativeWithin(ctx context.Context, name, command string, timeout time.Duration) (VMResourceNativeRecord, error) {
	result, err := u.vm.runResult(ctx, "sudo -n /bin/sh -eu -c "+nativeQuote(command)+" 2>&1", nil, 1<<20, timeout)
	if err != nil {
		return VMResourceNativeRecord{}, fmt.Errorf("%s: %w", name, err)
	}
	if result.ExitCode != 0 {
		tail := strings.TrimSpace(string(result.Stdout))
		if len(tail) > 2048 {
			tail = tail[len(tail)-2048:]
		}
		return VMResourceNativeRecord{}, fmt.Errorf("%s: guest exit %d: %q", name, result.ExitCode, tail)
	}
	record := resourceNativeRecord(name, result.Stdout)
	u.evidence.Native = append(u.evidence.Native, record)
	return record, nil
}

func (u *releaseUpgrade) host(ctx context.Context, name string) (*VMReleaseUpgradeHost, error) {
	record, err := u.native(ctx, name, releaseUpgradeHostCommand)
	if err != nil {
		return nil, err
	}
	return parseReleaseUpgradeHost(record.Bytes)
}

func (u *releaseUpgrade) lockHolder(ctx context.Context) (string, error) {
	return dpkgFrontendHolder(ctx, u.vm)
}

func releaseUpgradeResources(rpm resourcePackaging, packageVersion string) []*policyv1.ProfileResource {
	service := &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: dispatchUnit}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: dispatchUnit, Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED}}}
	verification := &resourcev1.VerificationPolicy{MaxAgeSeconds: 300, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}}
	retain := &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN}
	// Fixed resource IDs keep each resource's identity across revisions.
	return []*policyv1.ProfileResource{
		{ResourceId: "5b0c6f3e-2d8a-4f0b-9b1e-7a3c1d2e4f01", Desired: resourcePackageDesired(rpm, packageVersion, true), Ownership: resourceCreatePolicy(), Verification: verification},
		{ResourceId: "5b0c6f3e-2d8a-4f0b-9b1e-7a3c1d2e4f02", Desired: resourceFileDesired(releaseUpgradeFile, "managed across a release upgrade\n"), Ownership: resourceCreatePolicy(), Verification: verification},
		{ResourceId: "5b0c6f3e-2d8a-4f0b-9b1e-7a3c1d2e4f03", Desired: service, Ownership: retain, Verification: verification},
		{ResourceId: "5b0c6f3e-2d8a-4f0b-9b1e-7a3c1d2e4f04", Desired: resourceSysctlDesired(resourceLabSysctlKey, releaseUpgradeSysctl), Ownership: resourceAdoptionPolicy(), Verification: verification},
	}
}

// assign publishes the next immutable revision and moves the assignment head
// to it. Sysctl adoption makes every assignment an approved one.
func (u *releaseUpgrade) assign(ctx context.Context, resources []*policyv1.ProfileResource) error {
	request := &adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: u.profile, Reason: "disposable release upgrade qualification", Spec: &policyv1.ResourceProfile{Name: "Release upgrade qualification", Resources: resources}}
	if u.revision != "" {
		request.ExpectedRevisionId = proto.String(u.revision)
	}
	published, err := u.control.session.Admin.PublishProfileRevision(ctx, connect.NewRequest(request))
	if err != nil {
		return err
	}
	u.revision = published.Msg.GetRevision().GetRevisionId()
	assignment := &adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: u.device, Target: &adminv1.ResourceAssignmentTarget{ProfileId: u.profile, RevisionId: u.revision}, ReconcileIntervalSeconds: proto.Uint32(dispatchReconcileIntervalSeconds), Reason: "disposable release upgrade qualification"}
	if u.head != "" {
		assignment.ExpectedAssignmentId = proto.String(u.head)
	}
	if u.control.approver == nil {
		approver, err := u.control.openApprover(ctx)
		if err != nil {
			return err
		}
		u.control.approver = approver
	}
	approval, err := u.control.approver.Approve(ctx, u.control.session, &adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_SetResourceAssignment{SetResourceAssignment: assignment}})
	if err != nil {
		return err
	}
	assignment.ApprovalId = approval.GetId()
	response, err := u.control.session.Admin.SetResourceAssignment(ctx, connect.NewRequest(assignment))
	if err != nil {
		return err
	}
	u.head = response.Msg.GetAssignment().GetAssignmentId()
	return nil
}

// waitConverged waits until every resource of the head has a device-attested,
// converged result verified at or after since.
func (u *releaseUpgrade) waitConverged(ctx context.Context, since time.Time, timeout time.Duration) (*adminv1.GetDeviceResourceStateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last *adminv1.GetDeviceResourceStateResponse
	for {
		state, err := u.control.dispatchState(ctx, u.device)
		if err != nil {
			return last, err
		}
		last = state
		if state.GetAssignment().GetAssignmentId() != u.head || len(state.GetResources()) != 4 {
			return last, errors.New("release upgrade assignment head or cardinality changed")
		}
		done := true
		for _, resource := range state.GetResources() {
			if resource.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED {
				return last, fmt.Errorf("resource %s unsupported: %s", resource.GetDesired().GetRef().GetCanonicalKey(), resource.GetReason())
			}
			action := resource.GetLatestAction()
			if resource.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED || resource.GetLastVerifiedAt() == nil || resource.GetLastVerifiedAt().AsTime().Before(since) || action.GetClosedReason() != "result" || action.GetAttestedAt() == nil || action.GetStatus().GetVerification().GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
				done = false
			}
		}
		if done {
			return last, nil
		}
		if err := lifecycleDelay(ctx, 2*time.Second); err != nil {
			return last, fmt.Errorf("resources did not converge after %s: %w", since.Format(time.RFC3339), err)
		}
	}
}

func (u *releaseUpgrade) resourceOracles(ctx context.Context, phase, packageVersion string, rpm resourcePackaging) error {
	for _, oracle := range []func(context.Context) (VMResourceNativeRecord, error){
		func(ctx context.Context) (VMResourceNativeRecord, error) {
			return packageOracle(ctx, u.vm, rpm, packageVersion, true)
		},
		func(ctx context.Context) (VMResourceNativeRecord, error) {
			return fileOracle(ctx, u.vm, releaseUpgradeFile, "managed across a release upgrade\n", true)
		},
		func(ctx context.Context) (VMResourceNativeRecord, error) {
			return resourceOracle(ctx, u.vm, "native-systemd-service", "test \"$(systemctl show -P ActiveState "+dispatchUnit+")\" = active; test \"$(systemctl show -P UnitFileState "+dispatchUnit+")\" = enabled; systemctl show -p ActiveState -p SubState -p UnitFileState "+dispatchUnit)
		},
		func(ctx context.Context) (VMResourceNativeRecord, error) {
			return resourceOracle(ctx, u.vm, "native-sysctl", sysctlCommand(resourceLabSysctlKey, resourceLabSysctlPrior, releaseUpgradeSysctl))
		},
	} {
		record, err := oracle(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", phase, err)
		}
		record.Name = phase + "-" + record.Name
		u.evidence.Native = append(u.evidence.Native, record)
	}
	return nil
}

// waitFindings waits for the device evaluation bound to feedID and counts
// every finding's attributed feed.
func (u *releaseUpgrade) waitFindings(ctx context.Context, feedID string, timeout time.Duration) (*VMReleaseUpgradeFindings, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last *VMReleaseUpgradeFindings
	for {
		findings := new(VMReleaseUpgradeFindings)
		token := ""
		var err error
		// maxFindings is 100,000; 600 pages of 200 cover it with margin.
		for range 600 {
			var response *connect.Response[adminv1.ListDeviceFindingsResponse]
			response, err = u.control.session.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: u.device, PageSize: 200, PageToken: token}))
			if err != nil {
				break
			}
			freshness := response.Msg.GetFreshness()
			findings.FeedID, findings.State, findings.Reason = freshness.GetFeedId(), freshness.GetState().String(), freshness.GetReason()
			for _, finding := range response.Msg.GetFindings() {
				findings.Findings++
				if finding.GetFeedId() != feedID {
					findings.ForeignFeedFindings++
				}
				if finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
					findings.Affected++
				}
			}
			if token = response.Msg.GetNextPageToken(); token == "" {
				break
			}
		}
		if err == nil && token == "" {
			last = findings
			if findings.FeedID == feedID && findings.Findings > 0 && findings.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN.String() {
				return findings, nil
			}
		}
		if err := lifecycleDelay(ctx, 5*time.Second); err != nil {
			return last, fmt.Errorf("device findings never bound feed %s (last %+v): %w", feedID, last, err)
		}
	}
}

func (u *releaseUpgrade) serverDevice(ctx context.Context) (*adminv1.Device, error) {
	response, err := u.control.session.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: u.device}))
	if err != nil {
		return nil, vmControlPlaneError("get release upgrade device", err)
	}
	return response.Msg.GetDevice(), nil
}

// exerciseReleaseUpgrade runs after DispatchVM's authenticated enrollment.
func exerciseReleaseUpgrade(ctx context.Context, packages *nativeGuestPackages, control *vmControlPlane, fixture *devlab.AuthorityFixture, result *VMDispatchResult, manifest *labv1.ImageManifest, feedCache string, reboot func(context.Context) error) (err error) {
	source, target, err := releaseUpgradePath(manifest)
	if err != nil {
		return err
	}
	evidence := &VMReleaseUpgradeEvidence{SourceRelease: source.Key, TargetRelease: target.Key, SourceGate: source.GateReason(platform.ReleaseUpgrade), Command: releaseUpgradeCommand}
	result.ReleaseUpgrade = evidence
	u := &releaseUpgrade{vm: packages.vm, control: control, device: result.DeviceID, profile: uuid.NewString(), evidence: evidence}
	// Hard failures stop the lane; observations after the upgrade are all
	// collected and joined so one record carries every post-upgrade verdict.
	defer func() {
		if err == nil && len(evidence.Failures) != 0 {
			err = fmt.Errorf("release upgrade qualification failed: %s", strings.Join(evidence.Failures, "; "))
		}
	}()
	rpm := newResourcePackaging(packages.backend, result.Architecture)

	// The vendor upgrader refuses pending updates and pending reboots.
	if _, err := u.nativeWithin(ctx, "pre-upgrade-full-upgrade", "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l; log=/var/tmp/lindm-lab-full-upgrade.log; { apt-get -q update && apt-get -q -y -o Dpkg::Options::=--force-confold full-upgrade; } >$log 2>&1 || { tail -n 80 $log; exit 1; }; tail -n 40 $log; cat /var/run/reboot-required.pkgs 2>/dev/null || true", 30*time.Minute); err != nil {
		return err
	}
	if _, err := u.vm.run(ctx, "test -e /var/run/reboot-required", nil, 64, 15*time.Second); err == nil {
		if err := reboot(ctx); err != nil {
			return err
		}
		if _, err := waitGuestExecutorReady(ctx, u.vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
			return err
		}
	}
	// The agent repository forward did not survive any reboot; the operator's
	// deb822 source is configured against a live signed repository.
	if err := packages.startAPT(ctx, packages.apt, []packaging.Artifact{packages.first, packages.second}); err != nil {
		return err
	}
	key := "/etc/apt/keyrings/lindm-agent.gpg"
	if strings.HasSuffix(packages.keyPath, ".asc") {
		key = "/etc/apt/keyrings/lindm-agent.asc"
	}
	agentSource := "Types: deb\nURIs: http://" + packages.forward.Addr() + "/\nSuites: stable\nComponents: main\nSigned-By: " + key + "\n"
	if _, err := u.native(ctx, "operator-agent-source", "install -d -m 0755 /etc/apt/keyrings; install -m 0644 "+nativeQuote(packages.keyPath)+" "+key+"; printf '%s' "+nativeQuote(agentSource)+" > "+releaseUpgradeSources+"; chmod 0644 "+releaseUpgradeSources+"; apt-get -q -o APT::Update::Error-Mode=any update; policy=$(apt-cache policy lindm-agent); printf '%s\\n' \"$policy\"; printf '%s\\n' \"$policy\" | grep -F "+nativeQuote(packages.forward.Addr())+"; cat "+releaseUpgradeSources); err != nil {
		return err
	}

	if err := u.assign(ctx, releaseUpgradeResources(rpm, "1.0")); err != nil {
		return err
	}
	assigned := time.Now().UTC()
	if evidence.Converged, err = u.waitConverged(ctx, assigned, 15*time.Minute); err != nil {
		return err
	}
	if err := u.resourceOracles(ctx, "before", "1.0", rpm); err != nil {
		return err
	}

	sourceFeed, targetFeed := releaseUpgradeFeed(source, result.Architecture), releaseUpgradeFeed(target, result.Architecture)
	evidence.Feeds, err = fixture.RefreshVendorFeeds(ctx, feedCache, releaseUpgradeFeedBytes, 40*time.Minute, []*advisoryv1.FeedSource{sourceFeed, targetFeed})
	if err != nil {
		return err
	}
	if evidence.FindingsBefore, err = u.waitFindings(ctx, sourceFeed.GetId(), 15*time.Minute); err != nil {
		return err
	}
	if evidence.FindingsBefore.ForeignFeedFindings != 0 {
		return fmt.Errorf("%d source-release findings were attributed to another feed", evidence.FindingsBefore.ForeignFeedFindings)
	}

	if evidence.Before, err = u.host(ctx, "before-host"); err != nil {
		return err
	}
	if evidence.Before.ID != source.ID || evidence.Before.VersionID != source.Version.Value || evidence.Before.Codename != source.Codename {
		return fmt.Errorf("guest is not %s before the upgrade: %+v", source.Name, evidence.Before)
	}
	if evidence.IdentityBefore, err = waitGuestExecutorReady(ctx, u.vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return err
	}
	if evidence.ServerBefore, err = u.serverDevice(ctx); err != nil {
		return err
	}
	if _, err := u.native(ctx, "before-owned-pin-and-source", "stat -c '%n %i %a %u %g %s' /etc/apt/preferences.d/lindm-*; sha256sum /etc/apt/preferences.d/lindm-*; cat /etc/apt/preferences.d/lindm-*; cat "+releaseUpgradeSources+"; cat /etc/update-manager/release-upgrades"); err != nil {
		return err
	}

	evidence.StartedAt = time.Now().UTC()
	if err := lifecycleCommand(ctx, u.vm, "start vendor release upgrader", "test -x /usr/bin/do-release-upgrade; systemd-run --quiet --unit="+releaseUpgradeUnit+" --property=Type=exec --property=RemainAfterExit=yes --setenv=DEBIAN_FRONTEND=noninteractive "+releaseUpgradeCommand); err != nil {
		return err
	}
	if err := u.exerciseWindow(ctx, rpm); err != nil {
		u.fail("dpkg-locked window: %v", err)
	}
	if err := u.waitUpgrader(ctx); err != nil {
		return err
	}
	evidence.FinishedAt = time.Now().UTC()
	evidence.DurationSeconds = evidence.FinishedAt.Sub(evidence.StartedAt).Seconds()
	logs, err := u.native(ctx, "upgrader-logs", "systemctl show -p Result -p ExecMainStatus -p ExecMainStartTimestamp -p ExecMainExitTimestamp "+releaseUpgradeUnit+"; grep -m1 -o \"release-upgrader version '[^']*' started\" /var/log/dist-upgrade/main.log || true; sha256sum /var/log/dist-upgrade/*.log; grep -E 'Foreign|foreign pkg|lindm|Obsolete:|remove_candidates|third.party|disabled \\(' /var/log/dist-upgrade/main.log | cut -c1-400 | head -n 80 || true; tail -n 60 /var/log/dist-upgrade/main.log; journalctl -u "+releaseUpgradeUnit+" --no-pager -o cat | tail -n 40")
	if err != nil {
		return err
	}
	if line := nativeRecordLine(logs, "release-upgrader version '"); line != "" {
		evidence.UpgraderVersion = strings.TrimSuffix(strings.TrimPrefix(line, "release-upgrader version '"), "' started")
	}

	if err := reboot(ctx); err != nil {
		return err
	}
	rebooted := time.Now().UTC()
	if evidence.After, err = u.host(ctx, "after-host"); err != nil {
		return err
	}
	after := evidence.After
	if after.ID != target.ID || after.VersionID != target.Version.Value || after.Codename != target.Codename {
		return fmt.Errorf("guest is not %s after the upgrade: %+v", target.Name, after)
	}
	if after.Kernel == evidence.Before.Kernel {
		u.fail("kernel did not change across the release upgrade (%s)", after.Kernel)
	}
	if after.Packages["lindm-agent"] == "" || after.Packages["lindm-agent"] != evidence.Before.Packages["lindm-agent"] {
		u.fail("lindm-agent package changed or was removed: before %q after %q", evidence.Before.Packages["lindm-agent"], after.Packages["lindm-agent"])
	}
	for unit, value := range evidence.Before.Units {
		if after.Units[unit] != value {
			u.fail("agent unit %s changed: before %q after %q", unit, value, after.Units[unit])
		}
	}
	if evidence.IdentityAfter, err = waitGuestExecutorReady(ctx, u.vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return err
	}
	before, now := evidence.IdentityBefore, evidence.IdentityAfter
	if now.GetInstallationId() != before.GetInstallationId() || now.GetDeviceId() != before.GetDeviceId() || now.GetEnrollmentGeneration() != before.GetEnrollmentGeneration() || now.GetCommittedSessionEpoch() < before.GetCommittedSessionEpoch() {
		u.fail("protected executor identity changed across the release upgrade")
	}
	if !proto.Equal(now.GetCertificateNotAfter(), before.GetCertificateNotAfter()) && before.GetRenewAfter().AsTime().After(time.Now()) {
		u.fail("device certificate changed without a due renewal")
	}
	if _, err := u.native(ctx, "after-owned-pin-and-source", "stat -c '%n %i %a %u %g %s' /etc/apt/preferences.d/lindm-*; sha256sum /etc/apt/preferences.d/lindm-*; cat "+releaseUpgradeSources+"; ls -l /etc/apt/sources.list.d/; grep -x 'Enabled: no' "+releaseUpgradeSources+" || printf 'agent source still enabled\\n'"); err != nil {
		u.fail("post-upgrade pin and source oracle: %v", err)
	}

	if evidence.Reconverged, err = u.waitConverged(ctx, rebooted, 25*time.Minute); err != nil {
		u.fail("post-upgrade reconvergence: %v", err)
		evidence.Native = append(evidence.Native, executorDiagnostics(ctx, u.vm))
	} else if err := u.resourceOracles(ctx, "after", "2.0", rpm); err != nil {
		u.fail("post-upgrade native resources: %v", err)
	} else {
		for _, resource := range evidence.Reconverged.GetResources() {
			if resource.GetDesired().GetRef().GetKind() != resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE && resource.GetLatestAction().GetStartAuthorizedAt() != nil {
				u.fail("%s needed a native effect after the upgrade (ownership or state lost)", resource.GetDesired().GetRef().GetCanonicalKey())
			}
		}
	}

	// The held package change lands after the hold expires; only then is the
	// native package set stable enough to compare with fresh inventory.
	// Fresh authenticated inventory must equal post-upgrade native truth.
	if _, err := waitLifecycleInventory(ctx, u.vm, control, target, u.device, nil); err != nil {
		u.fail("fresh post-upgrade inventory: %v", err)
	}
	if evidence.ServerAfter, err = u.serverDevice(ctx); err != nil {
		return err
	}
	if evidence.ServerAfter.GetOsId() != target.ID || evidence.ServerAfter.GetOsVersion() != target.Version.Value || evidence.ServerAfter.GetEnrollmentGeneration() != evidence.ServerBefore.GetEnrollmentGeneration() {
		u.fail("server did not record the release change on the same enrollment: %s", evidence.ServerAfter)
	}

	if evidence.FindingsAfter, err = u.waitFindings(ctx, targetFeed.GetId(), 25*time.Minute); err != nil {
		u.fail("target-release findings: %v", err)
	} else if evidence.FindingsAfter.ForeignFeedFindings != 0 {
		u.fail("%d target-release findings were attributed to another feed", evidence.FindingsAfter.ForeignFeedFindings)
	}
	return nil
}

// exerciseWindow assigns a package change while the upgrader holds dpkg's
// frontend lock and records the server's outcome for it. The device must
// refuse the change explicitly without a native effect.
func (u *releaseUpgrade) exerciseWindow(ctx context.Context, rpm resourcePackaging) error {
	window := new(VMReleaseUpgradeWindow)
	u.evidence.Window = window
	ctx, cancel := context.WithTimeout(ctx, 40*time.Minute)
	defer cancel()
	for {
		holder, err := u.lockHolder(ctx)
		if err != nil {
			return err
		}
		if strings.HasPrefix(holder, "holder ") {
			window.LockHolder = holder
			break
		}
		if state, err := u.vm.run(ctx, "systemctl show -P SubState "+releaseUpgradeUnit, nil, 256, 15*time.Second); err != nil || strings.TrimSpace(string(state)) != "running" {
			return fmt.Errorf("upgrader left running state before holding the dpkg lock: %q %v", strings.TrimSpace(string(state)), err)
		}
		if err := lifecycleDelay(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("upgrader never held the dpkg frontend lock: %w", err)
		}
	}
	if err := u.assign(ctx, releaseUpgradeResources(rpm, "2.0")); err != nil {
		return err
	}
	window.AssignedAt = time.Now().UTC()
	for {
		state, err := u.control.dispatchState(ctx, u.device)
		if err != nil {
			return err
		}
		for _, resource := range state.GetResources() {
			action := resource.GetLatestAction()
			if resource.GetDesired().GetRef().GetKind() != resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE || action.GetClosedAt() == nil || action.GetIssuedAt().AsTime().Before(window.AssignedAt) {
				continue
			}
			window.Action, window.Disposition, window.Reason = action, resource.GetDisposition().String(), resource.GetReason()
			if window.LockHeldAfter, err = u.lockHolder(ctx); err != nil {
				return err
			}
			if !strings.HasPrefix(window.LockHeldAfter, "holder ") {
				return errors.New("package action closed after the upgrader released the dpkg lock; window not proven")
			}
			// Staging is effect-free and may finish before the upgrader's dpkg
			// transaction; a start grant may then be issued. The executor must
			// still refuse before consuming its effect gate.
			if action.GetStatus().GetStartedAt() != nil {
				return fmt.Errorf("package change consumed its effect gate while dpkg was locked: %s", action)
			}
			if action.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || action.GetStatus().GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY || resource.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED || resource.GetReason() != releaseUpgradeBusyReason {
				return fmt.Errorf("package change during the dpkg-locked window was not an explicit native-busy hold: %s %q %s", resource.GetDisposition(), resource.GetReason(), action.GetStatus())
			}
			_, err = resourceOracle(ctx, u.vm, "window-package-unchanged", "test \"$(dpkg-query -W -f='${Version}' "+resourcePackageName+")\" = 1.0-1; dpkg-query -W -f='${Package} ${Version}\\n' "+resourcePackageName)
			return err
		}
		if err := lifecycleDelay(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("package change outcome was not recorded during the window: %w", err)
		}
	}
}

func (u *releaseUpgrade) waitUpgrader(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Minute)
	defer cancel()
	for {
		data, err := u.vm.run(ctx, "systemctl show -p ActiveState -p SubState -p Result -p ExecMainStatus "+releaseUpgradeUnit, nil, 1024, 15*time.Second)
		if err != nil {
			return fmt.Errorf("observe vendor release upgrader: %w", err)
		}
		state := string(data)
		if strings.Contains(state, "SubState=exited") || strings.Contains(state, "ActiveState=failed") {
			if !strings.Contains(state, "Result=success") || !strings.Contains(state, "ExecMainStatus=0\n") {
				return fmt.Errorf("vendor release upgrader failed: %s", strings.Join(strings.Fields(state), " "))
			}
			return nil
		}
		if err := lifecycleDelay(ctx, 15*time.Second); err != nil {
			return fmt.Errorf("vendor release upgrader did not finish: %w", err)
		}
	}
}
