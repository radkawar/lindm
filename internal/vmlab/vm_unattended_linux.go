//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/platform"
)

// VMUnattendedOptions selects only owned, disposable native resources.
type VMUnattendedOptions struct {
	Repository, CacheDir, WorkDir, LindmdBinary, LabBinary string
	ApprovalRequired                                       bool
}

// VMUnattendedResult contains public observations only. Successful return means
// every owned VM, package workspace, local session and isolated database closed.
// Assignment receipt is not a claim of native service convergence.
type VMUnattendedResult struct {
	Distribution                     string                      `json:"distribution"`
	Version                          string                      `json:"version"`
	ImageID                          string                      `json:"image_id"`
	ImageSHA256                      string                      `json:"image_sha256"`
	PackageSHA256                    string                      `json:"package_sha256"`
	SignerFingerprint                string                      `json:"signer_fingerprint"`
	ApprovalRequired                 bool                        `json:"approval_required"`
	TokenID                          string                      `json:"token_id"`
	MaxUses                          uint32                      `json:"max_uses"`
	UsedCount                        uint32                      `json:"used_count"`
	ExhaustionReason                 string                      `json:"exhaustion_reason"`
	Devices                          []*unattendedDeviceEvidence `json:"devices"`
	OverallTimeoutSeconds            uint32                      `json:"overall_timeout_seconds"`
	ObservationTimeoutSeconds        uint32                      `json:"observation_timeout_seconds"`
	BootstrapReadinessTimeoutSeconds uint32                      `json:"bootstrap_readiness_timeout_seconds"`
	ApprovalResumeTimeoutSeconds     uint32                      `json:"approval_resume_timeout_seconds"`
	OwnedCleanupComplete             bool                        `json:"owned_cleanup_complete"`
}

type unattendedDeviceEvidence struct {
	DeviceID           string                         `json:"device_id"`
	Generation         string                         `json:"generation"`
	InstallationID     string                         `json:"installation_id"`
	Runtime            *vmRuntimeEvidence             `json:"runtime"`
	Privileges         *labv1.NetworkBoundaryEvidence `json:"privileges"`
	Inventory          *vmInventoryEvidence           `json:"inventory"`
	GroupID            string                         `json:"group_id"`
	ProfileRevisionID  string                         `json:"profile_revision_id"`
	PendingDenied      bool                           `json:"pending_denied"`
	SelfApprovalDenied bool                           `json:"self_approval_denied"`
	ApproverID         string                         `json:"approver_id,omitempty"`
}

const unattendedReason = "native unattended enrollment qualification"

// EnrollUnattendedVM qualifies two fresh native installations and a denied third
// token use against one isolated real authority. It never reuses a shared realm.
func EnrollUnattendedVM(ctx context.Context, manifest *labv1.ImageManifest, options VMUnattendedOptions) (result *VMUnattendedResult, err error) {
	// Registered first, this runs only after all owned-resource cleanup.
	defer func() {
		if err != nil {
			result = nil
		} else if result != nil {
			result.OwnedCleanupComplete = true
		}
	}()
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if err := manifestRelease(manifest).LabLane(platform.LaneUnattended); err != nil {
		return nil, err
	}
	if options.LindmdBinary == "" || options.LabBinary == "" {
		return nil, errors.New("provide prebuilt -lindmd and matching -lab-binary; protected dev trust and live PostgreSQL are required")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenDeviceActionAuthorityFixture(ctx, options.Repository, options.LindmdBinary)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, fixture.Close()) }()
	public, err := fixture.ReadAgentFixture(ctx)
	if err != nil {
		return nil, err
	}
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		err = errors.Join(err, owner.Close(cleanup))
	}()
	approver, err := fixture.OpenApproverSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		err = errors.Join(err, approver.Close(cleanup))
	}()
	if owner.AccountID == approver.AccountID {
		return nil, errors.New("unattended approval requires independently authenticated humans")
	}
	packages, err := buildActionNativePackage(ctx, manifest, options.Repository, options.WorkDir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, packages.Close()) }()
	groupID := uuid.NewString()
	if _, err := owner.Admin.SetDeviceGroup(ctx, connect.NewRequest(&adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: groupID, Name: "Unattended qualification", Reason: unattendedReason})); err != nil {
		return nil, vmControlPlaneError("create enrollment group", err)
	}
	profile, err := owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{
		RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: unattendedReason,
		Spec: &policyv1.ResourceProfile{Name: "Unattended assignment observation", Resources: []*policyv1.ProfileResource{{
			ResourceId: uuid.NewString(),
			Desired: &resourcev1.ResourceDesiredState{
				Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "enrollment-observation.service"},
				State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{
					Unit: "enrollment-observation.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED,
				}},
			},
			Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN},
			Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
		}}},
	}))
	if err != nil {
		return nil, vmControlPlaneError("publish enrollment assignment", err)
	}
	revisionID := profile.Msg.GetRevision().GetRevisionId()
	metadata := &adminv1.DeviceMetadata{Labels: []string{"enrollment-lab"}}
	issued, err := owner.Admin.CreateProvisioningToken(ctx, connect.NewRequest(&adminv1.CreateProvisioningTokenRequest{RequestId: uuid.NewString(), LifetimeSeconds: 3600, MaxUses: 2, ApprovalRequired: options.ApprovalRequired, Reason: unattendedReason, Metadata: metadata, GroupIds: []string{groupID}, ProfileRevisionIds: []string{revisionID}}))
	if err != nil {
		return nil, vmControlPlaneError("issue boot provisioning token", err)
	}
	token := []byte(issued.Msg.GetSecret())
	issued.Msg.Secret = ""
	defer clear(token)
	if len(token) == 0 || issued.Msg.GetSecretDeliveryUnknown() || !vmValidID(issued.Msg.GetTokenId()) {
		return nil, errors.New("provisioning token secret was not delivered; isolated fixture will be destroyed")
	}
	result = &VMUnattendedResult{Distribution: manifest.GetDistribution(), Version: manifest.GetVersion(), ImageID: manifest.GetId(), PackageSHA256: packages.artifact.SHA256, SignerFingerprint: packages.fingerprint, ApprovalRequired: options.ApprovalRequired, TokenID: issued.Msg.GetTokenId(), MaxUses: 2}
	for range 2 {
		evidence, digest, runErr := runUnattendedGuest(ctx, manifest, options, fixture, public, owner, approver, packages, token, result.TokenID, groupID, revisionID, metadata)
		if runErr != nil {
			return nil, runErr
		}
		result.ImageSHA256 = digest
		result.Devices = append(result.Devices, evidence)
	}
	if result.Devices[0].DeviceID == result.Devices[1].DeviceID || result.Devices[0].InstallationID == result.Devices[1].InstallationID {
		return nil, errors.New("reusable token merged distinct guest identities")
	}
	result.ExhaustionReason, err = probeUnattendedExhaustion(ctx, public, token)
	if err != nil {
		return nil, err
	}
	listed, err := owner.Admin.ListProvisioningTokens(ctx, connect.NewRequest(&adminv1.ListProvisioningTokensRequest{PageSize: 200}))
	if err != nil {
		return nil, vmControlPlaneError("observe token usage", err)
	}
	for _, observed := range listed.Msg.GetTokens() {
		if observed.GetTokenId() == result.TokenID {
			if observed.GetMaxUses() != 2 || observed.GetUsedCount() != 2 || observed.GetApprovalRequired() != options.ApprovalRequired || !proto.Equal(observed.GetMetadata(), metadata) || !slices.Equal(observed.GetGroupIds(), []string{groupID}) || !slices.Equal(observed.GetProfileRevisionIds(), []string{revisionID}) {
				return nil, errors.New("provisioning usage or immutable assignments changed")
			}
			result.UsedCount = observed.GetUsedCount()
		}
	}
	if result.UsedCount != 2 {
		return nil, errors.New("owned token absent from isolated usage observation")
	}
	if _, err := owner.Admin.RevokeProvisioningToken(ctx, connect.NewRequest(&adminv1.RevokeProvisioningTokenRequest{RequestId: uuid.NewString(), TokenId: result.TokenID, Reason: unattendedReason})); err != nil {
		return nil, vmControlPlaneError("revoke owned token", err)
	}
	result.OverallTimeoutSeconds, result.ObservationTimeoutSeconds = 3600, 300
	result.BootstrapReadinessTimeoutSeconds, result.ApprovalResumeTimeoutSeconds = 600, 600
	return result, nil
}

func runUnattendedGuest(ctx context.Context, manifest *labv1.ImageManifest, options VMUnattendedOptions, fixture *devlab.AuthorityFixture, public *devlab.AgentFixture, owner, approver *devlab.OwnerSession, packages *actionNativePackage, token []byte, tokenID, groupID, revisionID string, metadata *adminv1.DeviceMetadata) (_ *unattendedDeviceEvidence, _ string, err error) {
	vm, image, err := newVerifiedSeededGuest(ctx, manifest, options.CacheDir, options.WorkDir, false, nil, &unattendedSeed{root: public.ExecutionRootJSON, bundle: public.BootstrapEnvelope, token: token, approvalRequired: options.ApprovalRequired})
	if err != nil {
		return nil, "", err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	if err := vm.connect(ctx); err != nil {
		return nil, "", err
	}
	result := &unattendedDeviceEvidence{GroupID: groupID, ProfileRevisionID: revisionID}
	result.Runtime, err = vm.runtimeEvidence(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := packages.Install(ctx, vm, options.LabBinary); err != nil {
		return nil, "", err
	}
	forwarding, err := connectActionGuest(ctx, vm, fixture)
	if err != nil {
		return nil, "", err
	}
	defer func() { err = errors.Join(err, forwarding.Close()) }()
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED); err != nil {
		return nil, "", err
	}
	if _, err := vm.run(ctx, "sudo -n sh -eu -c 'test \"$(stat -c %u:%a /run/lindm-enrollment-lab/token)\" = 0:600; touch /run/lindm-enrollment-lab/ready'", nil, 1024, 10*time.Second); err != nil {
		return nil, "", errors.New("root-owned cloud-init provisioning material unavailable")
	}
	if err := unattendedPoll(ctx, func(ctx context.Context) (bool, error) {
		output, err := vm.run(ctx, "sudo -n sh -c 'if test -f /run/lindm-enrollment-lab/bootstrap-exit; then cat /run/lindm-enrollment-lab/bootstrap-exit; fi'", nil, 1024, 10*time.Second)
		if err != nil {
			return false, err
		}
		if len(output) != 0 && string(output) != "0\n" {
			return false, errors.New("cloud-init bootstrap failed; inspect protected guest configuration and installed agent compatibility")
		}
		return string(output) == "0\n", nil
	}); err != nil {
		return nil, "", err
	}
	if options.ApprovalRequired {
		if err := approveUnattendedGuest(ctx, vm, owner, approver, tokenID, result); err != nil {
			return nil, "", err
		}
	}
	if err := unattendedPoll(ctx, func(ctx context.Context) (bool, error) {
		output, err := vm.run(ctx, "sudo -n sh -c 'if test -f /run/lindm-enrollment-lab/complete; then printf ready; fi'", nil, 1024, 10*time.Second)
		return string(output) == "ready", err
	}); err != nil {
		return nil, "", err
	}
	status, err := readGuestAgentStatus(ctx, vm)
	if err != nil {
		return nil, "", err
	}
	identity := status.GetExecutor()
	if identity.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_ENROLLED {
		return nil, "", errors.New("cloud-init did not enroll installed agent")
	}
	if options.ApprovalRequired && (result.DeviceID != identity.GetDeviceId() || result.Generation != identity.GetEnrollmentGeneration() || result.InstallationID != identity.GetInstallationId()) {
		return nil, "", errors.New("approval activation changed the reserved native identity")
	}
	result.DeviceID, result.Generation, result.InstallationID = identity.GetDeviceId(), identity.GetEnrollmentGeneration(), identity.GetInstallationId()
	result.Privileges, err = probeGuestPrivileges(ctx, vm)
	if err != nil {
		return nil, "", err
	}
	if result.Privileges.GetDeviceId() != result.DeviceID || result.Privileges.GetEnrollmentGeneration() != result.Generation {
		return nil, "", errors.New("native privilege evidence changed enrolled identity")
	}
	control := &vmControlPlane{session: owner, fixture: public}
	result.Inventory, err = waitLifecycleInventory(ctx, vm, control, manifestRelease(manifest), result.DeviceID, nil)
	if err != nil {
		return nil, "", err
	}
	if result.Inventory.EnrollmentGeneration != result.Generation {
		return nil, "", errors.New("server inventory belongs to a different enrollment generation")
	}
	detail, err := control.GetDevice(ctx, result.DeviceID)
	if err != nil {
		return nil, "", err
	}
	if !proto.Equal(detail.GetDevice().GetMetadata(), metadata) {
		return nil, "", errors.New("enrolled device lost fixed metadata")
	}
	if detail.GetDevice().GetLifecycleState() != adminv1.DeviceState_DEVICE_STATE_ACTIVE {
		return nil, "", errors.New("approved native device did not activate")
	}
	groups, err := owner.Admin.ListDeviceGroups(ctx, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{PageSize: 100}))
	if err != nil {
		return nil, "", vmControlPlaneError("observe assigned group", err)
	}
	found := false
	for _, group := range groups.Msg.GetGroups() {
		if group.GetId() == groupID && slices.Contains(group.GetDeviceIds(), result.DeviceID) {
			found = true
		}
	}
	if !found {
		return nil, "", errors.New("enrolled device missing fixed group assignment")
	}
	service, err := owner.Admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: result.DeviceID}))
	if err != nil {
		return nil, "", vmControlPlaneError("observe assigned profile", err)
	}
	if service.Msg.GetAssignment().GetRevisionId() != revisionID || service.Msg.GetAssignment().GetEnrollmentGeneration() != result.Generation {
		return nil, "", errors.New("enrolled generation missing fixed profile revision")
	}
	if _, err := vm.run(ctx, "sudo -n sh -eu -c 'test ! -e /run/lindm-enrollment-lab/token; test \"$(stat -c %u:%a /run/lindm-enrollment-lab/root.json)\" = 0:600; test \"$(stat -c %u:%a /run/lindm-enrollment-lab/bootstrap.json)\" = 0:600'", nil, 1024, 10*time.Second); err != nil {
		return nil, "", errors.New("cloud-init credential cleanup or bootstrap ownership failed")
	}
	return result, image.SHA256, nil
}

func unattendedPoll(ctx context.Context, observe func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		ready, err := observe(ctx)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("unattended enrollment observation deadline: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
