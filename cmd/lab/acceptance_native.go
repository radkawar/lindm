//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/labhost"
	"lindm/internal/vmlab"
)

type acceptanceNativeRecord struct {
	Image               string                         `json:"image"`
	DeviceID            string                         `json:"device_id,omitempty"`
	CredentialID        string                         `json:"credential_id,omitempty"`
	InventoryHealthy    bool                           `json:"inventory_healthy"`
	ProfileNativeEffect bool                           `json:"profile_native_effect"`
	ExposureKnown       bool                           `json:"exposure_known"`
	ExposureReason      string                         `json:"exposure_reason,omitempty"`
	Evidence            *vmlab.AcceptanceGuestEvidence `json:"evidence,omitempty"`
	Observation         *vmlab.AcceptanceObservation   `json:"observation,omitempty"`
	Browser             *acceptanceBrowser             `json:"browser,omitempty"`
	Failure             string                         `json:"failure,omitempty"`
}

func runAcceptanceNative(ctx context.Context, fixture *devlab.AuthorityFixture, options acceptanceOptions, private string, browserConfig acceptanceBrowserConfig, browser acceptanceBrowser) ([]acceptanceNativeRecord, error) {
	config, err := labhost.Load()
	if err != nil {
		return nil, err
	}
	hosts, err := labhost.Select(config, &labhost.Requirements{Host: options.host, Architecture: "amd64", Vcpus: 2, MemoryMib: 4096, RequireKVM: true})
	if err != nil {
		return nil, err
	}
	host := hosts[0]
	if host.Transport != "local" || host.Runtime == "container" {
		return nil, errors.New("acceptance requires browser drivers, fixture PostgreSQL and native images on the selected host; invoke the maintained acceptance command in that host's checkout")
	}
	// This release gate never consumes more than one slot, and never raises the
	// shared workstation's explicit ceiling of three simultaneous native guests.
	if host.MaxGuests > 3 {
		host.MaxGuests = 3
	}
	slots, err := labhost.OpenSlots(host)
	if err != nil {
		return nil, err
	}
	if options.work == "" {
		options.work, err = labhost.ResolveWorkDirectory(host)
		if err != nil {
			return nil, err
		}
	}
	var records []acceptanceNativeRecord
	var failures error
	for i, image := range []string{"ubuntu-noble-amd64.json", "fedora-44-x86_64.json", "ubuntu-noble-encrypted-amd64.json"} {
		record := acceptanceNativeRecord{Image: image}
		manifest, err := vmlab.LoadManifest(filepath.Join(options.repository, "lab/images", image))
		if err != nil {
			return records, errors.Join(failures, err)
		}
		guestOptions := vmlab.AcceptanceGuestOptions{Manifest: manifest, Repository: options.repository, LabBinary: options.labBinary, CacheDir: options.cache, WorkDir: options.work}
		if i == 2 {
			guestOptions.Encrypted = &vmlab.EncryptedVMOptions{CacheDir: options.cache, GoldenDir: options.golden, WorkDir: options.work, Firmware: vmlab.EncryptedFirmwareOptions{Code: options.firmwareCode, Vars: options.firmwareVars, Package: options.firmwarePackage, Version: options.firmwareVersion}, Hardware: &vmlab.VMHardwareOptions{Accelerator: "kvm", StorageBus: "virtio-blk"}}
		}
		lease, err := slots.Acquire(ctx)
		if err != nil {
			return records, errors.Join(failures, err)
		}
		record.Evidence, err = vmlab.RunAcceptanceGuest(ctx, guestOptions, func(ctx context.Context, guest *vmlab.AcceptanceGuest) (resultErr error) {
			kind, secret := "provisioning", browser.Token.Secret
			record.CredentialID = browser.Token.ID
			if i == 0 {
				// Queueing for a host lease may exceed a one-time code's lifetime.
				// Issue through the UI only after this guest is ready to enroll.
				cfg := browserConfig
				cfg.Mode = "grant"
				cfg.EvidenceDirectory = filepath.Join(options.evidence, "native-grant")
				cfg.ResultPath = filepath.Join(private, "native-grant.json")
				fresh, issueErr := runAcceptanceBrowser(ctx, options.repository, private, cfg)
				if issueErr != nil {
					return issueErr
				}
				kind, secret = "grant", fresh.Grant.Secret
				record.CredentialID = fresh.Grant.ID
			}
			deviceID, err := guest.Enroll(ctx, fixture, kind, []byte(secret))
			if err != nil {
				return err
			}
			record.DeviceID = deviceID
			owner, err := fixture.OpenOwnerSession(ctx)
			if err != nil {
				return err
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				resultErr = errors.Join(resultErr, owner.Close(cleanup))
			}()
			observation, err := guest.Observe(ctx, owner)
			record.Observation = observation
			resultErr = errors.Join(resultErr, err)
			if observation != nil {
				healthErr := errors.Join(vmlab.CheckInventoryHealth(observation.Host, observation.Packages), vmlab.CheckInventoryHealth(observation.Detail.GetHost().GetObservation(), observation.Packages))
				record.InventoryHealthy = healthErr == nil
				resultErr = errors.Join(resultErr, healthErr)
			}
			if _, err := guest.PrepareServiceProbe(ctx); err != nil {
				return errors.Join(resultErr, err)
			}
			revision, err := acceptanceProfile(ctx, owner, manifest.GetId())
			if err != nil {
				return errors.Join(resultErr, err)
			}
			cfg := browserConfig
			cfg.Mode, cfg.DeviceID, cfg.ProfileRevisionID = "native", deviceID, revision
			cfg.EvidenceDirectory = filepath.Join(options.evidence, "native-"+manifest.GetId())
			cfg.ResultPath = filepath.Join(private, "native-"+manifest.GetId()+".json")
			cfg.StorageActions = []string{}
			cfg.StorageNotApplicableReason = "no_luks_in_native_inventory"
			if i == 2 {
				cfg.StorageActions = []string{"escrowRotate", "cryptoErase", "tpm2Bind"}
				cfg.RequireNoWWN = true
				cfg.StorageNotApplicableReason = ""
			}
			nativeBrowser, err := runAcceptanceBrowser(ctx, options.repository, private, cfg)
			nativeBrowser.Grant.Secret, nativeBrowser.Token.Secret = "", ""
			record.Browser = &nativeBrowser
			resultErr = errors.Join(resultErr, err)
			if nativeBrowser.Assignment != nil {
				effectErr := guest.VerifyServiceEffect(ctx, true, true)
				record.ProfileNativeEffect = effectErr == nil
				resultErr = errors.Join(resultErr, effectErr)
			}
			if options.skipFeeds {
				record.ExposureReason = "feed_refresh_omitted_diagnostic_not_release_qualified"
				return resultErr
			}
			findings, err := owner.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: deviceID, PageSize: 1}))
			if err != nil {
				return errors.Join(resultErr, err)
			}
			freshness := findings.Msg.GetFreshness()
			record.ExposureReason = freshness.GetReason()
			record.ExposureKnown = freshness.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR || freshness.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED
			if !record.ExposureKnown {
				resultErr = errors.Join(resultErr, fmt.Errorf("device exposure remains unknown: %s", record.ExposureReason))
			}
			return resultErr
		})
		err = errors.Join(err, lease.Close())
		if err != nil {
			record.Failure = err.Error()
			failures = errors.Join(failures, fmt.Errorf("%s: %w", image, err))
		}
		records = append(records, record)
	}
	return records, failures
}

// Each guest publishes its own profile head; the image-qualified name keeps the
// console's catalog labels unambiguous for the visible-option selection.
func acceptanceProfile(ctx context.Context, owner *devlab.OwnerSession, image string) (string, error) {
	response, err := owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{
		RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "release acceptance native service effect",
		Spec: &policyv1.ResourceProfile{Name: "Acceptance service effect " + image, Resources: []*policyv1.ProfileResource{{
			ResourceId:   uuid.NewString(),
			Desired:      &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: vmlab.AcceptanceServiceProbeUnit}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: vmlab.AcceptanceServiceProbeUnit, Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED}}},
			Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN},
			Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
		}}},
	}))
	if err != nil {
		return "", err
	}
	return response.Msg.GetRevision().GetRevisionId(), nil
}
