// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/recoveryboot"
	"lindm/internal/agent/recoverycustody"
	"lindm/internal/platform"
)

// RecoveryBootConfig contains resolved root-local paths and pinned release
// artifacts. RPC callers cannot choose any native path, image or signing key.
type RecoveryBootConfig struct {
	ImagePath           string
	ImageSHA256         []byte
	ImageSize           int64
	CertificatePath     string
	CertificateSHA256   []byte
	ESPPath             string
	StateDirectory      string
	Custody             agentv1.RecoveryCustody
	ExpectedPCR11SHA256 []byte
	BootMode            agentv1.RecoveryBootMode
	KernelSHA256        []byte
	SerialConsole       string
}

func WithRecoveryBootConfig(config *RecoveryBootConfig) Option {
	return func(s *Service) {
		if config == nil {
			return
		}
		copy := *config
		copy.ImageSHA256 = bytes.Clone(config.ImageSHA256)
		copy.CertificateSHA256 = bytes.Clone(config.CertificateSHA256)
		copy.ExpectedPCR11SHA256 = bytes.Clone(config.ExpectedPCR11SHA256)
		copy.KernelSHA256 = bytes.Clone(config.KernelSHA256)
		s.recoveryConfig = &copy
	}
}

// recoveryPlanner is intentionally distinct from ordinary native planning. It
// observes an original live root but cannot relax ordinary destructive Apply.
type recoveryPlanner interface {
	PrepareRecovery(context.Context, *agentv1.DeviceActionSpec) (*agentv1.DeviceActionPlan, error)
	RecoveryTargetDevices(context.Context, *agentv1.DeviceActionPlan) ([]string, error)
}

type recoveryBootStaged interface {
	Arm(context.Context, func(context.Context) error) error
	Rollback(context.Context) error
}

type recoveryTPMStore interface {
	Snapshot() ([]byte, error)
	Check(context.Context) error
	Close() error
}

type recoveryTPMPending interface {
	PublicKey() ed25519.PublicKey
	Check(context.Context) error
	Seal(context.Context, *agentv1.DeviceActionRecoveryHandoff, []byte, *agentv1.RecoveryJournal) (recoveryTPMStore, error)
	Close() error
}

type recoveryPendingAction struct {
	actionID string
	key      recoveryTPMPending
}

type nativeRecoveryPending struct{ *recoverycustody.Pending }

func (p nativeRecoveryPending) Seal(ctx context.Context, handoff *agentv1.DeviceActionRecoveryHandoff, pcr11 []byte, initial *agentv1.RecoveryJournal) (recoveryTPMStore, error) {
	store, err := p.Pending.Seal(ctx, handoff, pcr11, initial)
	if store == nil {
		return nil, err
	}
	return store, err
}

func (s *Service) generateRecoveryTPM() (recoveryTPMPending, error) {
	if s.recoveryTPM != nil {
		return s.recoveryTPM()
	}
	pending, err := recoverycustody.Generate()
	if err != nil {
		return nil, err
	}
	return nativeRecoveryPending{pending}, nil
}

type recoveryBootPlatform interface {
	Preflight(context.Context, recoveryboot.StageRequest) error
	ProvisionKey(string) (ed25519.PrivateKey, error)
	PrepareMeasured(context.Context, recoveryboot.StageRequest) (*agentv1.RecoveryMeasuredBoot, error)
	Stage(context.Context, recoveryboot.StageRequest) (recoveryBootStaged, error)
	Reboot(context.Context) error
	WriteCapsule(string, string, []byte) (string, []byte, error)
}

type nativeRecoveryBoot struct{}

func (nativeRecoveryBoot) Preflight(ctx context.Context, request recoveryboot.StageRequest) error {
	return recoveryboot.Preflight(ctx, request)
}
func (nativeRecoveryBoot) ProvisionKey(path string) (ed25519.PrivateKey, error) {
	return recoveryboot.ProvisionKey(path)
}
func (nativeRecoveryBoot) PrepareMeasured(ctx context.Context, request recoveryboot.StageRequest) (*agentv1.RecoveryMeasuredBoot, error) {
	return recoveryboot.PrepareMeasured(ctx, request)
}
func (nativeRecoveryBoot) Stage(ctx context.Context, request recoveryboot.StageRequest) (recoveryBootStaged, error) {
	return recoveryboot.Stage(ctx, request)
}
func (nativeRecoveryBoot) Reboot(ctx context.Context) error { return recoveryboot.Reboot(ctx) }
func (nativeRecoveryBoot) WriteCapsule(directory, actionID string, snapshot []byte) (string, []byte, error) {
	return recoveryboot.WriteCapsule(directory, actionID, snapshot)
}

func (s *Service) recoveryPlatform() recoveryBootPlatform {
	if s.recoveryBoot != nil {
		return s.recoveryBoot
	}
	return nativeRecoveryBoot{}
}

func (s *Service) recoveryStageRequest(intent *agentv1.DeviceActionIntent, boot string, devices []string) (recoveryboot.StageRequest, error) {
	cfg, recovery := s.recoveryConfig, intent.GetSpec().GetSanitize().GetRecovery()
	if cfg == nil || recovery == nil || recovery.GetBootMode() != cfg.BootMode || !bytes.Equal(cfg.ImageSHA256, recovery.GetImageSha256()) {
		return recoveryboot.StageRequest{}, fmt.Errorf("%w: recovery_boot_spec_mismatch", errResourceRejected)
	}
	if cfg.ImageSize < 0 || s.admit(&agentv1.RecoveryBootConfig{ImageFile: cfg.ImagePath, ImageSha256: cfg.ImageSHA256, ImageSize: uint64(cfg.ImageSize), SignerCertificateFile: cfg.CertificatePath, SignerCertificateSha256: cfg.CertificateSHA256, EspDirectory: cfg.ESPPath, StateDirectory: cfg.StateDirectory, Custody: cfg.Custody, ExpectedPcr11Sha256: cfg.ExpectedPCR11SHA256, BootMode: cfg.BootMode, KernelSha256: cfg.KernelSHA256, SerialConsole: cfg.SerialConsole}) != nil {
		return recoveryboot.StageRequest{}, fmt.Errorf("%w: recovery_boot_config_invalid", errResourceRejected)
	}
	media, err := digestMessage(intent.GetSpec().GetSanitize().GetTarget())
	if err != nil || !bytes.Equal(media, recovery.GetMediaSha256()) {
		return recoveryboot.StageRequest{}, fmt.Errorf("%w: recovery_media_mismatch", errResourceRejected)
	}
	request := recoveryboot.StageRequest{ImagePath: cfg.ImagePath, ImageSHA256: bytes.Clone(cfg.ImageSHA256), ImageSize: cfg.ImageSize, CertificatePath: cfg.CertificatePath, CertificateSHA256: bytes.Clone(cfg.CertificateSHA256), ESPPath: cfg.ESPPath, StateDirectory: cfg.StateDirectory, ActionID: intent.GetActionId(), SourceBootID: boot, TargetDevices: devices, BootMode: cfg.BootMode, KernelSHA256: bytes.Clone(cfg.KernelSHA256), SerialConsole: cfg.SerialConsole}
	if cfg.BootMode == agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB {
		chain := s.recoveryGRUB
		if chain == nil {
			chain = recoveryboot.HostGRUBChain
		}
		if request.GRUB, err = chain(); err != nil {
			return recoveryboot.StageRequest{}, fmt.Errorf("%w: recovery_grub_chain_unavailable: %w", errResourceRejected, err)
		}
		if request.GRUB.Entries != platform.GRUBBLSLoaderEntryOneShot {
			request.GrubEnv = s.grubEnvironment(cfg.ESPPath, request.GRUB)
		}
	}
	return request, nil
}
