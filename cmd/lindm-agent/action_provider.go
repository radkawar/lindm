//go:build linux

package main

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/executor"
	"lindm/internal/agent/journal"
	"lindm/internal/escrow"
)

func nativeActionProvider(cfg *agentv1.DeviceActionProviderConfig, store *journal.Store) (*actionprovider.Provider, error) {
	provider, err := actionprovider.New(actionprovider.Options{Config: cfg, AccountJournal: store, SealRecovery: sealActionRecovery})
	if err != nil {
		return nil, err
	}
	// Pin before the executor can decode any plaintext credential RPC or make
	// transient Go-crypto copies; individually locked secret buffers are not enough.
	if actionMemoryRequired(cfg) {
		if err := actionprovider.PinLiveRootMemory(); err != nil {
			return nil, err
		}
	}
	return provider, nil
}

func sealActionRecovery(ctx context.Context, binding *agentv1.RecoveryKeyBinding, spec *agentv1.DeviceActionSpec, secret []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if binding == nil || spec.GetEscrowRotate() == nil || binding.GetLuksUuid() != spec.GetEscrowRotate().GetTarget().GetLuksUuid() {
		return nil, errors.New("recovery binding does not match rotation target")
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(binding)
	if err != nil {
		return nil, err
	}
	return escrow.SealForServer(spec.GetEscrowRotate().GetEscrowPublicKey(), encoded, secret)
}

func recoveryBootConfig(cfg *agentv1.RecoveryBootConfig) *executor.RecoveryBootConfig {
	if cfg == nil {
		return nil
	}
	return &executor.RecoveryBootConfig{
		ImagePath: cfg.GetImageFile(), ImageSHA256: cfg.GetImageSha256(), ImageSize: int64(cfg.GetImageSize()),
		CertificatePath: cfg.GetSignerCertificateFile(), CertificateSHA256: cfg.GetSignerCertificateSha256(),
		ESPPath: cfg.GetEspDirectory(), StateDirectory: cfg.GetStateDirectory(),
		Custody: cfg.GetCustody(), ExpectedPCR11SHA256: cfg.GetExpectedPcr11Sha256(),
	}
}

func actionMemoryRequired(cfg *agentv1.DeviceActionProviderConfig) bool {
	if cfg.GetAllowAccountLock() || cfg.GetAllowLiveRootCryptoErase() || cfg.GetAllowRecoveryHandoff() {
		return true
	}
	for _, target := range cfg.GetTargets() {
		if target.GetAllowRecoveryRotation() || target.GetAllowTpm2Binding() {
			return true
		}
	}
	return false
}
