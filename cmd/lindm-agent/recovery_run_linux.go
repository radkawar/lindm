//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/config"
	"lindm/internal/agent/measuredtpm"
	"lindm/internal/agent/recovery"
	"lindm/internal/agent/recoveryboot"
	"lindm/internal/agent/recoverycustody"
	"lindm/internal/agent/transport"
	"lindm/internal/trust"
)

// recoveryRun is composed only inside the qualified signed recovery image. It
// has no device identity, enrollment, local RPC server or general admin client.
func recoveryRun(ctx context.Context, args []string) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("recovery-run requires root in the signed recovery environment")
	}
	flags := flag.NewFlagSet("recovery-run", flag.ContinueOnError)
	path := flags.String("config", "/etc/lindm/recovery.json", "authenticated recovery image configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("recovery-run accepts only -config FILE")
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("disable recovery core dumps: %w", err)
	}
	if err := actionprovider.PinLiveRootMemory(); err != nil {
		return fmt.Errorf("protect recovery process memory: %w", err)
	}
	document, err := config.LoadRecovery(*path)
	if err != nil {
		return err
	}
	cfg := document.Proto
	verifiedAt := cfg.GetBootstrapVerifiedAt()
	if !verifiedAt.IsValid() {
		return errors.New("invalid authenticated recovery bootstrap admission time")
	}
	authority, err := trust.New()
	if err != nil {
		return err
	}
	// This is restoration of authenticated image provisioning, exactly as the
	// ordinary executor restores its protected BootstrapVerifiedAt. The runtime
	// verifies current authority against nonce-authenticated server time, not RTC.
	bootstrap, err := authority.VerifyBootstrap(ctx, document.ExecutionRoot, document.Bootstrap, verifiedAt.AsTime())
	if err != nil {
		return err
	}
	if cfg.GetServerUrl() != bootstrap.Bundle.GetEnrollmentOrigin() || !bytes.Equal(document.ServerCA, bootstrap.Bundle.GetTransportCaPem()) {
		return errors.New("recovery endpoint does not match authenticated bootstrap transport")
	}
	clock := recovery.NewClock()
	client, closeClient, err := transport.NewRecoveryClient(cfg.GetServerUrl(), document.ServerCA, clock.Bounds)
	if err != nil {
		return err
	}
	defer closeClient()
	bootBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if len(bootBytes) > 64 {
		return errors.New("invalid recovery boot identity")
	}
	bootID := strings.TrimSpace(string(bootBytes))
	var store recovery.StateStore
	var key ed25519.PrivateKey
	providerOptions := actionprovider.Options{Config: cfg.GetProvider()}
	switch cfg.GetCustody() {
	case agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET:
		journal, openErr := recovery.OpenJournal(cfg.GetStateDirectory())
		if openErr != nil {
			return openErr
		}
		defer func() { err = errors.Join(err, journal.Close()) }()
		key, err = recoveryboot.LoadKey(cfg.GetKeyFile())
		if err != nil {
			return err
		}
		defer clear(key)
		store = journal
	case agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM:
		tpm, openErr := recoverycustody.OpenWithSnapshot(ctx, document.Capsule, func(ctx context.Context, signer ed25519.PrivateKey, initial *agentv1.RecoveryJournal, expected []byte) ([]byte, error) {
			return recovery.FetchSnapshot(ctx, recovery.SnapshotOptions{Key: signer, Bootstrap: bootstrap, Client: client, BootID: bootID, Initial: initial, ExpectedSHA256: expected, Clock: clock, ProvisionedAt: verifiedAt.AsTime()})
		})
		if openErr != nil {
			return openErr
		}
		defer func() { err = errors.Join(err, tpm.Close()) }()
		store, key = tpm, tpm.Signer()
		providerOptions.TrustedRecoveryCustody = tpm.CheckAction
	default:
		return errors.New("qualified recovery custody is required")
	}
	journal := new(agentv1.RecoveryJournal)
	found, err := store.Load(journal)
	if err != nil {
		return err
	}
	if !found || journal.GetHandoff() == nil {
		return errors.New("authenticated recovery handoff is missing")
	}
	handoff := journal.GetHandoff()
	var verifiedBoot string
	var attest func(context.Context, []byte) (*recoveryv1.RecoveryAttestation, error)
	switch cfg.GetBootMode() {
	case agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI:
		verifiedBoot, err = recoveryboot.VerifyBoot(ctx, cfg.GetStateDirectory(), handoff.GetIntent().GetActionId(), handoff.GetOriginalBootId(), handoff.GetRecoveryImageSha256(), cfg.GetCertificateSha256())
	case agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB:
		verifiedBoot, err = recoveryboot.VerifyMeasuredBoot(ctx, cfg.GetStateDirectory(), handoff.GetIntent().GetActionId(), handoff.GetOriginalBootId(), handoff.GetMeasuredBoot(), handoff.GetRecoveryImageSha256())
		attest = measuredAttestation(cfg.GetStateDirectory(), handoff.GetMeasuredBoot().GetAttestationKeyPublic())
	default:
		err = errors.New("qualified recovery boot mode is required")
	}
	if err != nil {
		return err
	}
	if verifiedBoot != bootID {
		return errors.New("recovery boot identity changed during custody verification")
	}
	provider, err := actionprovider.New(providerOptions)
	if err != nil {
		return err
	}
	return recovery.Run(ctx, recovery.Options{Journal: store, Key: key, Bootstrap: bootstrap, Client: client, Provider: provider, BootID: verifiedBoot, ImageSHA256: handoff.GetRecoveryImageSha256(), Clock: clock, ProvisionedAt: verifiedAt.AsTime(), Attest: attest})
}

// measuredAttestation quotes PCRs with the TPM-resident key bound by the
// handoff and attaches this boot's firmware event log for server replay.
func measuredAttestation(stateDirectory string, expectedPublic []byte) func(context.Context, []byte) (*recoveryv1.RecoveryAttestation, error) {
	return func(ctx context.Context, qualifyingData []byte) (*recoveryv1.RecoveryAttestation, error) {
		public, private, err := recoveryboot.LoadAttestationKey(stateDirectory, expectedPublic)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		quote, signature, err := measuredtpm.Quote(ctx, public, private, qualifyingData)
		if err != nil {
			return nil, err
		}
		eventLog, err := measuredtpm.ReadEventLog()
		if err != nil {
			return nil, err
		}
		return &recoveryv1.RecoveryAttestation{Quote: quote, Signature: signature, EventLog: eventLog}, nil
	}
}
