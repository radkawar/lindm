package config

import (
	"fmt"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// resolveRecoveryBoot keeps locally provisioned recovery paths relative to the
// protected executor configuration, never the network process working directory.
// Native staging separately verifies ownership, image bytes and off-target media.
func resolveRecoveryBoot(base string, cfg *agentv1.RecoveryBootConfig) error {
	if cfg == nil {
		return nil
	}
	cfg.ImageFile = resolve(base, cfg.GetImageFile())
	// Measured GRUB has no UKI signer. An absent path must stay absent rather
	// than resolve to the configuration directory and fail mode validation.
	if cfg.GetSignerCertificateFile() != "" {
		cfg.SignerCertificateFile = resolve(base, cfg.GetSignerCertificateFile())
	}
	esp, err := canonicalDirectory(resolve(base, cfg.GetEspDirectory()))
	if err != nil {
		return fmt.Errorf("recovery ESP directory: %w", err)
	}
	state, err := canonicalDirectory(resolve(base, cfg.GetStateDirectory()))
	if err != nil {
		return fmt.Errorf("recovery state directory: %w", err)
	}
	cfg.EspDirectory = esp
	cfg.StateDirectory = state
	return nil
}
