// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capabilitypolicy

import (
	"context"
	"errors"
	"fmt"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
)

// LoadEffectiveExecutorConfig loads /etc/lindm/executor.json, the executor's
// accepted record and the host, and returns the effective configuration. Every
// root helper and root service that applies provider configuration uses it so
// that executor and helpers derive the same providers.
func LoadEffectiveExecutorConfig(ctx context.Context) (*Effective, error) {
	document, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return nil, err
	}
	record, err := LoadRecord(document.StateDirectory)
	if err != nil {
		return nil, err
	}
	host, err := DetectHost(ctx)
	if err != nil {
		return nil, err
	}
	return Effect(ctx, document, record, host)
}

// Effect derives the effective configuration for a loaded executor document
// and binds it into a document copy: package signing keys are re-read under
// configuration custody and the protected-path overlap checks run on the
// merged providers. When the merge fails those checks, the document keeps the
// local providers only and every remotely derived capability reports
// UNAVAILABLE (protected_path_overlap, or vendor_key_unrecognized when a
// vendor key fails configuration custody): a policy can never widen local
// custody, and an unrelated local setting never stops the executor.
func Effect(ctx context.Context, document *config.Document, record *agentv1.CapabilityPolicyRecord, host Host) (*Effective, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if document == nil || document.Proto == nil {
		return nil, errors.New("capability derivation requires a loaded executor document")
	}
	effective, err := Derive(document.Proto, record, host)
	if err != nil {
		return nil, err
	}
	merged, mergeErr := document.WithProviders(effective.Config)
	if mergeErr == nil {
		effective.Document, effective.Config = merged, merged.Proto
		return effective, nil
	}
	local, err := Derive(document.Proto, nil, host)
	if err != nil {
		return nil, err
	}
	if local.Document, err = document.WithProviders(local.Config); err != nil {
		return nil, fmt.Errorf("local provider configuration: %w", err)
	}
	local.Config = local.Document.Proto
	detail := DetailVendorKeyUnrecognized
	if errors.Is(mergeErr, config.ErrProtectedOverlap) {
		detail = DetailProtectedPathOverlap
	}
	for i, observed := range effective.Status {
		if observed.GetStatus() == agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED {
			local.Status[i] = status(observed.GetCapability(), agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE, detail)
		}
	}
	return local, nil
}
