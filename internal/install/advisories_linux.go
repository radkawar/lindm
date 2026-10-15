// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	configv1 "lindm/gen/lindm/config/v1"
)

func nativeAdvisoryDefaults(airgap bool) *configv1.AdvisoryConfig {
	return &configv1.AdvisoryConfig{RefreshEnabled: !airgap, AutomaticInventoryFeeds: !airgap}
}

// Only a missing message and a recorded connected mode permit an upgrade to
// acquire network policy. Even an explicitly empty message is operator policy.
func applyNativeAdvisoryDefaults(cfg *configv1.ServerConfig, airgap *bool) bool {
	if cfg.GetAdvisories() != nil || airgap == nil {
		return false
	}
	cfg.Advisories = nativeAdvisoryDefaults(*airgap)
	return true
}

func enableNativeAdvisoryUpgrade(airgap *bool) error {
	if airgap == nil {
		return nil
	}
	uid, _, err := account("lindmd")
	if err != nil {
		return err
	}
	muid, _, err := account("lindmd-migrate")
	if err != nil {
		return err
	}
	return enableNativeAdvisoriesAt("/etc/lindm/server.json", "/etc/lindm/migrate/server.json", uid, muid, airgap)
}

func enableNativeAdvisoriesAt(runtimePath, migrationPath string, uid, muid int, airgap *bool) error {
	for _, target := range []struct {
		path string
		uid  int
	}{{runtimePath, uid}, {migrationPath, muid}} {
		cfg, before, err := loadNativeConfig(target.path, target.uid)
		if err != nil {
			return err
		}
		if applyNativeAdvisoryDefaults(cfg, airgap) {
			if err := replaceNativeConfig(target.path, cfg, before); err != nil {
				return err
			}
		}
	}
	return nil
}
