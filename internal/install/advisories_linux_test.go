// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func TestNativeAdvisoryDefaultsAndUpgradePolicy(t *testing.T) {
	for _, airgap := range []bool{false, true} {
		cfg := nativeAdvisoryDefaults(airgap)
		if cfg.GetRefreshEnabled() == airgap || cfg.GetAutomaticInventoryFeeds() == airgap || len(cfg.GetFeeds()) != 0 {
			t.Fatalf("mode %t: %v", airgap, cfg)
		}
		server := new(configv1.ServerConfig)
		if !applyNativeAdvisoryDefaults(server, &airgap) || !proto.Equal(server.Advisories, cfg) {
			t.Fatalf("known mode upgrade %t: %v", airgap, server)
		}
		if applyNativeAdvisoryDefaults(server, &airgap) {
			t.Fatal("upgrade rewrote configured policy")
		}
	}
	legacy := new(configv1.ServerConfig)
	if applyNativeAdvisoryDefaults(legacy, nil) || legacy.Advisories != nil {
		t.Fatal("unknown original installation mode acquired network policy")
	}
	connected := false
	for _, policy := range []*configv1.AdvisoryConfig{
		{},
		{RefreshEnabled: false, AutomaticInventoryFeeds: true},
		{RefreshEnabled: true, Feeds: []*advisoryv1.FeedSource{{Id: "operator", Url: "https://vendor.example.invalid/export"}}},
	} {
		server := &configv1.ServerConfig{Advisories: proto.CloneOf(policy)}
		if applyNativeAdvisoryDefaults(server, &connected) || !proto.Equal(server.Advisories, policy) {
			t.Fatal("upgrade replaced explicit advisory authority")
		}
	}
}

func TestNativeAdvisoryUpgradePersistsBothCheckedConfigs(t *testing.T) {
	runtime, migration, _ := nativeIntegrationConfigFixture(t, rootDatabaseFixture(t), nil)
	connected := false
	if err := enableNativeAdvisoriesAt(runtime, migration, 65534, 65534, &connected); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{runtime, migration} {
		cfg, _, err := loadNativeConfig(path, 65534)
		if err != nil || !cfg.GetAdvisories().GetRefreshEnabled() || !cfg.GetAdvisories().GetAutomaticInventoryFeeds() {
			t.Fatalf("upgrade config %s: %v %v", path, cfg, err)
		}
	}
}
