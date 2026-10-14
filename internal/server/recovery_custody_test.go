// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
	"time"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/serverops"
)

func TestRecoveryCustodyProjectionBindsCurrentConfiguration(t *testing.T) {
	expected := serverops.BackupIdentity{DeploymentID: "11111111-1111-4111-8111-111111111111", PublicURL: "https://control.invalid", DevicePublicURL: "https://devices.invalid", ConfigSHA256: strings.Repeat("a", 64)}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	base := serverops.RecoveryCustodyHealth{DeploymentID: expected.DeploymentID, PublicURL: expected.PublicURL, DevicePublicURL: expected.DevicePublicURL, ConfigSHA256: expected.ConfigSHA256, ConfirmationSHA256: strings.Repeat("b", 64), CreatedAt: now, RequiresExport: true, Exports: []serverops.RecoveryCustodyExport{{Kind: "canonical_authority", Path: serverops.RecoveryCustodyBundlePath, SHA256: strings.Repeat("d", 64), Present: true}}}
	for _, tc := range []struct {
		name     string
		change   func(*serverops.RecoveryCustodyHealth)
		mismatch bool
		external bool
	}{
		{name: "pending creation"},
		{name: "cipher moved", change: func(h *serverops.RecoveryCustodyHealth) { h.Exports[0].Present = false }},
		{name: "another deployment", change: func(h *serverops.RecoveryCustodyHealth) { h.DeploymentID = "22222222-2222-4222-8222-222222222222" }, mismatch: true},
		{name: "another console origin", change: func(h *serverops.RecoveryCustodyHealth) { h.PublicURL = "https://other.invalid" }, mismatch: true},
		{name: "another device origin", change: func(h *serverops.RecoveryCustodyHealth) { h.DevicePublicURL = "https://other-devices.invalid" }, mismatch: true},
		{name: "another config", change: func(h *serverops.RecoveryCustodyHealth) { h.ConfigSHA256 = strings.Repeat("c", 64) }, mismatch: true},
		{name: "explicit external recipients", change: func(h *serverops.RecoveryCustodyHealth) {
			h.External = true
			h.RequiresExport = false
			h.ConfirmationSHA256 = ""
			h.Exports = nil
		}, external: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			health := base
			health.Exports = append([]serverops.RecoveryCustodyExport(nil), base.Exports...)
			if tc.change != nil {
				tc.change(&health)
			}
			custody, err := recoveryCustodyProjection(health, expected)
			if tc.mismatch {
				if err == nil || custody != nil {
					t.Fatal("foreign creation record became custody evidence")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING
			if tc.external {
				want = adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_EXTERNAL_RECIPIENTS
			}
			if custody.State != want || custody.CanConfirm || custody.ConfirmedAt != nil || !custody.RecordedAt.AsTime().Equal(now) {
				t.Fatalf("creation record invented owner custody: %v", custody)
			}
			if !tc.external && (custody.ConfirmationDigest != health.ConfirmationSHA256 || len(custody.Exports) != 1 || custody.Exports[0].Sha256 != health.Exports[0].SHA256 || custody.Exports[0].Path != health.Exports[0].Path || custody.Exports[0].LocalPresent != health.Exports[0].Present) {
				t.Fatal("current required export set changed")
			}
		})
	}
}

func TestRecoveryCustodyProjectionRetainsSourceAndFreshDatabaseExports(t *testing.T) {
	expected := serverops.BackupIdentity{DeploymentID: "11111111-1111-4111-8111-111111111111", PublicURL: "https://control.invalid", DevicePublicURL: "https://devices.invalid", ConfigSHA256: strings.Repeat("a", 64)}
	health := serverops.RecoveryCustodyHealth{
		DeploymentID: expected.DeploymentID, PublicURL: expected.PublicURL, DevicePublicURL: expected.DevicePublicURL, ConfigSHA256: expected.ConfigSHA256,
		CreatedAt: time.Now(), RequiresExport: true, ConfirmationSHA256: strings.Repeat("c", 64),
		Exports: []serverops.RecoveryCustodyExport{
			{Kind: "canonical_authority", Path: serverops.RecoveryCustodyBundlePath, SHA256: strings.Repeat("d", 64)},
			{Kind: "fresh_database", Path: "/var/lib/lindmd-operations/database-custody/" + strings.Repeat("e", 64) + "/identities.age", SHA256: strings.Repeat("f", 64), Present: true},
		},
	}
	custody, err := recoveryCustodyProjection(health, expected)
	if err != nil {
		t.Fatal(err)
	}
	if custody.ConfirmationDigest != health.ConfirmationSHA256 || len(custody.Exports) != 2 || custody.Exports[0].LocalPresent || !custody.Exports[1].LocalPresent {
		t.Fatal("restore omitted fresh database export or confused custody with local ciphertext presence")
	}
	for i, export := range custody.Exports {
		if export.Sha256 != health.Exports[i].SHA256 || export.Path != health.Exports[i].Path || export.Sha256 == custody.ConfirmationDigest {
			t.Fatal("composite confirmation digest became an individual file checksum")
		}
	}
	if custody.Exports[1].Kind != adminv1.RecoveryKeyCustodyExportKind_RECOVERY_KEY_CUSTODY_EXPORT_KIND_FRESH_DATABASE {
		t.Fatal("fresh database recovery identity lost its actionable purpose")
	}
}
