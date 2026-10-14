// SPDX-License-Identifier: Apache-2.0

package labmatrix

import (
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestProductionSigningCellCountsOnlyVerifiedTestsScope(t *testing.T) {
	r := release(t, "ubuntu-24.04")
	manifest := &Manifest{Image: &labv1.ImageManifest{Id: "ubuntu"}, Release: r, Architecture: "x86_64"}
	spec := &labv1.MatrixCell{Name: "production-release-signing", Lane: "production-release-signing", Image: labv1.MatrixImage_MATRIX_IMAGE_CLOUD, Capabilities: []string{"packages"}}
	for _, scope := range []string{"", "first-run-install-only", "lifecycle", "production-signing-tests-only"} {
		for _, verified := range []bool{false, true} {
			e := entry(r.Key, spec.Name, "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, time.Now())
			e.Scope, e.Verified = scope, verified
			in := &Inputs{Manifests: []*Manifest{manifest}, Ledger: &labv1.MatrixLedger{Entries: []*labv1.MatrixLedgerEntry{e}}}
			c := in.cell(r, spec, "x86_64")
			if got, want := c.State == Pass, scope == "production-signing-tests-only" && verified; got != want {
				t.Errorf("scope=%q verified=%t state=%s", scope, verified, c.State)
			}
		}
	}
}
