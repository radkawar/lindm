// SPDX-License-Identifier: Apache-2.0

package demolab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	labv1 "lindm/gen/lindm/lab/v1"
)

func demoFixture(t *testing.T) *Spec {
	t.Helper()
	spec, err := Load("../../lab/demo/org-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func writeSpec(t *testing.T, document *labv1.DemoSpec) string {
	t.Helper()
	data, err := protojson.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "demo.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// These are synthetic ledger records for admission decisions only, never native
// qualification claims or evidence committed to the real ledger.
func qualifiedFixture(spec *Spec) *labv1.MatrixLedger {
	ledger := new(labv1.MatrixLedger)
	for _, device := range spec.Devices {
		for _, cell := range []string{"encrypted", "assistance"} {
			if cell == "assistance" && !device.Config.GetAssistance() {
				continue
			}
			ledger.Entries = append(ledger.Entries, &labv1.MatrixLedgerEntry{
				Platform: device.Release.Key, Architecture: device.Architecture,
				Cell: cell, Manifest: device.Manifest.GetId(),
				Verdict:  labv1.MatrixVerdict_MATRIX_VERDICT_PASS,
				Evidence: "unit-test-only.json", Sha256: strings.Repeat("a", 64),
				Recorded: timestamppb.New(time.Unix(100, 0)), Revision: "unit-test",
				Source: labv1.MatrixSource_MATRIX_SOURCE_RUN, Verified: true,
			})
		}
	}
	return ledger
}
