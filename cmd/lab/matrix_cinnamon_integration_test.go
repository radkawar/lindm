// SPDX-License-Identifier: Apache-2.0

//go:build linux && integration

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
	"lindm/internal/vmlab"
)

// Exercise the real child-process -> record classifier -> atomic ledger ->
// planner path. The controlled child is only an accounting test seam: these
// fixtures are not evidence that any native package, VM or desktop passed.
func TestCinnamonMatrixProcessLedgerAccounting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gated  bool
		exit   int
		mutate func(*vmlab.VMDeviceActionsResult)
		want   labv1.MatrixVerdict
		state  labmatrix.State
	}{
		{"fixed native proof", false, 0, nil, labv1.MatrixVerdict_MATRIX_VERDICT_PASS, labmatrix.Pass},
		{"stock 6.6 prerequisite", true, cinnamonLockGateExitCode, nil, labv1.MatrixVerdict_MATRIX_VERDICT_GATED, labmatrix.Gated},
		{"gate record with stdout IO failure", true, 1, nil, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, labmatrix.Fail},
		{"native cleanup failure", false, 1, func(r *vmlab.VMDeviceActionsResult) { r.Passed = false; r.Failure = "native cleanup failed" }, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, labmatrix.Fail},
		{"partial proof with Passed true", false, 0, func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.AfterPAM = nil }, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, labmatrix.Fail},
		{"wrong native phase", false, 0, func(r *vmlab.VMDeviceActionsResult) { r.WipePhase = "live-actions" }, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, labmatrix.Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "lab", "images"), 0o700); err != nil {
				t.Fatal(err)
			}
			evidence := filepath.Join(root, "evidence")
			if err := os.Mkdir(evidence, 0o700); err != nil {
				t.Fatal(err)
			}
			c := cinnamonMatrixCell(t)
			manifest := func(id, edition string) *labmatrix.Manifest {
				t.Helper()
				data := []byte(fmt.Sprintf(`{"id":%q}`, id))
				path := filepath.Join("lab", "images", id+".json")
				if err := os.WriteFile(filepath.Join(root, path), data, 0o600); err != nil {
					t.Fatal(err)
				}
				return &labmatrix.Manifest{Path: path, Image: &labv1.ImageManifest{Id: id, Edition: edition}, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Release: c.Release, Architecture: c.Architecture}
			}
			c.Manifest, c.Recovery = manifest("mint-encrypted", "encrypted-lab"), manifest("mint-cloud", "cloud")
			result := cinnamonRecordFixture(t, tc.gated)
			if tc.mutate != nil {
				tc.mutate(result)
			}
			fixture := writeCinnamonRecord(t, result)
			child := filepath.Join(root, "accounting-child")
			script := fmt.Sprintf("#!/bin/sh\nset -eu\nrecord=''\nwhile [ \"$#\" -gt 0 ]; do\n case \"$1\" in -record) shift; record=$1;; esac\n shift\ndone\n[ -n \"$record\" ]\ncp %q \"$record\"\nexit %d\n", fixture, tc.exit)
			if err := os.WriteFile(child, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			run := &matrixRun{root: root, evidence: evidence, self: child, revision: "accounting-fixture"}
			err := run.cell(context.Background(), c, io.Discard)
			if (err != nil) != (tc.want != labv1.MatrixVerdict_MATRIX_VERDICT_PASS) {
				t.Fatalf("cell error %v for %v", err, tc.want)
			}
			ledger, err := labmatrix.LoadLedger(filepath.Join(root, labmatrix.LedgerFile))
			if err != nil {
				t.Fatal(err)
			}
			if len(ledger.GetEntries()) != 1 {
				t.Fatalf("ledger entries: %d", len(ledger.GetEntries()))
			}
			entry := ledger.GetEntries()[0]
			if entry.GetVerdict() != tc.want || entry.GetScope() != labmatrix.CinnamonLockConfirmationScope || !entry.GetVerified() || (entry.GetGateReason() != "") != (tc.want == labv1.MatrixVerdict_MATRIX_VERDICT_GATED) {
				t.Fatalf("incorrect native accounting: %+v", entry)
			}
			in := &labmatrix.Inputs{Manifests: []*labmatrix.Manifest{c.Manifest, c.Recovery}, Ledger: ledger}
			planned := in.Plan([]*platform.Release{c.Release}, []*labv1.MatrixCell{c.Spec})
			if len(planned) != 1 || planned[0].State != tc.state || !planned[0].Runnable() {
				t.Fatalf("recorded outcome lost retryability or scope: %+v", planned)
			}
		})
	}
}
