// SPDX-License-Identifier: Apache-2.0

package db

import (
	"testing"
	"testing/fstest"
)

func TestSchemaCompatibilityRequiresReviewedExactHistory(t *testing.T) {
	for _, test := range []struct {
		name         string
		expected     []int64
		history      map[int64]bool
		policy       *compatibilityPolicy
		declarations map[int64]int64
		compatible   bool
		online       bool
		wantError    bool
	}{
		{"legacy exact", []int64{1, 2}, map[int64]bool{1: true, 2: true}, nil, nil, true, true, false},
		{"legacy newer rejected", []int64{1}, map[int64]bool{1: true, 2: true}, nil, nil, false, false, false},
		{"legacy unknown below maximum", []int64{1, 3}, map[int64]bool{1: true, 2: true, 3: true}, nil, nil, false, false, true},
		{"policy unknown below maximum", []int64{1, 3}, map[int64]bool{1: true, 2: true, 3: true}, &compatibilityPolicy{1, []int64{1, 2, 3}}, nil, false, false, true},
		{"initial policy fenced", []int64{1, 2}, map[int64]bool{1: true}, nil, nil, false, false, false},
		{"pre-policy cutover fenced", []int64{48, 49, 50}, map[int64]bool{48: true}, nil, map[int64]int64{50: 49}, false, false, false},
		{"introduced policy missing", []int64{48, 49, 50}, map[int64]bool{48: true, 49: true, 50: true}, nil, nil, false, false, true},
		{"reviewed rollback", []int64{1, 2}, map[int64]bool{1: true, 2: true, 3: true}, &compatibilityPolicy{2, []int64{1, 2, 3}}, nil, true, true, false},
		{"contract rejects rollback", []int64{1, 2}, map[int64]bool{1: true, 2: true, 3: true}, &compatibilityPolicy{3, []int64{1, 2, 3}}, nil, false, false, false},
		{"missing embedded migration", []int64{1, 2}, map[int64]bool{1: true, 3: true}, &compatibilityPolicy{1, []int64{1, 3}}, nil, false, false, false},
		{"reviewed expand online", []int64{1, 2, 3}, map[int64]bool{1: true, 2: true}, &compatibilityPolicy{2, []int64{1, 2}}, map[int64]int64{3: 2}, false, true, false},
		{"unreviewed expand fenced", []int64{1, 2, 3}, map[int64]bool{1: true, 2: true}, &compatibilityPolicy{2, []int64{1, 2}}, nil, false, false, false},
		{"history forged outside policy", []int64{1, 2}, map[int64]bool{1: true, 2: true, 3: true}, &compatibilityPolicy{2, []int64{1, 2}}, nil, false, false, true},
		{"history gap outside policy", []int64{1, 2}, map[int64]bool{1: true, 3: true}, &compatibilityPolicy{1, []int64{1, 2, 3}}, nil, false, false, true},
		{"missing compatibility floor", []int64{1, 2}, map[int64]bool{1: true, 2: true}, &compatibilityPolicy{3, []int64{1, 2}}, nil, false, false, true},
		{"out of order policy", []int64{1, 2}, map[int64]bool{1: true, 2: true}, &compatibilityPolicy{1, []int64{2, 1}}, nil, false, false, true},
		{"duplicate policy", []int64{1, 2}, map[int64]bool{1: true, 2: true}, &compatibilityPolicy{1, []int64{1, 2, 2}}, nil, false, false, true},
		{"expand needs newer runtime", []int64{1, 2, 3}, map[int64]bool{1: true, 2: true}, &compatibilityPolicy{2, []int64{1, 2}}, map[int64]int64{3: 3}, false, false, false},
		{"reverted version requires migrate", []int64{1, 2}, map[int64]bool{1: true, 2: false}, &compatibilityPolicy{1, []int64{1}}, map[int64]int64{2: 1}, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, err := evaluateSchema(test.expected, test.history, test.policy, test.declarations)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, want error %v", err, test.wantError)
			}
			if err == nil && (status.Compatible != test.compatible || status.Online != test.online) {
				t.Fatalf("status = %+v, want compatible %v online %v", status, test.compatible, test.online)
			}
		})
	}
}

func TestOnlineMigrationDeclarationRejectsInvalidOrDuplicateFloor(t *testing.T) {
	for _, test := range []struct {
		content   string
		wantError bool
	}{
		{"-- lindm:online-compatible minimum-runtime=2\n-- +goose Up\n", false},
		{"-- +goose Up\n", false},
		{"-- lindm:online-compatible minimum-runtime=0\n", true},
		{"-- lindm:online-compatible minimum-runtime=3\n", true},
		{"-- lindm:online-compatible minimum-runtime=wrong\n", true},
		{"-- lindm:online-compatible minimum-runtime=2\n-- lindm:online-compatible minimum-runtime=2\n", true},
	} {
		_, err := onlineDeclarations(fstest.MapFS{"00003_expand.sql": &fstest.MapFile{Data: []byte(test.content)}}, nil)
		if (err != nil) != test.wantError {
			t.Errorf("content %q: error = %v, want error %v", test.content, err, test.wantError)
		}
	}
}

func TestSchemaPreflightReportsContractRollbackFloor(t *testing.T) {
	status, err := evaluateSchema([]int64{1, 2, 3}, map[int64]bool{1: true, 2: true}, &compatibilityPolicy{2, []int64{1, 2}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status.Floor != 3 || status.Online {
		t.Fatalf("contract preflight = %+v, want fenced migration with floor 3", status)
	}
}
