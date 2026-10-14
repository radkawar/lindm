// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"testing"

	"lindm/internal/gendoc"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
)

func TestDocBlocksIncludesRegistryDrivenReadmeSupport(t *testing.T) {
	blocks, err := docBlocks("../..")
	if err != nil {
		t.Fatal(err)
	}
	var body string
	var supportBlocks, verificationBlocks int
	for _, block := range blocks {
		if block.File == "README.md" && block.Name == "readme-support" {
			supportBlocks++
			body = block.Body
		}
		if block.File == "docs/verification.md" && block.Name == "lab-matrix" {
			verificationBlocks++
		}
	}
	if supportBlocks != 1 || verificationBlocks != 1 {
		t.Fatalf("support blocks = %d, verification blocks = %d; want one each", supportBlocks, verificationBlocks)
	}
	releases, err := labmatrix.Platforms(nil)
	if err != nil {
		t.Fatal(err)
	}
	wantRows := 0
	for _, r := range platform.Releases() {
		link := fmt.Sprintf("](%s)", "docs/platforms/"+r.Page)
		prefix := "[" + gendoc.Escape(r.Name) + link
		count := strings.Count(body, prefix)
		if r.Tier != platform.Tier1 && r.Tier != platform.Tier2 {
			if count != 0 {
				t.Errorf("non-target release %s appears in public rows", r.Key)
			}
			continue
		}
		if count != len(r.Architectures) {
			t.Errorf("%s rows = %d, want %d registry architectures", r.Key, count, len(r.Architectures))
		}
		wantRows += len(r.Architectures)
	}
	var actualRows int
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "| [") {
			actualRows++
			if columns := len(strings.Split(line, "|")) - 2; columns != 9 {
				t.Errorf("table has %d columns, want distribution, architecture and seven capabilities", columns)
			}
		}
	}
	if len(releases) == 0 || actualRows != wantRows {
		t.Fatalf("public rows = %d, want %d registry-driven rows", actualRows, wantRows)
	}
	for _, jargon := range []string{"lane", "qualification", "evidence", "ledger", "matrix cell", "gated", "preview target", "lab-only", "Lab.TPM", "aarch64"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(jargon)) {
			t.Errorf("public support body contains %q", jargon)
		}
	}
}
