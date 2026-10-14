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
	var tableLines []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "| [") {
			tableLines = append(tableLines, line)
		}
	}
	tableBody := strings.Join(tableLines, "\n")
	for _, r := range platform.Releases() {
		link := fmt.Sprintf("](%s)", "docs/platforms/"+r.Page)
		prefix := "[" + gendoc.Escape(r.Name) + link
		count := strings.Count(tableBody, prefix)
		if r.Tier != platform.Tier1 && r.Tier != platform.Tier2 {
			if count != 0 {
				t.Errorf("non-target release %s appears in public rows", r.Key)
			}
			continue
		}
		if count != 1 {
			t.Errorf("%s rows = %d, want one x86_64 row", r.Key, count)
		}
		wantRows++
	}
	var actualRows int
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "| [") {
			actualRows++
			if columns := len(strings.Split(line, "|")) - 2; columns != 8 {
				t.Errorf("table has %d columns, want distribution and seven capabilities", columns)
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

func TestReadmeSupportRecognizesRecordedFeaturePasses(t *testing.T) {
	blocks, err := docBlocks("../..")
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, block := range blocks {
		if block.File == "README.md" && block.Name == "readme-support" {
			body = block.Body
		}
	}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "| [") {
			continue
		}
		columns := strings.Split(line, "|")[1:9]
		for i := range columns {
			columns[i] = strings.TrimSpace(columns[i])
		}
		if !strings.Contains(columns[0], "Omarchy") && !strings.HasPrefix(columns[6], "✓") {
			t.Errorf("%s findings = %q, want recorded vendor-feed pass", columns[0], columns[6])
		}
		if !strings.HasPrefix(columns[2], "✓") || !strings.HasPrefix(columns[3], "✓") || !strings.HasPrefix(columns[4], "✓") {
			t.Errorf("%s lost recorded profiles, encryption or lock/wipe: %v", columns[0], columns[2:5])
		}
		if strings.Contains(columns[0], "Ubuntu 24.04") && !strings.HasPrefix(columns[5], "✓") {
			t.Errorf("Ubuntu 24.04 OS updates = %q", columns[5])
		}
	}
}
