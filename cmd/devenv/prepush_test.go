// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"strings"
	"testing"
)

func TestPushedCommitsGatesEachPushedTipOnce(t *testing.T) {
	const a, b = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	const zero = "0000000000000000000000000000000000000000"
	input := strings.Join([]string{
		"refs/heads/main " + a + " refs/heads/main " + zero,
		"refs/tags/v1 " + a + " refs/tags/v1 " + zero,
		"(delete) " + zero + " refs/heads/old " + b,
		"refs/heads/topic " + b + " refs/heads/topic " + a,
		"",
	}, "\n")
	shas, err := pushedCommits(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(shas, []string{a, b}) {
		t.Fatalf("gated %v", shas)
	}
	if _, err := pushedCommits(strings.NewReader("refs/heads/main " + a + "\n")); err == nil {
		t.Fatal("accepted a malformed ref line")
	}
}
