// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"testing"
)

func TestSelectAcceptanceEnginesKeepsReleasePassesComplete(t *testing.T) {
	if got, err := selectAcceptanceEngines("chromium,webkit,firefox", false); err != nil || !slices.Equal(got, acceptanceEngines) {
		t.Fatalf("full release selection %v: %v", got, err)
	}
	if got, err := selectAcceptanceEngines("chromium", true); err != nil || !slices.Equal(got, []string{"chromium"}) {
		t.Fatalf("web-only Chromium selection %v: %v", got, err)
	}
	for _, bad := range []struct {
		list    string
		webOnly bool
	}{{"chromium", false}, {"chromium,chromium", true}, {"edge", true}, {"", true}} {
		if _, err := selectAcceptanceEngines(bad.list, bad.webOnly); err == nil {
			t.Fatalf("accepted engines %q (web-only %t)", bad.list, bad.webOnly)
		}
	}
}
