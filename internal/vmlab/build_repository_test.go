// SPDX-License-Identifier: Apache-2.0

package vmlab

import "testing"

func TestVMBuildRepository(t *testing.T) {
	for _, test := range []struct {
		name, fixture, override, want string
	}{
		{name: "existing default", fixture: "/trusted/fixture", want: "/trusted/fixture"},
		{name: "pinned source override", fixture: "/trusted/fixture", override: "/readonly/checkpoint", want: "/readonly/checkpoint"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := VMBuildRepository(test.fixture, test.override); got != test.want {
				t.Fatalf("build repository = %q, want %q", got, test.want)
			}
		})
	}
}
