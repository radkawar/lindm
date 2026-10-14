// SPDX-License-Identifier: Apache-2.0
//go:build linux

package install

import "testing"

func TestClusterCreationDisabled(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{"off", true},
		{"false", true},
		{"no", true},
		{"0", true},
		{"OFF", true},
		{"FaLsE", true},
		{"NO", true},
		{" \tfalse\r\n", true},
		{"on", false},
		{"true", false},
		{"yes", false},
		{"1", false},
		{"", false},
		{" \t\r\n", false},
		{"invalid", false},
		{"off\ntrue", false},
		{"false # comment", false},
	} {
		t.Run(test.value, func(t *testing.T) {
			if got := clusterCreationDisabled(test.value); got != test.want {
				t.Errorf("clusterCreationDisabled(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}
