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

func TestClusterPolicyDisabledWithoutNativeTool(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, test := range []struct {
		name   string
		policy string
		want   bool
	}{
		{"false", "create_main_cluster = false\n", true},
		{"off", "create_main_cluster=off", true},
		{"no", "create_main_cluster no\n", true},
		{"zero", "create_main_cluster = 0\n", true},
		{"quoted", "create_main_cluster = 'FaLsE' # preserve this file\n", true},
		{"case", "\tCREATE_MAIN_CLUSTER = NO\r\n", true},
		{"other settings", "data_directory = '/var/lib/postgresql/%v/%c'\nstart_conf = 'auto'\ncreate_main_cluster = false\n", true},
		{"comment", "# create_main_cluster = true\ncreate_main_cluster = false # disabled\n", true},
		{"enabled", "create_main_cluster = true\n", false},
		{"empty", "", false},
		{"missing", "start_conf = auto\n", false},
		{"invalid boolean", "create_main_cluster = maybe\n", false},
		{"duplicate disabled", "create_main_cluster = false\ncreate_main_cluster = off\n", false},
		{"conflict", "create_main_cluster = false\ncreate_main_cluster = true\n", false},
		{"include", "create_main_cluster = false\ninclude 'override.conf'\n", false},
		{"optional include", "create_main_cluster = false\nINCLUDE_IF_EXISTS = 'missing.conf'\n", false},
		{"include directory", "create_main_cluster = false\ninclude_dir '/etc/postgresql-common/createcluster.d'\n", false},
		{"unterminated quote", "create_main_cluster = 'false\n", false},
		{"escaped value", "create_main_cluster = 'of\\f'\n", false},
		{"doubled quote", "create_main_cluster = 'of''f'\n", false},
		{"double quote", "create_main_cluster = \"false\"\n", false},
		{"missing value", "create_main_cluster =\n", false},
		{"invalid separator", "create_main_cluster:false\n", false},
		{"extra statement", "create_main_cluster = false; start_conf = auto\n", false},
		{"invalid other setting", "create_main_cluster = false\nstart_conf = ++\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(test.policy)
			if got := clusterPolicyDisabled(data); got != test.want {
				t.Errorf("clusterPolicyDisabled(%q) = %t, want %t", test.policy, got, test.want)
			}
			if string(data) != test.policy {
				t.Fatal("policy validation changed operator bytes")
			}
		})
	}
}
