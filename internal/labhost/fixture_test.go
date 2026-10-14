// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

func fixtureHost(name, directory string) *labv1.LabHost {
	return &labv1.LabHost{
		Name:          name,
		Transport:     "local",
		Architectures: []string{"amd64"},
		Kvm:           true,
		MaxGuests:     2,
		MaxVcpus:      2,
		MaxMemoryMib:  4096,
		WorkDirectory: directory,
		Runtime:       "native",
	}
}

func writeConfig(t *testing.T, filename string, hosts ...*labv1.LabHost) {
	t.Helper()
	data, err := protojson.Marshal(&labv1.LabConfig{Hosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
}
