// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// The guest's evidence carries provider observations whose oneof the host
// must decode strictly; encoding/json alone cannot round-trip a oneof.
func TestServiceEvidenceRoundTripsProviderOneofs(t *testing.T) {
	observation := &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_SystemdService{SystemdService: &resourcev1.SystemdServiceObservation{Unit: "lab-native-service-proof.service", FingerprintSha256: bytes.Repeat([]byte{7}, 32)}}}
	sent := &VMServicesEvidence{Capability: "systemd.service.v1", Steps: []VMServiceStep{
		{Name: "converge-active", Target: "lab-native-service-proof.service", Before: observation, After: observation, NativeBefore: &VMServiceNativeState{Unit: "u"}, NativeAfter: &VMServiceNativeState{Unit: "u"}},
		{Name: "missing-rejected", Target: "missing.service", After: observation, Rejection: "unsupported", UnreportedDefinition: &VMServiceDefinitionLength{ObservedSize: 9}},
	}}
	data, err := json.Marshal(sent)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	got := new(VMServicesEvidence)
	if err := decoder.Decode(got); err != nil {
		t.Fatalf("host cannot decode guest service evidence: %v\n%s", err, data)
	}
	if len(got.Steps) != 2 || !proto.Equal(got.Steps[0].After, observation) || !proto.Equal(got.Steps[0].Before, observation) || got.Steps[1].Before != nil || got.Steps[1].Plan != nil ||
		got.Steps[1].Rejection != "unsupported" || got.Steps[1].UnreportedDefinition.ObservedSize != 9 || got.Steps[0].NativeAfter.Unit != "u" {
		t.Fatalf("service evidence changed in transit: %+v", got)
	}
	strict := json.NewDecoder(bytes.NewReader([]byte(`{"capability":"x","steps":[{"name":"n","target":"t","after":null,"native_before":null,"native_after":null,"surprise":1}]}`)))
	strict.DisallowUnknownFields()
	if err := strict.Decode(new(VMServicesEvidence)); err == nil {
		t.Fatal("unknown step field accepted")
	}
}

func TestServiceEvidenceRejectsEmptyScenarioRecords(t *testing.T) {
	// A successful guest exit and the expected record count do not establish
	// that the required native scenarios ran.
	evidence := &VMServicesEvidence{Capability: "systemd.service.v1", Steps: make([]VMServiceStep, 11)}
	if err := validateServiceEvidence(evidence); err == nil {
		t.Fatal("empty native scenario records accepted as qualification evidence")
	}
}

func TestServiceProbeRequiresSelectedGuestArchitecture(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := elf.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	machine := binary.Machine
	if err := binary.Close(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []elf.Machine{machine, elf.EM_NONE} {
		snapshot, _, err := snapshotServicesProbe(context.Background(), t.TempDir(), executable, want)
		if want == machine {
			if err != nil {
				t.Fatal(err)
			}
			if err := snapshot.Close(); err != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			_ = snapshot.Close()
			t.Fatal("service probe for another guest architecture was accepted")
		}
	}
}
