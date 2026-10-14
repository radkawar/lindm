// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestPackageSnapshotBatchesBindExactBytes(t *testing.T) {
	data, err := packages(2001, nil)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	names := map[string]bool{}
	for i, encoded := range data.batches {
		descriptor := data.descriptors[i]
		digest := sha256.Sum256(encoded)
		if !bytes.Equal(digest[:], descriptor.GetSha256()) || int(descriptor.GetEncodedSize()) != len(encoded) || descriptor.GetIndex() != uint32(i) {
			t.Fatal("descriptor does not bind opaque batch bytes")
		}
		batch := new(inventoryv1.PackageBatch)
		if err := proto.Unmarshal(encoded, batch); err != nil {
			t.Fatal(err)
		}
		if err := validator.Validate(batch); err != nil {
			t.Fatal(err)
		}
		if len(batch.GetPackages()) != int(descriptor.GetCount()) {
			t.Fatal("descriptor count mismatch")
		}
		for _, pkg := range batch.GetPackages() {
			if names[pkg.GetName()] {
				t.Fatal("duplicate package identity")
			}
			names[pkg.GetName()] = true
			count++
		}
	}
	if count != 2001 || len(data.batches) != 5 {
		t.Fatalf("snapshot lost partial final batch: count=%d batches=%d", count, len(data.batches))
	}
}

func TestSyntheticNativeDetailsPreservesUnavailableHardware(t *testing.T) {
	details := syntheticNativeDetails()
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(details); err != nil {
		t.Fatalf("synthetic host details cannot be published: %v", err)
	}
	for _, count := range []*inventoryv1.ObservedUint64{details.GetSessions().GetUsers(), details.GetSessions().GetSessions()} {
		if count.GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || count.GetValue() != 0 {
			t.Fatal("simulator must explicitly report zero synthetic users and sessions")
		}
	}
	unavailable := inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	if details.GetStorage().GetStatus() != unavailable || len(details.GetStorage().GetDevices()) != 0 || details.GetTpm().GetPresent().GetStatus() != unavailable || details.GetTpm().GetPresent().GetValue() {
		t.Fatal("synthetic details invented storage or TPM capabilities")
	}
}
