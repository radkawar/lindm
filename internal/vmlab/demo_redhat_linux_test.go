// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
)

const demoConsumer = "11111111-1111-4111-8111-111111111111"

// The device root's receipt is the only registration record: an unregistered
// device has none, a lost registration reply keeps only the run name, and a
// completed registration resolves to its exact consumer.
func TestDemoRedHatReceiptRecordsExactConsumer(t *testing.T) {
	root := t.TempDir()
	if identity, err := readDemoRedHatReceipt(root); err != nil || identity != nil {
		t.Fatalf("unregistered root = %v, %v", identity, err)
	}
	var out bytes.Buffer
	if err := UnregisterDemoRedHat(t.Context(), root, "", &out); err != nil || out.Len() != 0 {
		t.Fatalf("unregistered destroy needed a token or acted: %v %q", err, out.String())
	}
	runName, err := newVMRedHatRunName()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := createVMRedHatReceipt(root, runName)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := readDemoRedHatReceipt(root)
	if err != nil || identity.GetRunName() != runName || identity.GetConsumerUuid() != "" {
		t.Fatalf("pending receipt = %v, %v", identity, err)
	}
	if err := UnregisterDemoRedHat(t.Context(), root, "", &out); err == nil || !strings.Contains(err.Error(), runName) {
		t.Fatalf("destroy guessed an unrecorded consumer: %v", err)
	}
	if err := appendVMRedHatReceipt(receipt, &labv1.RedHatRegistrationIdentity{RunName: runName, ConsumerUuid: demoConsumer}); err != nil {
		t.Fatal(err)
	}
	if err := receipt.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err = readDemoRedHatReceipt(root)
	if err != nil || identity.GetConsumerUuid() != demoConsumer {
		t.Fatalf("registered receipt = %v, %v", identity, err)
	}
	if err := UnregisterDemoRedHat(t.Context(), root, "", &out); err == nil {
		t.Fatal("registered device destroyed without a token")
	}
	other, err := newVMRedHatRunName()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, other+demoRedHatReceiptSuffix), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDemoRedHatReceipt(root); err == nil {
		t.Fatal("two registrations accepted")
	}
}
