// SPDX-License-Identifier: Apache-2.0

package measuredboot

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

const testAction = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"

func TestKernelOptions(t *testing.T) {
	for console, want := range map[string]string{
		"":               "rdinit=/init panic=10 quiet lindm.recovery.action=" + testAction,
		"ttyS0,115200n8": "rdinit=/init panic=10 quiet console=tty0 console=ttyS0,115200n8 lindm.recovery.action=" + testAction,
		"ttyAMA0,115200": "rdinit=/init panic=10 quiet console=tty0 console=ttyAMA0,115200 lindm.recovery.action=" + testAction,
	} {
		options, err := KernelOptions(testAction, console)
		if err != nil || options != want {
			t.Fatalf("KernelOptions(%q) = %q, %v; want %q", console, options, err, want)
		}
		action, err := ActionFromKernelOptions(options)
		if err != nil || action != testAction {
			t.Fatalf("ActionFromKernelOptions(%q) = %q, %v", options, action, err)
		}
	}
}

func TestKernelOptionsRejects(t *testing.T) {
	for name, test := range map[string]struct {
		action, console string
		want            error
	}{
		"uppercase action": {"0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "", errActionID},
		"short action":     {testAction[:35], "", errActionID},
		"no hyphens":       {"0f1e2d3c04b5a0697808796-a5b4c3d2e1f0", "", errActionID},
		"braced action":    {"{" + testAction[1:35] + "}", "", errActionID},
		"injected action":  {testAction[:35] + " ", "", errActionID},
		"other console":    {testAction, "ttyS1,115200n8", errSerialConsole},
		"console options":  {testAction, "ttyS0,115200n8 init=/bin/sh", errSerialConsole},
	} {
		if _, err := KernelOptions(test.action, test.console); !errors.Is(err, test.want) {
			t.Fatalf("%s: KernelOptions error = %v, want %v", name, err, test.want)
		}
	}
	valid, err := KernelOptions(testAction, "ttyS0,115200n8")
	if err != nil {
		t.Fatal(err)
	}
	for name, options := range map[string]string{
		"empty":            "",
		"extra option":     valid + " init=/bin/sh",
		"leading option":   "init=/bin/sh " + valid,
		"double space":     "rdinit=/init  panic=10 quiet lindm.recovery.action=" + testAction,
		"no console tty0":  "rdinit=/init panic=10 quiet console=ttyS0,115200n8 lindm.recovery.action=" + testAction,
		"unknown console":  "rdinit=/init panic=10 quiet console=tty0 console=ttyS1,115200n8 lindm.recovery.action=" + testAction,
		"bad action":       "rdinit=/init panic=10 quiet lindm.recovery.action=not-a-uuid",
		"two actions":      "rdinit=/init panic=10 quiet lindm.recovery.action=" + testAction + " lindm.recovery.action=" + testAction,
		"missing action":   "rdinit=/init panic=10 quiet",
		"oversized":        valid + string(bytes.Repeat([]byte{' '}, maxKernelOptions)),
		"trailing newline": valid + "\n",
	} {
		if action, err := ActionFromKernelOptions(options); err == nil {
			t.Fatalf("%s: ActionFromKernelOptions(%q) = %q, want error", name, options, action)
		}
	}
}

func TestQualifyingData(t *testing.T) {
	receipt, challenge := []byte("receipt"), []byte("challenge")
	receiptDigest, challengeDigest := sha256.Sum256(receipt), sha256.Sum256(challenge)
	input := append([]byte(Domain), 0)
	input = append(input, receiptDigest[:]...)
	input = append(input, challengeDigest[:]...)
	want := sha256.Sum256(input)
	got := QualifyingData(receipt, challenge)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("QualifyingData = %x, want %x", got, want)
	}
	if bytes.Equal(QualifyingData(challenge, receipt), got) {
		t.Fatal("QualifyingData is not order sensitive")
	}
}
