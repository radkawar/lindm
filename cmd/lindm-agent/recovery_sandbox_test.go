// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestRecoverySandboxPathsRemainExact(t *testing.T) {
	cfg := &agentv1.RecoveryBootConfig{EspDirectory: "/boot/efi", StateDirectory: "/mnt/lindm-recovery"}
	text, err := recoverySandboxPaths(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := "ReadWritePaths=/boot/efi\nReadWritePaths=/mnt/lindm-recovery\nReadWritePaths=/sys/firmware/efi/efivars\n"
	if text != want {
		t.Fatalf("unexpected recovery write scope: %q", text)
	}
	for _, path := range []string{"/", "relative", "/boot/../etc", "/boot/%i", "/boot/efi\nProtectSystem=no", "/boot/efi:/etc", "/boot/efi /etc"} {
		cfg.EspDirectory = path
		if _, err := recoverySandboxPaths(cfg); err == nil {
			t.Fatalf("accepted unsafe recovery path %q", path)
		}
	}
	if _, err := recoverySandboxPaths(nil); err == nil {
		t.Fatal("accepted unqualified recovery write paths")
	}
}

func TestActionSecretMemoryIsProtectedBeforeCredentialAdmission(t *testing.T) {
	for _, test := range []struct {
		name      string
		config    *agentv1.DeviceActionProviderConfig
		protected bool
	}{
		{"disabled", nil, false},
		{"lock", &agentv1.DeviceActionProviderConfig{AllowSessionLock: true}, false},
		{"rotation", &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{{AllowRecoveryRotation: true}}}, true},
		{"TPM-binding", &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{{AllowTpm2Binding: true}}}, true},
		{"live-root", &agentv1.DeviceActionProviderConfig{AllowLiveRootCryptoErase: true}, true},
		{"recovery", &agentv1.DeviceActionProviderConfig{AllowRecoveryHandoff: true}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if actionMemoryRequired(test.config) != test.protected {
				t.Fatal("incorrect plaintext/process memory qualification")
			}
			text, err := actionSandboxText(test.config, nil)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(text, "CAP_IPC_LOCK") != test.protected || strings.Contains(text, "LimitMEMLOCK=infinity") != test.protected {
				t.Fatalf("memory qualification and sandbox disagree: %q", text)
			}
			if strings.Contains(text, "CAP_WAKE_ALARM") || strings.Contains(text, "CAP_SYS_BOOT") {
				t.Fatal("executor inherited independent poweroff helper capabilities")
			}
		})
	}
}
