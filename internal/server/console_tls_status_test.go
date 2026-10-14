// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

func TestConsoleCAStatusUsesOnlyConsolePublicCertificate(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	console := &x509.Certificate{Raw: []byte("console-public-certificate"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}
	device := &x509.Certificate{Raw: []byte("device-public-certificate"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 24 * time.Hour)}
	resources := &config.Resources{AdminCACertificate: console, DeviceCACertificate: device}
	check := consoleCAStatus(resources, now)
	if check.Component != "console_ca" || check.State != statusOK || !check.ExpiresAt.AsTime().Equal(console.NotAfter) || !check.EvidenceAt.AsTime().Equal(now) {
		t.Fatalf("console CA observation used the wrong identity: %v", check)
	}
	consoleDigest := sha256.Sum256(console.Raw)
	deviceDigest := sha256.Sum256(device.Raw)
	if !strings.Contains(check.Detail, fmt.Sprintf("%x", consoleDigest)) || strings.Contains(check.Detail, fmt.Sprintf("%x", deviceDigest)) {
		t.Fatal("console CA fingerprint did not identify only its public certificate")
	}
	for _, text := range []string{"/etc/lindm/console-ca.crt", "not the device CA"} {
		if !strings.Contains(check.NextAction, text) {
			t.Fatalf("missing console trust guidance: %s", text)
		}
	}
	for _, text := range []string{"ECDSA P-256/SHA-256", "Ed25519", "separate device trust"} {
		if !strings.Contains(check.Detail, text) {
			t.Fatalf("missing listener trust distinction: %s", text)
		}
	}
	for _, forbidden := range []string{".key", "PRIVATE KEY", "https://", "console-public-certificate", "device-public-certificate"} {
		if strings.Contains(check.String(), forbidden) {
			t.Fatalf("status exposed non-digest material: %s", forbidden)
		}
	}
	console.NotAfter = now
	if expired := consoleCAStatus(resources, now); expired.State != statusFailed || !strings.Contains(expired.NextAction, "Renew") {
		t.Fatal("trust guidance concealed expired console CA maintenance")
	}
}

func TestConsoleCAStatusAbsentAndUnavailable(t *testing.T) {
	resources := &config.Resources{}
	check := consoleCAStatus(resources, time.Now())
	if check.State != statusInactive || check.ExpiresAt != nil || check.EvidenceAt != nil || !strings.Contains(check.NextAction, "publicly trusted") {
		t.Fatal("absent optional private CA fabricated expiry or demanded an import")
	}
	resources.Proto = new(configv1.ServerConfig)
	if err := protojson.Unmarshal([]byte(`{"adminCaFile":"/etc/lindm/console-ca.crt"}`), resources.Proto); err != nil {
		t.Fatal(err)
	}
	check = consoleCAStatus(resources, time.Now())
	if check.State != statusUnknown || check.ExpiresAt != nil || check.Detail != "" {
		t.Fatal("unavailable configured console CA fabricated public evidence")
	}
}
