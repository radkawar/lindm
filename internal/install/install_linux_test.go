// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/platform"
)

func TestDependencyClosureRequiresEveryNativePrerequisite(t *testing.T) {
	for _, key := range []string{"ubuntu-24.04", "rhel-9"} {
		release, ok := platform.Lookup(key)
		if !ok {
			t.Fatalf("missing server release %s", key)
		}
		names := []string{"openssl", "systemd", "ca-certificates"}
		if release.Packages.Backend.PackageDB() == platform.PackageDBDpkg {
			names = append(names, "postgresql-16", "postgresql-client-16", "gpgv", "util-linux")
		} else {
			names = append(names, "postgresql-server", "postgresql", "rpm", "cpio", "policycoreutils")
		}
		if err := requiredDependencies(names, release); err != nil {
			t.Fatal(err)
		}
		for i, name := range names {
			t.Run(key+"_missing_"+name, func(t *testing.T) {
				remaining := append([]string{}, names[:i]...)
				remaining = append(remaining, names[i+1:]...)
				if err := requiredDependencies(remaining, release); err == nil {
					t.Fatalf("accepted closure missing %s", name)
				}
			})
		}
	}
}

func TestAirgapRequiresItsOwnPlatformAddonBeforeMutation(t *testing.T) {
	for _, key := range []string{"ubuntu-24.04", "rhel-9"} {
		release, ok := platform.Lookup(key)
		if !ok {
			t.Fatalf("missing server release %s", key)
		}
		t.Run(key, func(t *testing.T) {
			bundle := t.TempDir()
			if err := requireAirgapAddon(bundle, release); err == nil || !strings.Contains(err.Error(), "air-gap installation requires authenticated") {
				t.Fatalf("missing platform add-on did not fail clearly: %v", err)
			}
			for _, name := range []string{release.Server.SnapshotName, release.Server.SnapshotName + ".digest"} {
				if err := os.WriteFile(filepath.Join(bundle, name), []byte("presence only; signature authentication is tested by releasebuild"), 0600); err != nil {
					t.Fatal(err)
				}
				err := requireAirgapAddon(bundle, release)
				if (err == nil) != strings.HasSuffix(name, ".digest") {
					t.Fatalf("incomplete platform pair accepted: %v", err)
				}
			}
		})
	}
}

func TestInstallerRejectsSecretURLsInArguments(t *testing.T) {
	o := Options{Origin: "https://mdm.example:18444", AdminPort: 18444, DevicePort: 18445, ReleaseKey: "/trusted/key.pub", ReleaseKeyID: "pin", BackupRecipient: "/trusted/recipient", DatabaseURL: "postgresql://runtime:secret@database/lindm", MigrationURL: "/trusted/migration-url"}
	if err := options(&o); err == nil {
		t.Fatal("password-bearing database URL in arguments accepted")
	}
}

func TestInstallerRejectsOriginCredentialAndListenerCollision(t *testing.T) {
	for _, origin := range []string{"http://mdm.example", "https://user:secret@mdm.example", "https://mdm.example/path", "https://mdm.example?secret=value"} {
		o := Options{Origin: origin, AdminPort: 18444, DevicePort: 18445, ReleaseKey: "/trusted/key.pub", ReleaseKeyID: "pin", BackupRecipient: "/trusted/recipient"}
		if err := options(&o); err == nil {
			t.Fatalf("unsafe origin accepted: %s", origin)
		}
	}
	o := Options{Origin: "https://mdm.example", AdminPort: 18444, DevicePort: 18444, ReleaseKey: "/trusted/key.pub", ReleaseKeyID: "pin", BackupRecipient: "/trusted/recipient"}
	if err := options(&o); err == nil {
		t.Fatal("admin/device listener collision accepted")
	}
}

func TestPublicOriginsUseActualDefaultListeners(t *testing.T) {
	for _, host := range []string{"mdm.example", "[2001:db8::1]"} {
		o := Options{Origin: "https://" + host + "/", AdminPort: 18444, DevicePort: 18445}
		if err := publicOrigins(&o); err != nil {
			t.Fatal(err)
		}
		if o.Origin != "https://"+host+":18444" || o.DeviceOrigin != "https://"+host+":18445" {
			t.Fatalf("unreachable default origin: %+v", o)
		}
	}
}

func TestPublicOriginsPreserveExplicitProxyAndDeviceOrigins(t *testing.T) {
	o := Options{Origin: "https://console.example:443/", DeviceOrigin: "https://device.example:8443/", AdminPort: 18444, DevicePort: 18445}
	if err := publicOrigins(&o); err != nil {
		t.Fatal(err)
	}
	if o.Origin != "https://console.example:443" || o.DeviceOrigin != "https://device.example:8443" {
		t.Fatalf("explicit origins changed: %+v", o)
	}
}

func TestPublicOriginsRejectInvalidPublicPorts(t *testing.T) {
	for _, origin := range []string{"https://mdm.example:0", "https://mdm.example:65536"} {
		o := Options{Origin: origin, AdminPort: 18444, DevicePort: 18445}
		if err := publicOrigins(&o); err == nil {
			t.Fatalf("accepted invalid public port %s", origin)
		}
	}
}

func TestGeneratedAuthorityKeysSeparateAndConstrained(t *testing.T) {
	first, firstKey, err := newCertificateAuthority("first authority")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(firstKey)
	second, secondKey, err := newCertificateAuthority("second authority")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secondKey)
	if bytes.Equal(firstKey, secondKey) {
		t.Fatal("CA private authority reused")
	}
	for _, ca := range []*x509.Certificate{first, second} {
		if !ca.IsCA || !ca.BasicConstraintsValid || !ca.MaxPathLenZero || ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
			t.Fatal("generated CA constraints differ from admission policy")
		}
		if err := ca.CheckSignatureFrom(ca); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := privateKeyPEM(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("custody does not contain exact PKCS8 PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
}
