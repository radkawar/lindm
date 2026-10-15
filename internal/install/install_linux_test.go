// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"lindm/internal/platform"
)

func TestDependencyClosureRequiresEveryNativePrerequisite(t *testing.T) {
	for _, key := range []string{"ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04", "debian-12", "debian-13", "rhel-9", "rhel-10", "rocky-9", "rocky-10", "almalinux-9", "almalinux-10"} {
		release, ok := platform.Lookup(key)
		if !ok {
			t.Fatalf("missing server release %s", key)
		}
		names := []string{"openssl", "systemd", "ca-certificates"}
		if release.Packages.Backend.PackageDB() == platform.PackageDBDpkg {
			major := strconv.Itoa(release.Server.PostgreSQLMajor)
			names = append(names, "postgresql-"+major, "postgresql-client-"+major, "gpgv", "util-linux")
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
			expected := "air-gap installation requires authenticated"
			if key == "rhel-9" {
				expected = "this server platform supports connected installation only; air-gap qualification is out of scope"
			}
			if err := requireAirgapAddon(bundle, release); err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("missing platform add-on or unavailable mode did not fail clearly: %v", err)
			}
			for _, name := range []string{release.Server.SnapshotName, release.Server.SnapshotName + ".digest"} {
				if err := os.WriteFile(filepath.Join(bundle, name), []byte("presence only; signature authentication is tested by releasebuild"), 0600); err != nil {
					t.Fatal(err)
				}
				err := requireAirgapAddon(bundle, release)
				if key == "rhel-9" {
					if err == nil || err.Error() != expected {
						t.Fatalf("RHEL offline mode became available from add-on file presence: %v", err)
					}
				} else if (err == nil) != strings.HasSuffix(name, ".digest") {
					t.Fatalf("incomplete platform pair accepted: %v", err)
				}
			}
		})
	}
}

func TestConnectedServerRecipesRefuseOfflineBeforeDependencyMutation(t *testing.T) {
	for _, release := range platform.Releases() {
		if release.Server == nil || !release.Server.ConnectedOnly {
			continue
		}
		t.Run(release.Key, func(t *testing.T) {
			bundle := t.TempDir()
			for _, name := range []string{release.Server.SnapshotName, release.Server.SnapshotName + ".digest"} {
				if err := os.WriteFile(filepath.Join(bundle, name), []byte("not an authenticated offline qualification"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, err := range []error{
				requireAirgapAddon(bundle, release),
				installDependencies(t.Context(), Options{Airgap: true, Bundle: bundle}, release),
			} {
				if err == nil || !strings.Contains(err.Error(), "connected installation only") {
					t.Fatalf("unqualified offline path admitted or mutated state: %v", err)
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
		if ca.PublicKeyAlgorithm != x509.Ed25519 || ca.SignatureAlgorithm != x509.PureEd25519 {
			t.Fatal("device signing authority must remain Ed25519")
		}
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
	defer clear(block.Bytes)
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedConsoleTLSUsesBrowserCompatibleAlgorithms(t *testing.T) {
	ca, key, err := newTLSCertificateAuthority("console authority")
	if err != nil {
		t.Fatal(err)
	}
	public, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() || key.Curve != elliptic.P256() ||
		ca.PublicKeyAlgorithm != x509.ECDSA || ca.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatal("console CA must use P-256 and SHA-256")
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || !ca.MaxPathLenZero ||
		ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign ||
		!ca.NotAfter.Equal(ca.NotBefore.Add(time.Minute).AddDate(10, 0, 0)) {
		t.Fatal("console CA constraints or lifetime changed")
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	encoded, err := privateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("console custody must contain exact PKCS8 PEM")
	}
	defer clear(block.Bytes)
	recovered, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	recoveredKey, ok := recovered.(*ecdsa.PrivateKey)
	if !ok || !recoveredKey.Equal(key) {
		t.Fatal("console custody key does not match its authority")
	}
	path := filepath.Join(t.TempDir(), "server")
	hosts := []string{"console.example", "127.0.0.1", "::1", "console-alt.example"}
	if err := issueAdminServerCertificate(path, "console server", hosts, ca, key, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(path+".crt", path+".key")
	if err != nil {
		t.Fatal(err)
	}
	leafKey, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || leafKey.Curve != elliptic.P256() {
		t.Fatal("server TLS private key must use P-256")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || leafPublic.Curve != elliptic.P256() ||
		leaf.PublicKeyAlgorithm != x509.ECDSA || leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatal("server TLS certificate must use P-256 and SHA-256")
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		leaf.NotAfter.Sub(leaf.NotBefore) != 397*24*time.Hour+time.Minute ||
		len(leaf.DNSNames) != 2 || len(leaf.IPAddresses) != 2 {
		t.Fatal("server TLS usages, SANs or lifetime changed")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, host := range hosts {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example"}); err == nil {
		t.Fatal("server TLS accepted a host outside its SANs")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: hosts[0], CurrentTime: leaf.NotAfter.Add(time.Second)}); err == nil {
		t.Fatal("expired server TLS certificate accepted")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: hosts[0], KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("server TLS certificate accepted for device client authentication")
	}
}

func TestGeneratedDeviceTransportRemainsEd25519(t *testing.T) {
	ca, key, err := newCertificateAuthority("device transport authority")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if ca.PublicKeyAlgorithm != x509.Ed25519 || ca.SignatureAlgorithm != x509.PureEd25519 {
		t.Fatal("device transport authority must remain Ed25519")
	}
	path := filepath.Join(t.TempDir(), "server")
	if err := issueServerCertificate(path, "device server", []string{"device.example"}, ca, key, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(path+".crt", path+".key")
	if err != nil {
		t.Fatal(err)
	}
	leafKey, ok := pair.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("device server private key must remain Ed25519")
	}
	defer clear(leafKey)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.PublicKeyAlgorithm != x509.Ed25519 || leaf.SignatureAlgorithm != x509.PureEd25519 {
		t.Fatal("device server certificate must remain Ed25519")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "device.example", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleBYORejectsEd25519LeafOrIssuer(t *testing.T) {
	for _, edIssuer := range []bool{false, true} {
		for _, edLeaf := range []bool{false, true} {
			var ca *x509.Certificate
			var key crypto.Signer
			if edIssuer {
				certificate, private, err := newCertificateAuthority("BYO Ed25519 issuer")
				if err != nil {
					t.Fatal(err)
				}
				defer clear(private)
				ca, key = certificate, private
			} else {
				certificate, private, err := newTLSCertificateAuthority("BYO ECDSA issuer")
				if err != nil {
					t.Fatal(err)
				}
				ca, key = certificate, private
			}
			issue := issueAdminServerCertificate
			if edLeaf {
				issue = issueServerCertificate
			}
			path := filepath.Join(t.TempDir(), "server")
			if err := issue(path, "BYO console", []string{"console.example"}, ca, key, os.Getuid(), os.Getgid()); err != nil {
				t.Fatal(err)
			}
			pair, err := tls.LoadX509KeyPair(path+".crt", path+".key")
			if err != nil {
				t.Fatal(err)
			}
			if private, ok := pair.PrivateKey.(ed25519.PrivateKey); ok {
				defer clear(private)
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			err = validateConsoleTLSLeaf(leaf)
			if (err != nil) != (edIssuer || edLeaf) {
				t.Fatalf("BYO browser algorithm admission mismatch: Ed25519 issuer=%t leaf=%t: %v", edIssuer, edLeaf, err)
			}
		}
	}
}

func TestDatabaseAuthoritySupportsCertificateBoundSCRAM(t *testing.T) {
	ca, key, err := newDatabaseCertificateAuthority("database authority")
	if err != nil {
		t.Fatal(err)
	}
	if key.Curve != elliptic.P256() || ca.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		!ca.IsCA || !ca.BasicConstraintsValid || !ca.MaxPathLenZero ||
		ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatal("database authority must be constrained P-256 with SHA-256 signatures")
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	encoded, err := privateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("database custody must contain exact PKCS8 PEM")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	recovered, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("database custody lost the ECDSA key")
	}
	if !recovered.Equal(key) {
		t.Fatal("database custody key does not match its authority")
	}
	path := filepath.Join(t.TempDir(), "postgresql")
	if err := issueAdminServerCertificate(path, "database server", []string{"localhost", "127.0.0.1", "::1"}, ca, key, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(path+".crt", path+".key")
	if err != nil {
		t.Fatal(err)
	}
	leafKey, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || leafKey.Curve != elliptic.P256() {
		t.Fatal("database server private key must use P-256")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.PublicKeyAlgorithm != x509.ECDSA || leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatal("database server certificate lacks a SCRAM-PLUS-compatible hash")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLocalDatabaseURLsRequireBoundSCRAMForBothRoles(t *testing.T) {
	for _, role := range []string{"lindm_runtime", "lindm_migrator"} {
		t.Run(role, func(t *testing.T) {
			connection, err := url.Parse(strings.TrimSpace(localDatabaseURL(role, "fixture-password", "15432", "/fixture/database-ca.crt")))
			if err != nil {
				t.Fatal("generated database URL is invalid")
			}
			q := connection.Query()
			if q.Get("channel_binding") != "require" || q.Get("require_auth") != "scram-sha-256" ||
				q.Get("sslmode") != "verify-full" || q.Get("sslrootcert") != "/fixture/database-ca.crt" {
				t.Fatal("generated local database URL permits unbound or unverified authentication")
			}
			if connection.User.Username() != role {
				t.Fatal("generated URL changed its restricted role")
			}
		})
	}
}

func TestRuntimeDatabaseCallersUseRoleSpecificStages(t *testing.T) {
	required := map[string]bool{"validateDatabaseRoles": false, "restrictMetadata": false}
	for _, root := range []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok || len(call.Args) != 1 {
						return true
					}
					var name string
					switch target := call.Fun.(type) {
					case *ast.Ident:
						name = target.Name
					case *ast.SelectorExpr:
						name = target.Sel.Name
					}
					argument, ok := call.Args[0].(*ast.BasicLit)
					if !ok || argument.Kind != token.STRING {
						return true
					}
					value, err := strconv.Unquote(argument.Value)
					if err != nil || value != "/etc/lindm/server.json" {
						return true
					}
					if name == "StageDatabaseConfig" {
						t.Errorf("%s: runtime configuration must not request migration credentials", path)
					}
					if name == "StageRuntimeDatabaseConfig" && filepath.Base(path) == "provision_linux.go" {
						if _, expected := required[function.Name.Name]; expected {
							required[function.Name.Name] = true
						}
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, found := range required {
		if !found {
			t.Errorf("%s does not stage the installed runtime configuration", name)
		}
	}
}
