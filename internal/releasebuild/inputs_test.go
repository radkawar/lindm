//go:build linux

package releasebuild

import (
	"archive/tar"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
)

func testCABundle(t *testing.T) (string, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(2200000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "explicit-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path, certificate, private
}

func inventoryFixture(t *testing.T, substitute crypto.PublicKey, domain string) *releasev1.SigningTrustInventory {
	t.Helper()
	other, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, publicPEM, err := keyID(other)
	if err != nil {
		t.Fatal(err)
	}
	inventory := &releasev1.SigningTrustInventory{ExecutionPublicKeysPem: []string{string(publicPEM)}, TlsPublicKeysOrCertificatesPem: []string{string(publicPEM)}, NativeRejectFingerprints: []string{"  " + strings.Repeat("a", 40) + "  "}, NativeRejectHomePrefixes: []string{"/private/execution-keys"}}
	rootPublic := crypto.PublicKey(other)
	if domain != "" {
		_, encoded, err := keyID(substitute)
		if err != nil {
			t.Fatal(err)
		}
		switch domain {
		case "execution":
			inventory.ExecutionPublicKeysPem = []string{string(encoded)}
		case "tls":
			inventory.TlsPublicKeysOrCertificatesPem = []string{string(encoded)}
		case "tuf":
			rootPublic = substitute
		}
	}
	root := metadata.Root(time.Unix(1, 0))
	key, err := metadata.KeyFromPublicKey(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"root", "snapshot", "timestamp"} {
		if err := root.Signed.AddKey(key, role); err != nil {
			t.Fatal(err)
		}
	}
	targetsKey, err := metadata.KeyFromPublicKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Signed.AddKey(targetsKey, "targets"); err != nil {
		t.Fatal(err)
	}
	inventory.TufRootJson, err = root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	delegatedPublic := crypto.PublicKey(other)
	if domain == "delegated" {
		delegatedPublic = substitute
	}
	delegatedKey, err := metadata.KeyFromPublicKey(delegatedPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegatedID, err := delegatedKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	// Already-expired signed metadata still supplies valid key exclusions.
	targets := metadata.Targets(time.Unix(1, 0))
	targets.Signed.Delegations = &metadata.Delegations{
		Keys:  map[string]*metadata.Key{delegatedID: delegatedKey},
		Roles: []metadata.DelegatedRole{{Name: "rollout", KeyIDs: []string{delegatedID}, Threshold: 1, Paths: []string{"channels/*.json"}}},
	}
	if domain == "retired-delegated" {
		retired, err := metadata.KeyFromPublicKey(substitute)
		if err != nil {
			t.Fatal(err)
		}
		retiredID, err := retired.ID()
		if err != nil {
			t.Fatal(err)
		}
		targets.Signed.Delegations.Keys[retiredID] = retired
	}
	targetsSigner, err := signature.LoadSignerVerifier(otherPrivate, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targets.Sign(targetsSigner); err != nil {
		t.Fatal(err)
	}
	inventory.TufTargetsJson, err = targets.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func writeInventory(t *testing.T, inventory *releasev1.SigningTrustInventory) (string, string) {
	t.Helper()
	data, err := protojson.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sum[:])
}

func TestProductionRequiresAuthenticatedCompleteTrustInventory(t *testing.T) {
	signer, key := testSigner(t)
	key.Custody = "production"
	if err := os.WriteFile(key.Path+".purpose", []byte("production-release-attestation\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigner(key); err == nil {
		t.Fatal("production accepted absent trust inventory")
	}
	public, err := signer.signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	inventory := inventoryFixture(t, public, "")
	path, pin := writeInventory(t, inventory)
	key.TrustInventory, key.TrustInventorySHA256 = path, "  "+strings.ToUpper(pin)+"\n"
	key.KeyID = " " + strings.ToUpper(key.KeyID) + " "
	loaded, err := loadSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.exclusions.spki) == 0 || loaded.exclusions.fingerprints[0] != strings.Repeat("A", 40) || len(loaded.exclusions.homes) != 1 {
		t.Fatal("authenticated exclusions not normalized")
	}
	key.TrustInventorySHA256 = strings.Repeat("0", 64)
	if _, err := loadSigner(key); err == nil {
		t.Fatal("accepted substituted inventory")
	}
	for _, missing := range []string{"execution", "tls", "tuf", "targets"} {
		invalid := inventoryFixture(t, public, "")
		switch missing {
		case "execution":
			invalid.ExecutionPublicKeysPem = nil
		case "tls":
			invalid.TlsPublicKeysOrCertificatesPem = nil
		case "tuf":
			invalid.TufRootJson = nil
		case "targets":
			invalid.TufTargetsJson = nil
		}
		key.TrustInventory, key.TrustInventorySHA256 = writeInventory(t, invalid)
		if _, err := loadSigner(key); err == nil {
			t.Fatalf("accepted missing %s domain", missing)
		}
	}
	for _, domain := range []string{"execution", "tls", "tuf", "delegated", "retired-delegated"} {
		key.TrustInventory, key.TrustInventorySHA256 = writeInventory(t, inventoryFixture(t, public, domain))
		if _, err := loadSigner(key); err == nil {
			t.Fatalf("accepted %s public-key material reused for attestation", domain)
		}
	}
	for _, attack := range []string{"malformed", "unbound", "tampered", "unsigned"} {
		invalid := inventoryFixture(t, public, "")
		switch attack {
		case "malformed":
			invalid.TufTargetsJson = []byte(`{"signed":`)
		case "unbound":
			// A genuine but unrelated offline authority must not populate the
			// exclusion inventory authenticated by this root.
			invalid.TufTargetsJson = inventoryFixture(t, public, "").TufTargetsJson
		case "tampered", "unsigned":
			targets, err := metadata.Targets().FromBytes(invalid.TufTargetsJson)
			if err != nil {
				t.Fatal(err)
			}
			if attack == "tampered" {
				targets.Signed.Version++
			} else {
				targets.Signatures = nil
			}
			invalid.TufTargetsJson, err = targets.ToBytes(false)
			if err != nil {
				t.Fatal(err)
			}
		}
		key.TrustInventory, key.TrustInventorySHA256 = writeInventory(t, invalid)
		if _, err := loadSigner(key); err == nil {
			t.Fatalf("accepted %s targets inventory", attack)
		}
	}
}

func TestCABundleRequiresExplicitPinAndCertificates(t *testing.T) {
	path, _, _ := testCABundle(t)
	sum, _, err := digestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCABundle(path, " "+strings.ToUpper(sum)+" "); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{"", strings.Repeat("0", 64), "not-a-pin"} {
		if _, _, err := loadCABundle(path, pin); err == nil {
			t.Fatal("accepted absent or incorrect CA pin")
		}
	}
	malformed := filepath.Join(t.TempDir(), "not-certs")
	if err := os.WriteFile(malformed, []byte("ambient host trust is not an explicit CA bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	sum, _, err = digestFile(malformed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCABundle(malformed, sum); err == nil {
		t.Fatal("accepted noncertificate trust input")
	}
}

func TestOCITrustBytesSupportTLSAndAreBoundByVerifier(t *testing.T) {
	caPath, ca, caKey := testCABundle(t)
	pin, _, err := digestFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	binary := filepath.Join(directory, "lindmd")
	if err := os.WriteFile(binary, []byte("serialization test input"), 0555); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(directory, "image.tar")
	if err := buildOCI(binary, caPath, image, "lindmd", "amd64", 1760000000); err != nil {
		t.Fatal(err)
	}
	artifact := &releasev1.ReleaseArtifact{Product: "lindmd", Architecture: "amd64"}
	bom, err := withCABundleSBOM([]byte(`{"components":[],"metadata":{"component":{"bom-ref":"product"}},"dependencies":[{"ref":"product","dependsOn":[]}]}`), pin)
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := json.Marshal(map[string]any{"buildDefinition": map[string]any{"resolvedDependencies": []any{map[string]any{"uri": "urn:lindm:explicit-oci-ca-bundle", "digest": map[string]string{"sha256": pin}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOCICA(image, artifact, bom, provenance); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []struct{ bom, provenance []byte }{{bytes.ReplaceAll(bom, []byte(pin), []byte(strings.Repeat("0", 64))), provenance}, {bom, bytes.ReplaceAll(provenance, []byte(pin), []byte(strings.Repeat("0", 64)))}, {[]byte(`{"components":[]}`), provenance}} {
		if err := verifyOCICA(image, artifact, changed.bom, changed.provenance); err == nil {
			t.Fatal("accepted missing/substituted OCI trust declaration")
		}
	}
	if err := verifyOCIImage(image, "lindmd", "amd64", strings.Repeat("0", 64)); err == nil {
		t.Fatal("verifier ignored actual image trust bytes")
	}
	file, err := os.Open(image)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	outer := tar.NewReader(file)
	var actual []byte
	for {
		header, err := outer.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(outer)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(header.Name, "blobs/") || json.Valid(data) {
			continue
		}
		layer := tar.NewReader(bytes.NewReader(data))
		for {
			member, err := layer.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if member.Name == "etc/ssl/certs/ca-certificates.crt" {
				actual, err = io.ReadAll(layer)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(actual) {
		t.Fatal("image did not contain usable CA certificates")
	}
	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"oidc.example"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, leafPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "oidc.example", Roots: roots, CurrentTime: time.Unix(1800000000, 0)}); err != nil {
		t.Fatalf("OCI roots cannot authenticate configured OIDC issuer: %v", err)
	}
}
