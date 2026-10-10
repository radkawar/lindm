package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	labv1 "lindm/gen/lindm/lab/v1"
)

func vendorFixture(t *testing.T) (*labv1.ImageManifest, *labv1.VendorImageReceipt, string) {
	t.Helper()
	data := []byte("bounded vendor image fixture")
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	m := &labv1.ImageManifest{Id: "rhel-9.8-x86-64", Distribution: "rhel", Version: "9.8", Architecture: "x86_64", Edition: "kvm", Release: "9.8", ImageFilename: "rhel-9.8-x86_64-kvm.qcow2", ImageUrl: "https://api.access.redhat.com/management/v1/images/" + hash + "/download", ChecksumUrl: "https://api.access.redhat.com/management/v1/images/rhel/9.8/x86_64", Sha256: hash, ImageSizeBytes: uint64(len(data)), ChecksumMode: labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED, ReleaseProvenanceUrl: "https://access.redhat.com/downloads/content/rhel"}
	now := time.Now().UTC()
	r := &labv1.VendorImageReceipt{ImageFilename: m.ImageFilename, Sha256: hash, ImageSizeBytes: m.ImageSizeBytes, Version: m.Version, Architecture: m.Architecture, PublishedAt: timestamppb.New(now.Add(-time.Hour)), AcquiredAt: timestamppb.New(now), MetadataUrl: m.ChecksumUrl}
	image := filepath.Join(t.TempDir(), "vendor-image")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return m, r, image
}

func TestVendorImageImportAndOfflineVerification(t *testing.T) {
	m, receipt, image := vendorFixture(t)
	encoded, err := protojson.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(t.TempDir(), "cache")
	result, err := ImportVendorImage(t.Context(), m, cache, image, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if result.SigningFingerprint != "" || result.PrimaryFingerprint != "" {
		t.Fatal("authenticated vendor checksum claimed an OpenPGP signer")
	}
	if err := os.Remove(image); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyCache(t.Context(), m, cache)
	if err != nil || verified.SHA256 != m.Sha256 {
		t.Fatalf("offline verified=%v, error=%v", verified, err)
	}
	// VM startup consumes Fetch; authenticated entries must remain usable
	// offline without granting that generic fetcher access to credentials.
	fetched, err := (Fetcher{}).Fetch(t.Context(), m, cache)
	if err != nil || fetched.SHA256 != m.Sha256 {
		t.Fatalf("cached vendor VM input=%v, error=%v", fetched, err)
	}
	if err := os.Chmod(result.Path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(result.Path, make([]byte, m.ImageSizeBytes), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCache(t.Context(), m, cache); err == nil {
		t.Fatal("same-length altered image passed offline verification")
	}
}

func TestVendorImageImportRejectsMismatchedReceiptAndBytes(t *testing.T) {
	for _, kind := range []string{"receipt", "bytes", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			m, receipt, image := vendorFixture(t)
			if kind == "receipt" {
				receipt.ImageSizeBytes++
			}
			if kind == "bytes" {
				if err := os.WriteFile(image, []byte("wrong"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			encoded, err := protojson.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "unknown-field" {
				encoded = append([]byte(`{"token":"must-not-be-retained",`), encoded[1:]...)
			}
			cache := filepath.Join(t.TempDir(), "cache")
			if _, err := ImportVendorImage(t.Context(), m, cache, image, encoded); err == nil {
				t.Fatal("invalid vendor acquisition was accepted")
			}
			if _, err := os.Stat(filepath.Join(cache, "sha256-"+m.Sha256)); !os.IsNotExist(err) {
				t.Fatalf("failed import published a cache entry: %v", err)
			}
		})
	}
}

func TestVendorModeCannotDowngradeSignedDistribution(t *testing.T) {
	m, _, _ := vendorFixture(t)
	for _, distro := range []string{"ubuntu", "fedora"} {
		x := proto.CloneOf(m)
		x.Distribution = distro
		if err := validateManifest(x); err == nil {
			t.Fatalf("vendor mode admitted unsigned %s", distro)
		}
	}
	m.ChecksumMode = labv1.ChecksumMode_CHECKSUM_MODE_CLEARSIGNED
	if err := validateManifest(m); err == nil {
		t.Fatal("signed mode admitted absent pinned signing key")
	}
}
