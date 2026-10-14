// SPDX-License-Identifier: Apache-2.0
//go:build linux && integration && production_signing

package packaging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func TestProductionMemorySignerImportsAndSignsNativeFormats(t *testing.T) {
	requireNativeTools(t, "gpg", "gpgconf", "gpgv", "rpmbuild", "rpmsign", "rpm", "rpmkeys", "rpm2cpio", "cpio")
	secret, passphrase := nativeProductionExport(t, ProductionSigningUID)
	root, err := os.MkdirTemp("", "pkg-import-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeWork(root); err != nil {
			t.Error(err)
		}
	})
	// Native homes must not inherit this deliberately overlong socket path.
	parent := filepath.Join(root, strings.Repeat("long-workspace-", 12))
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key, cleanup, err := ImportProductionSigner(ctx, parent, secret, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	})
	if key.Custody != CustodyProduction || key.PassphraseFile != "" || key.PassphraseFD == nil {
		t.Fatal("production import did not return memory-only passphrase custody")
	}
	keyValue, guard, err := validateSigner(ctx, parent, *key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := guard.close(ctx, parent); err != nil {
			t.Error(err)
		}
	}()
	build := filepath.Join(parent, "build")
	if err := os.Mkdir(build, 0o700); err != nil {
		t.Fatal(err)
	}
	payload, staged, digest := stageProductFixture(t, build, agentProduct())
	artifact, err := buildRPM(ctx, build, payload, "0.1.0", Architecture{RPM: "x86_64", Debian: "amd64"}, DefaultSourceDateEpoch, keyValue, digest, staged, agentProduct())
	if err != nil || !artifact.Signed || artifact.SignerFingerprint != key.Fingerprint {
		t.Fatalf("protected memory RPM signature: %v", err)
	}
	binary, _, err := exportPublicKeys(ctx, build, keyValue, build)
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(build, "Release")
	if err := os.WriteFile(release, []byte("Origin: lindm\nSuite: stable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pass, err := passphraseFile(build, keyValue)
	if err != nil {
		t.Fatal(err)
	}
	inRelease, err := signAPTRelease(ctx, build, keyValue, pass, release)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{inRelease}, {filepath.Join(build, "Release.gpg"), release}} {
		if _, _, err := runTool(ctx, build, toolCmd{Name: "gpgv", Args: append([]string{"--homedir", build, "--keyring", binary}, args...)}); err != nil {
			t.Fatal(err)
		}
	}
	// Arch signing uses the same native detached-signature path for package data.
	arch := filepath.Join(build, "package.pkg.tar.zst")
	if err := os.WriteFile(arch, []byte("detached native package signing payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signArchFile(ctx, build, arch, keyValue, DefaultSourceDateEpoch); err != nil {
		t.Fatal(err)
	}
	if err := verifyArchSignature(ctx, build, arch, binary); err != nil {
		t.Fatal(err)
	}
	if err := encryptedSignerHome(key.Home); err != nil {
		t.Fatal(err)
	}
	if err := guard.close(ctx, parent); err != nil {
		t.Fatal(err)
	}
	// Production retains the real SPKI exclusion gate, not just OpenPGP IDs.
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(secret))
	if err != nil || len(entities) != 1 {
		t.Fatalf("read encrypted fixture public material: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(entities[0].PrimaryKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	rejected := *key
	rejected.RejectPublicKeySHA256 = []string{hex.EncodeToString(sum[:])}
	if _, accepted, err := validateSigner(ctx, parent, rejected); !errors.Is(err, ErrSigner) {
		if accepted != nil {
			if closeErr := accepted.close(ctx, parent); closeErr != nil {
				t.Error(closeErr)
			}
		}
		t.Fatalf("production bypassed actual SPKI exclusion: %v", err)
	}
	busy, err := lockSignerHome(key.Home, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); !errors.Is(err, ErrSignerBusy) {
		t.Fatalf("cleanup interrupted an active signer: %v", err)
	}
	if err := busy.close(ctx, parent); err != nil {
		t.Fatal(err)
	}
	home, descriptor := key.Home, key.PassphraseFD
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("encrypted import home remains: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != "build" {
		t.Fatalf("encrypted import work remains: %v", err)
	}
	if _, err := descriptor.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("passphrase descriptor remains open: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestProductionImportErrorsRemoveOwnedHome(t *testing.T) {
	secret, passphrase := nativeProductionExport(t, ProductionSigningUID)
	parent, err := os.MkdirTemp("", "pkg-error-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeWork(parent); err != nil {
			t.Error(err)
		}
	})
	encoded, _, err := encryptedProductionSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(secret))
	if err != nil || len(entities) != 1 {
		t.Fatalf("read encrypted fixture: %v", err)
	}
	if err := entities[0].PrivateKey.Decrypt(passphrase); err != nil {
		t.Fatal(err)
	}
	var plaintext bytes.Buffer
	if err := entities[0].SerializePrivateWithoutSigning(&plaintext, nil); err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext.Bytes())
	for _, test := range []struct {
		name   string
		secret []byte
	}{
		{"unprotected-production", plaintext.Bytes()},
		{"extra-primary", append(bytes.Clone(encoded), encoded...)},
		// packet.Reader skips a Marker; the import gate must inspect it instead.
		{"skipped-marker", append(bytes.Clone(encoded), 0xca, 3, 'P', 'G', 'P')},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer clear(test.secret)
			if _, cleanup, err := ImportProductionSigner(context.Background(), parent, test.secret, passphrase); !errors.Is(err, ErrSigner) {
				if cleanup != nil {
					if closeErr := cleanup(); closeErr != nil {
						t.Error(closeErr)
					}
				}
				t.Fatalf("invalid encrypted export accepted: %v", err)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("rejected export wrote private files: %v", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name string
		ctx  context.Context
		pass []byte
	}{
		{"empty-passphrase", context.Background(), nil},
		{"wrong-passphrase", context.Background(), []byte("wrong passphrase")},
		{"canceled-import", canceled, passphrase},
	} {
		t.Run(test.name, func(t *testing.T) {
			if key, cleanup, err := ImportProductionSigner(test.ctx, parent, secret, test.pass); err == nil {
				if cleanup != nil {
					if closeErr := cleanup(); closeErr != nil {
						t.Error(closeErr)
					}
				}
				t.Fatalf("accepted invalid import with fingerprint %s", key.Fingerprint)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed import retained owned work: %v", err)
			}
		})
	}
}
