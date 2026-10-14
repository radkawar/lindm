// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Native outputs for one certificate whose signing subkey made the signature:
// primary A589…85E0, signing subkey C1F1…30CB (gpgv 2.4.7 and sqv 1.3.0 on
// Debian 13).
const (
	subkeySignedVALIDSIG = "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 4824C0B7820C30CB S <s@invalid>\n[GNUPG:] VALIDSIG C1F1FC5C774F8F32123F670B4824C0B7820C30CB 2026-10-11 1791701247 0 4 0 1 10 01 A58916A999DFF5F4F2297341D0F124DB226585E0\n"
	subkeySignedSQV      = "A58916A999DFF5F4F2297341D0F124DB226585E0\n"
	subkeyPrimary        = "A58916A999DFF5F4F2297341D0F124DB226585E0"
)

// The verifier is the one the device's APT uses: APT 3 with sqv installed
// (Debian 13 has no gpgv), otherwise gpgv. The distribution name never decides.
func TestAPTVerifierFollowsNativeAPTGeneration(t *testing.T) {
	for _, tc := range []struct {
		version string
		sqv     bool
		want    aptVerifier
	}{
		{"apt 3.0.3 (arm64)", true, aptVerifierSQV},
		{"apt 3.0.3 (arm64)", false, aptVerifierGPGV},
		{"apt 2.8.3 (amd64)", true, aptVerifierGPGV},
		{"apt 2.6.1 (arm64)", false, aptVerifierGPGV},
		{"apt 2.4.14 (arm64)", false, aptVerifierGPGV},
	} {
		if got, err := selectAPTVerifier(tc.version, tc.sqv); err != nil || got != tc.want {
			t.Errorf("%q sqv=%t: verifier %d, %v", tc.version, tc.sqv, got, err)
		}
	}
	for _, version := range []string{"", "apt", "dpkg 1.22.6 (arm64)", "apt x.0 (arm64)", "apt 0.9 (arm64)"} {
		if _, err := selectAPTVerifier(version, true); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%q accepted: %v", version, err)
		}
	}
}

// A subkey-signed repository has one signer identity, the certificate's
// primary fingerprint, whichever verifier the APT generation selects. gpgv
// once bound VALIDSIG's first field, the subkey, so the two disagreed.
func TestBothVerifiersBindTheSigningCertificate(t *testing.T) {
	primary, err := hex.DecodeString(subkeyPrimary)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(primary)
	gpgv, err := validSigners([]byte(subkeySignedVALIDSIG))
	if err != nil {
		t.Fatal(err)
	}
	sqv, err := sqvSigners([]byte(subkeySignedSQV))
	if err != nil {
		t.Fatal(err)
	}
	if len(gpgv) != 1 || len(sqv) != 1 || !bytes.Equal(gpgv[0], want[:]) || !bytes.Equal(sqv[0], want[:]) {
		t.Fatalf("signer identities differ: gpgv=%x sqv=%x want=%x", gpgv, sqv, want)
	}
	v6 := bytes.Repeat([]byte{0xab}, 32)
	if signers, err := sqvSigners([]byte(hex.EncodeToString(v6) + "\n" + subkeyPrimary + "\n")); err != nil || len(signers) != 2 {
		t.Fatalf("v6 and v4 certificates: %x %v", signers, err)
	}
}

func TestSignerParsersRefuseIncompleteOrUntrustedEvidence(t *testing.T) {
	for _, status := range []string{
		"",
		"[GNUPG:] VALIDSIG C1F1FC5C774F8F32123F670B4824C0B7820C30CB 2026-10-11 1791701247 0 4 0 1 10 01\n",
		subkeySignedVALIDSIG + "[GNUPG:] BADSIG 4824C0B7820C30CB S\n",
		"[GNUPG:] VALIDSIG C1F1FC5C774F8F32123F670B4824C0B7820C30CB 2026-10-11 1791701247 0 4 0 1 10 01 NOTHEX\n",
	} {
		if signers, err := validSigners([]byte(status)); err == nil {
			t.Errorf("gpgv status %q accepted: %x", status, signers)
		}
	}
	for _, stdout := range []string{"", "\n", "zz\n", subkeyPrimary + " extra\n", subkeyPrimary[:38] + "\n", "Missing key " + subkeyPrimary + "\n"} {
		if signers, err := sqvSigners([]byte(stdout)); err == nil {
			t.Errorf("sqv output %q accepted: %x", stdout, signers)
		}
	}
}

// Each verifier runs with fixed arguments against the approved keyring; sqv's
// authenticated copy goes to a fresh private path that does not outlive it.
func TestInReleaseVerifierInvocation(t *testing.T) {
	directory := t.TempDir()
	key, inRelease, output := filepath.Join(directory, "approved-key.gpg"), filepath.Join(directory, "lists", "x_InRelease"), filepath.Join(directory, "sqv-x_InRelease")
	for _, tc := range []struct {
		verifier aptVerifier
		path     string
		args     []string
		stdout   string
	}{
		{aptVerifierSQV, sqvPath, []string{"--keyring", key, "--cleartext", "--output", output, inRelease}, subkeySignedSQV},
		{aptVerifierGPGV, "/usr/bin/gpgv", []string{"--status-fd=1", "--keyring", key, inRelease}, subkeySignedVALIDSIG},
	} {
		if err := os.WriteFile(output, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
		calls := 0
		p := &Provider{run: func(_ context.Context, path string, args []string, _ string, _ []string) (nativeResult, error) {
			calls++
			if path != tc.path || !slices.Equal(args, tc.args) {
				t.Fatalf("native verifier %s %v", path, args)
			}
			if tc.verifier == aptVerifierSQV {
				if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("sqv output path not fresh: %v", err)
				}
				if err := os.WriteFile(output, []byte("authenticated"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			return nativeResult{stdout: []byte(tc.stdout)}, nil
		}}
		signers, err := p.inReleaseSigners(t.Context(), tc.verifier, key, inRelease, output)
		if err != nil || len(signers) != 1 || calls != 1 {
			t.Fatalf("verifier %d: signers=%x calls=%d err=%v", tc.verifier, signers, calls, err)
		}
		if _, err := os.Stat(output); tc.verifier == aptVerifierSQV && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("sqv authenticated copy retained: %v", err)
		}
		if err := os.RemoveAll(output); err != nil {
			t.Fatal(err)
		}
	}
}

// The verifier must use the approved bytes even if the host keyring changes
// after source admission. No package-manager network operation may start.
func TestAPTPreparationRechecksCopiedKeyringDigest(t *testing.T) {
	directory := rootPackageFixtureDirectory(t)
	keyPath := filepath.Join(directory, "vendor-key.gpg")
	original := []byte("original independently approved keyring")
	digest := sha256.Sum256(original)
	if err := os.WriteFile(keyPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	source := &agentv1.NativePackageSource{
		Repository:     &resourcev1.RepositoryDesired{Source: &resourcev1.RepositoryDesired_Apt{Apt: nobleArchive()}},
		SigningKeyFile: keyPath, SigningKeySha256: digest[:],
	}
	if err := checkSource(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("replaced keyring"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &Provider{run: func(context.Context, string, []string, string, []string) (nativeResult, error) {
		t.Fatal("APT ran with keyring bytes different from the pin")
		return nativeResult{}, errors.New("unexpected native call")
	}}
	if _, err := p.prepareAPT(t.Context(), filepath.Join(directory, "transaction"), source); err == nil {
		t.Fatal("keyring replacement between admission and copying accepted")
	}
}
