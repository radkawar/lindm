// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

func TestDevelopmentBootstrapRefreshRetainsTrustIdentities(t *testing.T) {
	root, before, old := oldDevelopmentBootstrapFixture(t, nil)
	material, err := ReadPublicAgentFixture(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := authority.VerifyBootstrap(t.Context(), material.ExecutionRootJSON, material.BootstrapEnvelope, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	old.ConsoleCaPem = bytes.Clone(old.GetTransportCaPem())
	if !proto.Equal(old, verified.Bundle) {
		t.Fatal("schema repair changed signed fields beyond the console pin")
	}
	dir := filepath.Join(FixturePath(root), "agent-trust")
	after, err := readDevelopmentTrustFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range before {
		if name != "bootstrap.dsse.json" && !bytes.Equal(content, after[name]) {
			t.Fatalf("schema repair changed existing %s", name)
		}
	}
	if bytes.Equal(before["bootstrap.dsse.json"], after["bootstrap.dsse.json"]) {
		t.Fatal("old-shaped bootstrap was not re-signed")
	}
	info, err := os.Lstat(filepath.Join(dir, "bootstrap.dsse.json"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("replacement lost protected regular-file custody: %v", err)
	}
	if err := Trust(t.Context(), root); err != nil {
		t.Fatal(err)
	}
	unchanged, err := readOwned(filepath.Join(dir, "bootstrap.dsse.json"))
	if err != nil || !bytes.Equal(unchanged, after["bootstrap.dsse.json"]) {
		t.Fatalf("current-schema bootstrap was rewritten: %v", err)
	}
}

func TestDevelopmentBootstrapRefreshRefusesInvalidTrust(t *testing.T) {
	for _, tc := range []struct{ name, reason string }{
		{"invalid original signature", "original development bootstrap quorum verification failed"},
		{"unknown signed field", "unrecognized protobuf field"},
		{"wrong signed issuer", "does not bind the existing HTTPS issuers"},
		{"wrong release key", "development release key differs"},
		{"present console pin", "already has console trust"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind := tc.name
			root, _, _ := oldDevelopmentBootstrapFixture(t, func(bundle *agentv1.BootstrapBundle) {
				switch kind {
				case "unknown signed field":
					bundle.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
				case "wrong signed issuer":
					bundle.TransportCaPem = bytes.Clone(bundle.GetDeviceCaPem())
				case "present console pin":
					bundle.ConsoleCaPem = []byte("invalid existing console trust must not be replaced")
				}
			})
			dir := filepath.Join(FixturePath(root), "agent-trust")
			path := filepath.Join(dir, "bootstrap.dsse.json")
			if kind == "invalid original signature" {
				encoded, err := readOwned(path)
				if err != nil {
					t.Fatal(err)
				}
				var envelope dsse.Envelope
				if err := json.Unmarshal(encoded, &envelope); err != nil {
					t.Fatal(err)
				}
				envelope.Signatures[0].Sig = "aW52YWxpZA=="
				encoded, err = json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				writeDevelopmentRefreshTestFile(t, path, encoded)
			}
			if kind == "wrong release key" {
				key, err := readOwned(filepath.Join(dir, "execution-key-0.pem"))
				if err != nil {
					t.Fatal(err)
				}
				writeDevelopmentRefreshTestFile(t, filepath.Join(dir, "release-key.pem"), key)
			}
			before, err := readOwned(path)
			if err != nil {
				t.Fatal(err)
			}
			_, refusal := ReadPublicAgentFixture(t.Context(), root)
			if refusal == nil || !strings.Contains(refusal.Error(), tc.reason) {
				t.Fatalf("invalid %s did not fail at its trust boundary: %v", kind, refusal)
			}
			after, err := readOwned(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("failed repair published replacement: %v", err)
			}
		})
	}
}

func oldDevelopmentBootstrapFixture(t *testing.T, change func(*agentv1.BootstrapBundle)) (string, map[string][]byte, *agentv1.BootstrapBundle) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "deploy", "dev"), 0700); err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile("../../deploy/dev/compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	writeDevelopmentRefreshTestFile(t, filepath.Join(root, "deploy", "dev", "compose.yml"), compose)
	if err := os.Mkdir(filepath.Join(root, ".cache"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := initialize(root, "keycloak"); err != nil {
		t.Fatal(err)
	}
	if err := Trust(t.Context(), root); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(FixturePath(root), "agent-trust")
	files, err := readDevelopmentTrustFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, bundle, err := developmentBootstrapEnvelope(files["bootstrap.dsse.json"])
	if err != nil {
		t.Fatal(err)
	}
	bundle.ConsoleCaPem = nil
	if change != nil {
		change(bundle)
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var signers []dsse.Signer
	for _, name := range []string{"execution-key-0.pem", "execution-key-1.pem"} {
		key, err := developmentPrivateKey(files[name])
		if err != nil {
			t.Fatal(err)
		}
		public := ed25519.PublicKey(key[ed25519.SeedSize:])
		id, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, developmentRefreshTestSigner{developmentBootstrapVerifier: developmentBootstrapVerifier{public: public, id: id}, private: key})
	}
	signer, err := dsse.NewEnvelopeSigner(signers...)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.SignPayload(t.Context(), trust.BootstrapType, payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	files["bootstrap.dsse.json"] = encoded
	writeDevelopmentRefreshTestFile(t, filepath.Join(dir, "bootstrap.dsse.json"), encoded)
	return root, files, bundle
}

func writeDevelopmentRefreshTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

type developmentRefreshTestSigner struct {
	developmentBootstrapVerifier
	private ed25519.PrivateKey
}

func (s developmentRefreshTestSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ed25519.Sign(s.private, message), nil
}
