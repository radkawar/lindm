// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/config"
	"lindm/internal/custody"
	"lindm/internal/trust"
)

// Trust generates development-only roots without rotating existing identities.
// An authenticated bootstrap missing the console field is re-signed in place.
func Trust(ctx context.Context, repoRoot string) error {
	return locked(ctx, repoRoot, func(root string) (err error) {
		fixture := FixturePath(root)
		if err := validateFixture(fixture); err != nil {
			return err
		}
		authority, err := trust.New()
		if err != nil {
			return err
		}
		dir := filepath.Join(fixture, "agent-trust")
		if _, err := os.Lstat(dir); err == nil {
			return verifyDevelopmentTrust(ctx, authority, dir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		document, err := config.Load(filepath.Join(fixture, "server.json"))
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Second)
		expires := now.Add(30 * 24 * time.Hour)
		execution := &agentv1.ExecutionRoot{DeploymentId: document.Proto.GetDeploymentId(), Version: 1, Threshold: 2, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(expires)}
		keys := make([]ed25519.PrivateKey, 0, 3)
		files := make(map[string][]byte)
		for i := range 3 {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			id, err := trust.KeyID(public)
			if err != nil {
				return err
			}
			execution.Keys = append(execution.Keys, &agentv1.ExecutionKey{KeyId: id, PublicKey: public})
			keys = append(keys, private)
			encoded, err := x509.MarshalPKCS8PrivateKey(private)
			if err != nil {
				return err
			}
			files[fmt.Sprintf("execution-key-%d.pem", i)] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
		}
		files["execution-root.json"], err = (protojson.MarshalOptions{Indent: "  "}).Marshal(execution)
		if err != nil {
			return err
		}
		releasePublic, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		release := metadata.Root(expires)
		releaseKey, err := metadata.KeyFromPublicKey(releasePublic)
		if err != nil {
			return err
		}
		for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
			if err := release.Signed.AddKey(releaseKey, role); err != nil {
				return err
			}
		}
		releaseSigner, err := signature.LoadSignerVerifier(releasePrivate, crypto.Hash(0))
		if err != nil {
			return err
		}
		if _, err := release.Sign(releaseSigner); err != nil {
			return err
		}
		files["release-root.json"], err = release.ToBytes(false)
		if err != nil {
			return err
		}
		releasePEM, err := x509.MarshalPKCS8PrivateKey(releasePrivate)
		if err != nil {
			return err
		}
		files["release-key.pem"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: releasePEM})
		transport, err := os.ReadFile(filepath.Join(fixture, "transport-ca.crt"))
		if err != nil {
			return err
		}
		device, err := os.ReadFile(filepath.Join(fixture, "device-ca.crt"))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(files["execution-root.json"])
		// This development fixture explicitly shares its HTTPS issuer between
		// origins; each domain is still independently pinned by the signed bundle.
		bundle := &agentv1.BootstrapBundle{BundleId: uuid.NewString(), DeploymentId: execution.GetDeploymentId(), EnrollmentOrigin: document.Proto.GetPublicUrl(), DeviceOrigin: "https://localhost:18445", TransportCaPem: transport, ConsoleCaPem: transport, DeviceCaPem: device, ExecutionRootVersion: 1, ExecutionRootSha256: digest[:], ReleaseRootJson: files["release-root.json"], NotBefore: execution.GetNotBefore(), ExpiresAt: execution.GetExpiresAt()}
		files["bootstrap.dsse.json"], err = authority.Sign(ctx, bundle, keys[:2]...)
		if err != nil {
			return err
		}
		if _, err := authority.VerifyBootstrap(ctx, files["execution-root.json"], files["bootstrap.dsse.json"], now); err != nil {
			return err
		}
		tmp, err := os.MkdirTemp(fixture, ".agent-trust-new-")
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, os.RemoveAll(tmp)) }()
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(tmp, name), content, 0600); err != nil {
				return err
			}
		}
		return os.Rename(tmp, dir)
	})
}

func verifyDevelopmentTrust(ctx context.Context, authority *trust.Authority, dir string) error {
	files, err := readDevelopmentTrustFiles(dir)
	if err != nil {
		return err
	}
	verified, err := authority.VerifyBootstrap(ctx, files["execution-root.json"], files["bootstrap.dsse.json"], time.Now())
	if err != nil {
		_, _, err = refreshDevelopmentBootstrap(ctx, authority, dir, files["execution-root.json"], files["bootstrap.dsse.json"])
		return err
	}
	return verifyDevelopmentTrustKeys(files, verified)
}

func readDevelopmentTrustFiles(dir string) (map[string][]byte, error) {
	if _, err := custody.Owned(dir, true); err != nil {
		return nil, err
	}
	files := make(map[string][]byte)
	for _, name := range []string{"execution-root.json", "bootstrap.dsse.json", "release-root.json", "release-key.pem", "execution-key-0.pem", "execution-key-1.pem", "execution-key-2.pem"} {
		content, err := readOwned(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		files[name] = content
	}
	return files, nil
}

func verifyDevelopmentTrustKeys(files map[string][]byte, verified *trust.Bootstrap) error {
	if !bytes.Equal(verified.Bundle.GetReleaseRootJson(), files["release-root.json"]) {
		return errors.New("development release root differs from signed bootstrap")
	}
	for i, key := range verified.Root.GetKeys() {
		private, err := developmentPrivateKey(files[fmt.Sprintf("execution-key-%d.pem", i)])
		if err != nil {
			return err
		}
		if !bytes.Equal(ed25519.PublicKey(private[ed25519.SeedSize:]), key.GetPublicKey()) {
			return errors.New("development execution key differs from pinned root")
		}
	}
	private, err := developmentPrivateKey(files["release-key.pem"])
	if err != nil {
		return err
	}
	releaseKey, err := metadata.KeyFromPublicKey(private.Public())
	if err != nil {
		return err
	}
	keyID, err := releaseKey.ID()
	if err != nil {
		return err
	}
	release, err := metadata.Root().FromBytes(files["release-root.json"])
	if err != nil {
		return err
	}
	if _, exists := release.Signed.Keys[keyID]; !exists {
		return errors.New("development release key differs from pinned root")
	}
	return nil
}

func developmentPrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid development signing key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid development signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("development signing key is not Ed25519")
	}
	return key, nil
}
