//go:build linux

package packaging

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	pgped25519 "github.com/ProtonMail/go-crypto/openpgp/ed25519"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// validatePublicExclusions runs with the signer-home guard held. OpenPGP
// fingerprints and TUF key IDs encode different objects; compare actual public
// material using canonical X.509 SPKI digests instead of comparing those IDs.
func validatePublicExclusions(ctx context.Context, work string, key SigningKey) error {
	if len(key.RejectPublicKeySHA256) == 0 {
		return nil
	}
	exported, _, err := runTool(ctx, work, toolCmd{Name: "gpg", Args: []string{"--no-options", "--batch", "--homedir", key.Home, "--export", key.Fingerprint}, ExtraEnv: gpgEnv(key.Home)})
	if err != nil {
		return err
	}
	return rejectPublicPacket(exported, key.Fingerprint, key.RejectPublicKeySHA256)
}

func rejectPublicPacket(encoded []byte, fingerprint string, rejected []string) error {
	reader := packet.NewReader(bytes.NewReader(encoded))
	found := false
	for {
		item, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: decode signing public key: %v", ErrSigner, err)
		}
		key, ok := item.(*packet.PublicKey)
		if !ok || key.IsSubkey {
			continue
		}
		if found || !strings.EqualFold(hex.EncodeToString(key.Fingerprint), fingerprint) {
			return fmt.Errorf("%w: public export identity mismatch", ErrSigner)
		}
		found = true
		var public crypto.PublicKey
		switch value := key.PublicKey.(type) {
		case *rsa.PublicKey:
			public = value
		case *eddsa.PublicKey:
			if len(value.X) != ed25519.PublicKeySize {
				return fmt.Errorf("%w: unsupported EdDSA signing curve", ErrSigner)
			}
			public = ed25519.PublicKey(value.X)
		case *pgped25519.PublicKey:
			if len(value.Point) != ed25519.PublicKeySize {
				return fmt.Errorf("%w: invalid Ed25519 public point", ErrSigner)
			}
			public = ed25519.PublicKey(value.Point)
		default:
			return fmt.Errorf("%w: signing public key cannot be compared with deployment trust", ErrSigner)
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(der)
		identity := hex.EncodeToString(sum[:])
		for _, pin := range rejected {
			pin = strings.ToLower(strings.TrimSpace(pin))
			decoded, err := hex.DecodeString(pin)
			if err != nil || len(decoded) != sha256.Size {
				return fmt.Errorf("%w: invalid public-key exclusion pin", ErrSigner)
			}
			if pin == identity {
				return fmt.Errorf("%w: signing key reuses execution, TLS, TUF or attestation key material", ErrSigner)
			}
		}
	}
	if !found {
		return fmt.Errorf("%w: signing public key missing", ErrSigner)
	}
	return nil
}
