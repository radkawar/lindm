// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasekit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const productionSigningUID = "lindm production package signing <package-signing@production.lindm.invalid>"

// cappedOutput bounds native output without silently accepting truncation.
type cappedOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (b *cappedOutput) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.buffer.Len() {
		return 0, errors.New("releasekit: native output exceeds bound")
	}
	return b.buffer.Write(data)
}

func (b *cappedOutput) Bytes() []byte  { return b.buffer.Bytes() }
func (b *cappedOutput) String() string { return b.buffer.String() }

func runGPG(ctx context.Context, home string, passphrase []byte, args ...string) (_ []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	base := []string{"--no-options", "--require-secmem", "--homedir", home, "--batch", "--no-tty", "--no-auto-check-trustdb"}
	var readEnd *os.File
	if len(passphrase) > 0 {
		if len(passphrase) > 128 || bytes.ContainsAny(passphrase, "\r\n") {
			return nil, errors.New("releasekit: invalid native passphrase")
		}
		var writeEnd *os.File
		readEnd, writeEnd, err = os.Pipe()
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, readEnd.Close()) }()
		if _, err := writeEnd.Write(passphrase); err != nil {
			return nil, errors.Join(err, writeEnd.Close())
		}
		if _, err := writeEnd.Write([]byte("\n")); err != nil {
			return nil, errors.Join(err, writeEnd.Close())
		}
		if err := writeEnd.Close(); err != nil {
			return nil, err
		}
		base = append(base, "--pinentry-mode", "loopback", "--passphrase-fd", "3")
	}
	cmd := exec.CommandContext(ctx, "gpg", append(base, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GNUPGHOME=" + home, "LC_ALL=C"}
	cmd.WaitDelay = 2 * time.Second
	if readEnd != nil {
		cmd.ExtraFiles = []*os.File{readEnd}
	}
	stdout := &cappedOutput{limit: maxFileSize}
	stderr := &cappedOutput{limit: 32 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	defer clear(stderr.Bytes())
	if err := cmd.Run(); err != nil {
		clear(stdout.Bytes())
		return nil, fmt.Errorf("releasekit: GPG operation: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func stopPackageAgent(home string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gpgconf", "--homedir", home, "--kill", "gpg-agent")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GNUPGHOME=" + home, "LC_ALL=C"}
	cmd.WaitDelay = 2 * time.Second
	output := &cappedOutput{limit: 32 << 10}
	cmd.Stdout, cmd.Stderr = output, output
	defer clear(output.Bytes())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("releasekit: stop owned GPG agent: %w", err)
	}
	return nil
}

func generatePackageKey(ctx context.Context) (secret, passphrase, public []byte, fingerprint string, err error) {
	// A short, fresh 0700 home avoids GPG agent Unix-socket path limits even
	// when the operator kit's destination is deeply nested. Only encrypted
	// native private material is ever written here.
	home, err := os.MkdirTemp("/tmp", "lindm-release-gpg-")
	if err != nil {
		return nil, nil, nil, "", err
	}
	defer func() {
		err = errors.Join(err, stopPackageAgent(home), os.RemoveAll(home))
		if err != nil {
			clear(secret)
			clear(passphrase)
			secret, passphrase = nil, nil
		}
	}()
	if err := writePublic(home, "gpg-agent.conf", []byte("allow-loopback-pinentry\nno-allow-external-cache\ndefault-cache-ttl 0\nmax-cache-ttl 0\n")); err != nil {
		return nil, nil, nil, "", err
	}
	entropy := make([]byte, 48)
	defer clear(entropy)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return nil, nil, nil, "", err
	}
	passphrase = make([]byte, base64.RawURLEncoding.EncodedLen(len(entropy)))
	base64.RawURLEncoding.Encode(passphrase, entropy)
	output, err := runGPG(ctx, home, passphrase, "--quick-generate-key", productionSigningUID, "rsa4096", "sign", "2y")
	clear(output)
	if err != nil {
		return nil, passphrase, nil, "", err
	}
	if err := checkProtectedStore(home); err != nil {
		return nil, passphrase, nil, "", err
	}
	public, err = runGPG(ctx, home, nil, "--armor", "--export", productionSigningUID)
	if err != nil {
		return nil, passphrase, nil, "", err
	}
	fingerprint, err = validatePackagePublic(public)
	if err != nil {
		return nil, passphrase, public, "", err
	}
	secret, err = runGPG(ctx, home, passphrase, "--armor", "--export-secret-keys", fingerprint)
	if err != nil {
		return nil, passphrase, public, "", err
	}
	if err := validatePackageSecret(secret, passphrase, fingerprint); err != nil {
		return secret, passphrase, public, fingerprint, err
	}
	return secret, passphrase, public, fingerprint, nil
}

func checkProtectedStore(home string) error {
	directory := filepath.Join(home, "private-keys-v1.d")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) != 1 {
		return errors.New("releasekit: expected one distinct native package private key")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".key") || entry.Type() != 0 {
			return errors.New("releasekit: unexpected native private key entry")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > 64<<10 {
			return errors.New("releasekit: unsafe native private key file")
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		protected := bytes.Contains(data, []byte("(protected-private-key")) && !bytes.Contains(data, []byte("(private-key"))
		clear(data)
		if !protected {
			return errors.New("releasekit: native package private key is not encrypted")
		}
	}
	return nil
}

// Check packets independently of ReadKeyRing, which deliberately skips some
// unsupported packets. A newly generated kit has one primary, UID and self-
// certification; extra private keys or armor blocks are never silently ignored.
func decodePackage(data []byte) (_ []byte, err error) {
	trimmed := bytes.TrimSpace(data)
	var kind string
	for _, candidate := range []string{openpgp.PublicKeyType, openpgp.PrivateKeyType} {
		if bytes.HasPrefix(trimmed, []byte("-----BEGIN "+candidate+"-----")) {
			kind = candidate
			break
		}
	}
	if kind == "" || !bytes.HasSuffix(trimmed, []byte("-----END "+kind+"-----")) || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 || bytes.Count(trimmed, []byte("-----END ")) != 1 {
		return nil, errors.New("releasekit: expected one complete package key armor block")
	}
	block, err := armor.Decode(bytes.NewReader(trimmed))
	if err != nil {
		return nil, err
	}
	decoded, err := io.ReadAll(io.LimitReader(block.Body, maxFileSize+1))
	defer func() {
		if err != nil {
			clear(decoded)
		}
	}()
	if err != nil {
		return nil, err
	}
	if len(decoded) > maxFileSize {
		return nil, errors.New("releasekit: oversized decoded package key")
	}
	input := bytes.NewReader(decoded)
	count := 0
	for {
		value, err := packet.Read(input)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value := value.(type) {
		case *packet.PublicKey:
			if count != 0 || kind != openpgp.PublicKeyType || value.IsSubkey {
				return nil, errors.New("releasekit: unexpected package public packet")
			}
		case *packet.PrivateKey:
			if count != 0 || kind != openpgp.PrivateKeyType || value.IsSubkey || !value.Encrypted {
				return nil, errors.New("releasekit: package secret packet is not exclusively protected")
			}
		case *packet.UserId:
			if count != 1 || value.Id != productionSigningUID {
				return nil, errors.New("releasekit: unexpected package purpose packet")
			}
		case *packet.Signature:
			if count != 2 {
				return nil, errors.New("releasekit: unexpected package signature packet")
			}
		default:
			return nil, errors.New("releasekit: unexpected package key packet")
		}
		count++
	}
	if count != 3 {
		return nil, errors.New("releasekit: incomplete package signing identity")
	}
	return decoded, nil
}

func packageEntity(data []byte) (*openpgp.Entity, string, error) {
	if len(data) == 0 || len(data) > maxFileSize {
		return nil, "", errors.New("releasekit: invalid package key size")
	}
	decoded, err := decodePackage(data)
	if err != nil {
		return nil, "", err
	}
	defer clear(decoded)
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(decoded))
	if err != nil {
		return nil, "", err
	}
	if len(entities) != 1 {
		return nil, "", errors.New("releasekit: expected one package signing identity")
	}
	entity := entities[0]
	public, ok := entity.PrimaryKey.PublicKey.(*rsa.PublicKey)
	if !ok || public.N.BitLen() != 4096 || len(entity.Subkeys) != 0 || len(entity.Identities) != 1 || len(entity.Revocations) != 0 {
		return nil, "", errors.New("releasekit: package signing requires a distinct RSA4096 primary identity")
	}
	identity := entity.Identities[productionSigningUID]
	if identity == nil || identity.SelfSignature == nil || !identity.SelfSignature.FlagSign {
		return nil, "", errors.New("releasekit: package key has no production signing purpose")
	}
	return entity, strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint)), nil
}

func validatePackagePublic(data []byte) (string, error) {
	entity, fingerprint, err := packageEntity(data)
	if err != nil {
		return "", err
	}
	if entity.PrivateKey != nil {
		return "", errors.New("releasekit: package public file contains private material")
	}
	return fingerprint, nil
}

func validatePackageSecret(data, passphrase []byte, expected string) error {
	if len(passphrase) != 64 || bytes.ContainsAny(passphrase, "\r\n") {
		return errors.New("releasekit: invalid generated package protection secret")
	}
	entity, fingerprint, err := packageEntity(data)
	if err != nil {
		return err
	}
	if fingerprint != expected || entity.PrivateKey == nil || !entity.PrivateKey.Encrypted {
		return errors.New("releasekit: package secret must be protected and match public identity")
	}
	if err := entity.PrivateKey.Decrypt(passphrase); err != nil {
		return fmt.Errorf("releasekit: package protection secret mismatch: %w", err)
	}
	private, ok := entity.PrivateKey.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return errors.New("releasekit: expected native RSA private key")
	}
	defer clearRSA(private)
	return private.Validate()
}

func clearRSA(private *rsa.PrivateKey) {
	clear(private.D.Bits())
	for _, prime := range private.Primes {
		clear(prime.Bits())
	}
	if private.Precomputed.Dp != nil {
		clear(private.Precomputed.Dp.Bits())
	}
	if private.Precomputed.Dq != nil {
		clear(private.Precomputed.Dq.Bits())
	}
	if private.Precomputed.Qinv != nil {
		clear(private.Precomputed.Qinv.Bits())
	}
}
