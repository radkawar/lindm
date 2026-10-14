// SPDX-License-Identifier: Apache-2.0
//go:build linux

// Package releasekit creates operator-owned production identities, publishes only
// their public trust material, and retains private material in an age archive.
// It does not install trust or authorize a release. Init and Unlock establish
// native signing protection before Init and pure-Go protection before Unlock.
// Callers must protect credentials before reading them and must not change the
// approved swap topology while secrets remain live.
package releasekit

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

const (
	AttestationPublicFile = "attestation.pub"
	InventoryFile         = "inventory.json"
	CAFile                = "ca-certificates.crt"
	RootFile              = "root.json"
	CustodyFile           = "custody.age"
	PackagePublicFile     = "package-signing.pub"
	BackupRecipientFile   = "backup-recipient.txt"
	PinsFile              = "pins.txt"
	AttestationPurpose    = "production-release-attestation"
	maxFileSize           = 4 << 20
	maxArchiveSize        = 16 << 20
	scryptWorkFactor      = 18
)

var publicFiles = []string{AttestationPublicFile, InventoryFile, CAFile, RootFile, "targets.json", "snapshot.json", "timestamp.json", "delegated.json", PackagePublicFile, BackupRecipientFile}
var keyMembers = []string{"attestation.pem", "execution.pem", "tls.pem", "tuf-root.pem", "tuf-targets.pem", "tuf-snapshot.pem", "tuf-timestamp.pem", "tuf-delegated.pem"}
var purposes = []string{AttestationPurpose, "production-execution", "production-tls", "production-tuf-root", "production-tuf-targets", "production-tuf-snapshot", "production-tuf-timestamp", "production-tuf-delegated"}

// Public contains pins suitable for independently recording with a kit backup.
// Load detects inconsistent public material; Unlock additionally authenticates
// it against the encrypted archive. Replacing an entire kit requires comparison
// with the operator's independently recorded pins.
type Public struct {
	AttestationKeyID   string
	PackageFingerprint string
	InventorySHA256    string
	CASHA256           string
}

// Secrets owns decrypted buffers. Domain backup keys are intentionally not
// exposed as interchangeable release signers. Close invalidates every buffer.
type Secrets struct {
	Purpose           string
	AttestationPEM    []byte
	PackageSecret     []byte
	PackagePassphrase []byte
	members           map[string][]byte
	buffers           []*custody.SecretBuffer
}

func (s *Secrets) Close() error {
	if s == nil {
		return nil
	}
	for _, value := range s.members {
		clear(value)
	}
	clear(s.AttestationPEM)
	clear(s.PackageSecret)
	clear(s.PackagePassphrase)
	var err error
	for _, buffer := range s.buffers {
		err = errors.Join(err, buffer.Close())
	}
	s.AttestationPEM, s.PackageSecret, s.PackagePassphrase, s.members, s.buffers = nil, nil, nil, nil, nil
	s.Purpose = ""
	return err
}

// Init creates a new kit, never replacing an existing directory. caBundle must
// be explicitly approved public PEM CA certificates, not implicit host trust.
// Exactly one custody mode is required: X25519 recipients or a passphrase.
func Init(ctx context.Context, directory string, recipients []string, passphrase, caBundle []byte) (_ *Public, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateCA(caBundle); err != nil {
		return nil, err
	}
	if (len(recipients) == 0) == (len(passphrase) == 0) {
		return nil, errors.New("releasekit: select recipients or passphrase custody, not both")
	}
	if len(recipients) > 128 {
		return nil, errors.New("releasekit: at most 128 X25519 recipients permitted")
	}
	if err := custody.ProtectNativeSigningSecrets(); err != nil {
		return nil, fmt.Errorf("releasekit: protect production key generation: %w", err)
	}
	encryptTo, err := custodyRecipients(recipients, passphrase)
	if err != nil {
		return nil, err
	}
	parentPath, base, err := destination(directory)
	if err != nil {
		return nil, err
	}
	parent, err := openDirectory(parentPath, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, parent.Close()) }()
	if _, err := os.Lstat(filepath.Join(parentPath, base)); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("releasekit: destination already exists or cannot be inspected")
	}
	stage, err := os.MkdirTemp(parentPath, ".releasekit-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	members := make(map[string][]byte)
	defer func() {
		for _, data := range members {
			clear(data)
		}
	}()
	keys := make([]ed25519.PrivateKey, len(keyMembers))
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for index, name := range keyMembers {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		keys[index] = key
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		members[name] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		clear(der)
	}
	documents, err := trustDocuments(keys, caBundle)
	if err != nil {
		return nil, err
	}
	secret, packagePass, public, fingerprint, err := generatePackageKey(ctx)
	if err != nil {
		return nil, err
	}
	members["package-secret.asc"], members["package-passphrase.txt"] = secret, packagePass
	documents[PackagePublicFile] = public
	if len(recipients) > 0 {
		documents[BackupRecipientFile] = []byte(recipients[0] + "\n")
	} else {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, err
		}
		members["backup-identity.txt"] = []byte(identity.String() + "\n")
		documents[BackupRecipientFile] = []byte(identity.Recipient().String() + "\n")
	}
	pins := makePins(documents, fingerprint)
	documents[PinsFile] = pins
	documents["pins.sig"] = ed25519.Sign(keys[0], pins)
	members["manifest.txt"] = archiveManifest(documents, members)
	for name, data := range documents {
		if err := writePublic(stage, name, data); err != nil {
			return nil, err
		}
	}
	if err := encryptArchive(ctx, stage, members, encryptTo); err != nil {
		return nil, err
	}
	if err := syncDirectory(stage); err != nil {
		return nil, err
	}
	if err := unix.Renameat2(int(parent.Fd()), filepath.Base(stage), int(parent.Fd()), base, unix.RENAME_NOREPLACE); err != nil {
		return nil, fmt.Errorf("releasekit: publish new kit: %w", err)
	}
	if err := parent.Sync(); err != nil {
		return nil, err
	}
	return publicSummary(documents, fingerprint)
}

func custodyRecipients(recipients []string, passphrase []byte) ([]age.Recipient, error) {
	encryptTo := make([]age.Recipient, 0, max(1, len(recipients)))
	for _, value := range recipients {
		if len(value) > 128 {
			return nil, errors.New("releasekit: oversized X25519 recipient")
		}
		recipient, err := age.ParseX25519Recipient(value)
		if err != nil {
			return nil, fmt.Errorf("releasekit: parse recipient: %w", err)
		}
		encryptTo = append(encryptTo, recipient)
	}
	if len(recipients) == 0 {
		if len(passphrase) < 16 || len(passphrase) > 1024 {
			return nil, errors.New("releasekit: custody passphrase must contain 16 to 1024 bytes")
		}
		recipient, err := age.NewScryptRecipient(string(passphrase))
		if err != nil {
			return nil, err
		}
		recipient.SetWorkFactor(scryptWorkFactor)
		encryptTo = append(encryptTo, recipient)
	}
	return encryptTo, nil
}

// Load reads bounded, owned regular public files without following symlinks.
func Load(directory string) (_ *Public, err error) {
	dir, err := openDirectory(directory, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	documents, err := readPublic(dir)
	if err != nil {
		return nil, err
	}
	return validatePublic(documents)
}

// Unlock authenticates the complete archive and its public bindings before
// returning any signer material. identity contains one age X25519 private
// identity (not a path); passphrase is used only for scrypt custody.
func Unlock(ctx context.Context, directory string, passphrase, identity []byte) (result *Secrets, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if (len(passphrase) == 0) == (len(identity) == 0) {
		return nil, errors.New("releasekit: provide exactly one custody credential")
	}
	if err := custody.ProtectReleaseSecrets(); err != nil {
		return nil, fmt.Errorf("releasekit: protect custody unlock: %w", err)
	}
	dir, err := openDirectory(directory, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, dir.Close())
		if err != nil && result != nil {
			err = errors.Join(err, result.Close())
			result = nil
		}
	}()
	documents, err := readPublic(dir)
	if err != nil {
		return nil, err
	}
	pub, err := validatePublic(documents)
	if err != nil {
		return nil, err
	}
	var decryptWith age.Identity
	if len(identity) > 0 {
		if len(identity) > 1024 {
			return nil, errors.New("releasekit: oversized age identity")
		}
		decryptWith, err = age.ParseX25519Identity(strings.TrimSpace(string(identity)))
	} else {
		if len(passphrase) > 1024 {
			return nil, errors.New("releasekit: oversized passphrase")
		}
		scrypt, identityErr := age.NewScryptIdentity(string(passphrase))
		if identityErr != nil {
			return nil, identityErr
		}
		scrypt.SetMaxWorkFactor(scryptWorkFactor)
		decryptWith = scrypt
	}
	if err != nil {
		return nil, err
	}
	ciphertext, err := readFile(dir, CustodyFile, maxArchiveSize)
	if err != nil {
		return nil, err
	}
	decrypted, err := age.Decrypt(bytes.NewReader(ciphertext), decryptWith)
	if err != nil {
		return nil, fmt.Errorf("releasekit: unlock custody: %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(decrypted, maxArchiveSize+1))
	defer clear(plain)
	if err != nil {
		return nil, fmt.Errorf("releasekit: authenticate custody: %w", err)
	}
	if len(plain) > maxArchiveSize {
		return nil, errors.New("releasekit: oversized custody archive")
	}
	members, buffers, err := readArchive(ctx, plain)
	if err != nil {
		return nil, err
	}
	secrets := &Secrets{members: members, buffers: buffers}
	defer func() {
		if err != nil {
			err = errors.Join(err, secrets.Close())
		}
	}()
	if err := validateArchive(documents, members, pub); err != nil {
		return nil, err
	}
	secrets.Purpose = AttestationPurpose
	secrets.AttestationPEM = members["attestation.pem"]
	secrets.PackageSecret = members["package-secret.asc"]
	secrets.PackagePassphrase = members["package-passphrase.txt"]
	return secrets, nil
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func encryptArchive(ctx context.Context, stage string, members map[string][]byte, recipients []age.Recipient) (err error) {
	file, err := os.OpenFile(filepath.Join(stage, CustodyFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	encrypted, err := age.Encrypt(file, recipients...)
	if err != nil {
		return err
	}
	archive := tar.NewWriter(encrypted)
	for _, name := range archiveNames(members) {
		if err := ctx.Err(); err != nil {
			return err
		}
		data := members[name]
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := archive.Write(data); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if err := encrypted.Close(); err != nil {
		return err
	}
	return file.Sync()
}
