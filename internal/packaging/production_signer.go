// SPDX-License-Identifier: Apache-2.0
//go:build linux

package packaging

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// ProductionSigningUID is the self-signed purpose of keys created by releasekit.
// A directory marker cannot relabel an existing development key for production.
const ProductionSigningUID = "lindm production package signing <package-signing@production.lindm.invalid>"

const maxProductionSecret = 1 << 20
const maxPassphrase = 4096

// ImportProductionSigner opens one encrypted, purpose-bound RSA4096 secret key
// in an isolated native GPG home. Neither the exported secret nor the passphrase
// is written to a plaintext file. The caller owns secret/passphrase and must
// protect and clear those buffers. The returned cleanup must run after the last
// sequential signing operation; it stops only this home's agent, removes the
// imported encrypted home and erases/closes the locked passphrase descriptor.
func ImportProductionSigner(ctx context.Context, directory string, secret, passphrase []byte) (result *SigningKey, cleanup func() error, err error) {
	if err := custody.ProtectNativeSigningSecrets(); err != nil {
		return nil, nil, err
	}
	encoded, entity, err := encryptedProductionSecret(secret)
	if err != nil {
		return nil, nil, err
	}
	defer clear(encoded)
	protected, err := newPassphraseFD(passphrase)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, protected.close())
		}
	}()
	if err := rejectReservedHome(directory, nil); err != nil {
		return nil, nil, err
	}
	parent, err := openPrivate(directory)
	if err != nil {
		return nil, nil, err
	}
	if err := parent.Close(); err != nil {
		return nil, nil, err
	}
	work, remove, err := privateWork(directory)
	if err != nil {
		return nil, nil, err
	}
	// GPG's agent uses AF_UNIX sockets; a caller's long workspace path cannot
	// be its native home. This short owned directory contains encrypted keys
	// only and is included in every import cleanup path.
	home, err := os.MkdirTemp("/tmp", "lindm-release-gpg-")
	if err != nil {
		return nil, nil, errors.Join(err, remove())
	}
	removeImport := func() error { return errors.Join(removeWork(home), remove()) }
	var guard *signerGuard
	defer func() {
		if err != nil {
			err = errors.Join(err, guard.close(ctx, work), removeImport())
			result, cleanup = nil, nil
		}
	}()
	guard, err = lockSignerHome(home, nil)
	if err != nil {
		return nil, nil, err
	}
	fingerprint := strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
	key := SigningKey{Home: home, Fingerprint: fingerprint, Custody: CustodyProduction, PassphraseFD: protected.file}
	if _, _, err := runTool(ctx, work, toolCmd{
		Name:  "gpg",
		Args:  []string{"--no-options", "--require-secmem", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-file", "/proc/self/fd/3", "--homedir", home, "--import"},
		Stdin: bytes.NewReader(encoded), Files: passphraseFiles(key), ExtraEnv: gpgEnv(home),
	}); err != nil {
		return nil, nil, fmt.Errorf("%w: encrypted production key import failed", ErrSigner)
	}
	key, err = guard.validate(ctx, work, key)
	if err != nil {
		return nil, nil, err
	}
	if err := proveProductionUnlock(ctx, work, key, entity); err != nil {
		return nil, nil, err
	}
	if err := guard.close(ctx, work); err != nil {
		return nil, nil, err
	}
	var mu sync.Mutex
	closed := false
	cleanup = func() error {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return nil
		}
		owned, err := lockSignerHome(home, nil)
		if err != nil {
			return err // Never stop an agent being used by another signing operation.
		}
		err = stopAgent(context.WithoutCancel(ctx), work, home)
		// Retain the inode lock until its encrypted files have been removed.
		err = errors.Join(err, removeImport(), owned.home.Close(), protected.close())
		owned.home = nil
		closed = true
		return err
	}
	return &key, cleanup, nil
}

// Import can store an encrypted key without authenticating its passphrase.
// Restart the owned agent to exclude an import-time cache, then require a fresh
// native signature verified against the already authenticated export. Challenge
// and signature stay in memory; only the sealed passphrase descriptor is inherited.
func proveProductionUnlock(ctx context.Context, work string, key SigningKey, entity *openpgp.Entity) error {
	if err := stopAgent(ctx, work, key.Home); err != nil {
		return err
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	signed, _, err := runTool(ctx, work, toolCmd{
		Name:     "gpg",
		Args:     []string{"--no-options", "--require-secmem", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-file", "/proc/self/fd/3", "--homedir", key.Home, "--local-user", key.Fingerprint + "!", "--no-armor", "--detach-sign", "--output", "-"},
		Stdin:    bytes.NewReader(challenge),
		ExtraEnv: gpgEnv(key.Home),
		Files:    passphraseFiles(key),
	})
	if err != nil {
		return fmt.Errorf("%w: production passphrase cannot unlock imported signer", ErrSigner)
	}
	if len(signed) == 0 || len(signed) > 8192 {
		return fmt.Errorf("%w: invalid production unlock signature", ErrSigner)
	}
	signer, err := openpgp.CheckDetachedSignature(openpgp.EntityList{entity}, bytes.NewReader(challenge), bytes.NewReader(signed), nil)
	if err != nil || signer != entity {
		return fmt.Errorf("%w: production unlock signature verification failed", ErrSigner)
	}
	return nil
}

// Decode the encrypted export before allowing GPG to create any private files.
// Inspect every packet, not just a keyring parser that may skip invalid entities.
func encryptedProductionSecret(secret []byte) ([]byte, *openpgp.Entity, error) {
	if len(secret) == 0 || len(secret) > maxProductionSecret {
		return nil, nil, fmt.Errorf("%w: production secret export exceeds bound", ErrSigner)
	}
	var encoded []byte
	if bytes.HasPrefix(secret, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
		block, err := armor.Decode(bytes.NewReader(secret))
		if err != nil || block.Type != openpgp.PrivateKeyType {
			return nil, nil, fmt.Errorf("%w: invalid armored production secret", ErrSigner)
		}
		encoded, err = io.ReadAll(io.LimitReader(block.Body, maxProductionSecret+1))
		if err != nil || len(encoded) > maxProductionSecret {
			clear(encoded)
			return nil, nil, fmt.Errorf("%w: invalid armored production secret", ErrSigner)
		}
	} else {
		encoded = bytes.Clone(secret)
	}
	reject := func() ([]byte, *openpgp.Entity, error) {
		clear(encoded)
		return nil, nil, fmt.Errorf("%w: exactly one encrypted RSA4096 production package-signing key required", ErrSigner)
	}
	reader := bytes.NewReader(encoded)
	primary := false
	identities, certifications := 0, 0
	for {
		item, err := packet.Read(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return reject()
		}
		switch value := item.(type) {
		case *packet.PrivateKey:
			public, ok := value.PublicKey.PublicKey.(*rsa.PublicKey)
			if primary || value.IsSubkey || !value.Encrypted || value.PrivateKey != nil || !ok || public.N.BitLen() != 4096 {
				return reject()
			}
			primary = true
		case *packet.UserId:
			identities++
			if value.Id != ProductionSigningUID || identities != 1 {
				return reject()
			}
		case *packet.Signature:
			certifications++
			if value.SigType != packet.SigTypePositiveCert || certifications != 1 {
				return reject()
			}
			// The keyring parser below authenticates the UID self-signature.
		default:
			return reject()
		}
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(encoded))
	if err != nil || len(entities) != 1 || !primary || identities != 1 || certifications != 1 || len(entities[0].Identities) != 1 || len(entities[0].Subkeys) != 0 {
		return reject()
	}
	identity := entities[0].Identities[ProductionSigningUID]
	if identity == nil || identity.SelfSignature == nil || !identity.SelfSignature.FlagsValid || !identity.SelfSignature.FlagSign {
		return reject()
	}
	return encoded, entities[0], nil
}

func productionHomePurpose(ctx context.Context, work string, key SigningKey) error {
	listed, _, err := runTool(ctx, work, toolCmd{Name: "gpg", Args: []string{"--no-options", "--require-secmem", "--batch", "--no-tty", "--homedir", key.Home, "--with-colons", "--list-keys", key.Fingerprint}, ExtraEnv: gpgEnv(key.Home)})
	if err != nil {
		return err
	}
	identities := 0
	for _, line := range strings.Split(string(listed), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "uid" {
			identities++
			if fields[9] != ProductionSigningUID {
				return fmt.Errorf("%w: native key lacks production package-signing purpose", ErrSigner)
			}
		}
	}
	if identities != 1 {
		return fmt.Errorf("%w: exactly one production package-signing UID required", ErrSigner)
	}
	return encryptedSignerHome(key.Home)
}

// Native GPG may persist only its protected private-key representation. The
// packet gate above prevents importing plaintext even temporarily; this second
// check detects a native import that did not retain encryption at rest.
func encryptedSignerHome(home string) (err error) {
	directory, err := openPrivate(filepath.Join(home, "private-keys-v1.d"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".key") || !entries[0].Type().IsRegular() {
		return fmt.Errorf("%w: production home must contain one encrypted native private key", ErrSigner)
	}
	fd, err := unix.Openat(int(directory.Fd()), entries[0].Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "encrypted-native-key")
	defer func() { err = errors.Join(err, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxProductionSecret {
		return fmt.Errorf("%w: unsafe native private key", ErrSigner)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxProductionSecret+1))
	if err != nil {
		return err
	}
	defer clear(data)
	data = bytes.TrimSpace(data)
	protected := bytes.HasPrefix(data, []byte("(protected-private-key")) || bytes.Contains(data, []byte("\nKey: (protected-private-key"))
	if len(data) > maxProductionSecret || !protected || bytes.Contains(data, []byte("(private-key")) {
		return fmt.Errorf("%w: native production private key is not encrypted", ErrSigner)
	}
	return nil
}

// The existing writable mapping is retained solely for erasure. FUTURE_WRITE
// prevents any inherited descriptor from changing or remapping secret pages.
// Mlock and DONTDUMP cover the backing pages for the full descriptor lifetime.
type protectedPassphrase struct {
	file   *os.File
	memory []byte
}

func (secret *protectedPassphrase) close() error {
	if secret == nil || secret.file == nil {
		return nil
	}
	clear(secret.memory)
	err := errors.Join(unix.Munlock(secret.memory), unix.Munmap(secret.memory), secret.file.Close())
	secret.memory, secret.file = nil, nil
	return err
}

func newPassphraseFD(passphrase []byte) (_ *protectedPassphrase, err error) {
	if len(passphrase) == 0 || len(passphrase) > maxPassphrase || bytes.ContainsAny(passphrase, "\x00\r\n") {
		return nil, fmt.Errorf("%w: production passphrase must be bounded, nonempty and one line", ErrSigner)
	}
	fd, err := unix.MemfdCreate("lindm-package-passphrase", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	secret := &protectedPassphrase{file: os.NewFile(uintptr(fd), "lindm-package-passphrase")}
	defer func() {
		if err != nil {
			if secret.memory != nil {
				err = errors.Join(err, secret.close())
			} else {
				err = errors.Join(err, secret.file.Close())
			}
		}
	}()
	if err := secret.file.Chmod(0o600); err != nil {
		return nil, err
	}
	if err := secret.file.Truncate(int64(len(passphrase))); err != nil {
		return nil, err
	}
	secret.memory, err = unix.Mmap(fd, 0, len(passphrase), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	if err := unix.Mlock(secret.memory); err != nil {
		return nil, fmt.Errorf("%w: lock passphrase memory: %w", ErrSigner, err)
	}
	if err := unix.Madvise(secret.memory, unix.MADV_DONTDUMP); err != nil {
		return nil, err
	}
	copy(secret.memory, passphrase)
	seals := unix.F_SEAL_FUTURE_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(secret.file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, err
	}
	return secret, nil
}

func lockPassphraseFD(file *os.File) (_ []byte, err error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, err
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: passphrase descriptor is not a sealed memfd", ErrSigner)
	}
	fixed := unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size <= 0 || stat.Size > maxPassphrase || seals&fixed != fixed || seals&(unix.F_SEAL_WRITE|unix.F_SEAL_FUTURE_WRITE) == 0 {
		return nil, fmt.Errorf("%w: unsafe passphrase descriptor", ErrSigner)
	}
	memory, err := unix.Mmap(int(file.Fd()), 0, int(stat.Size), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, unix.Munlock(memory), unix.Munmap(memory))
		}
	}()
	if err := unix.Mlock(memory); err != nil {
		return nil, fmt.Errorf("%w: lock inherited passphrase memory: %w", ErrSigner, err)
	}
	if err := unix.Madvise(memory, unix.MADV_DONTDUMP); err != nil {
		return nil, err
	}
	if bytes.ContainsAny(memory, "\x00\r\n") {
		return nil, fmt.Errorf("%w: passphrase descriptor must contain one line", ErrSigner)
	}
	return memory, nil
}
