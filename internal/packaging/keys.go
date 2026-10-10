//go:build linux

package packaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/statefs"
)

const developmentUID = "lindm development package signing <package-signing@development.lindm.invalid>"

func normalizeFingerprint(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 40 && len(value) != 64 {
		return "", fmt.Errorf("%w: fingerprint must be 40 or 64 hex characters", ErrSigner)
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return "", fmt.Errorf("%w: fingerprint is not hex", ErrSigner)
		}
	}
	return value, nil
}

func rejectedFingerprint(fingerprint string, rejected []string) error {
	for _, item := range rejected {
		normalized, err := normalizeFingerprint(item)
		if err != nil {
			return fmt.Errorf("%w: rejected fingerprint list is invalid", ErrSigner)
		}
		if normalized == fingerprint {
			return fmt.Errorf("%w: fingerprint is an execution, TLS, or TUF key", ErrSigner)
		}
	}
	return nil
}

func readPurpose(home string) (bool, error) {
	dir, err := openPrivate(home)
	if err != nil {
		return false, err
	}
	defer func() { _ = dir.Close() }()
	present, err := statefs.CheckFile(int(dir.Fd()), "purpose")
	if err != nil {
		if errors.Is(err, statefs.ErrUnsafe) {
			return false, fmt.Errorf("%w: purpose file is not a private regular file", ErrSigner)
		}
		return false, err
	}
	if !present {
		return false, nil
	}
	fd, err := unix.Openat(int(dir.Fd()), "purpose", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(fd), "purpose")
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, int64(len(purposeText))+1))
	if err != nil {
		return false, err
	}
	if !bytes.Equal(data, []byte(purposeText)) {
		return false, fmt.Errorf("%w: purpose file is not a development package-signing marker", ErrSigner)
	}
	return true, nil
}

// signerGuard owns the actual private directory inode, not a replaceable lock
// file. Closing its descriptor releases flock only after agent shutdown.
type signerGuard struct {
	home *os.File
}

func lockSignerHome(home string, rejected []string) (*signerGuard, error) {
	if err := rejectReservedHome(home, rejected); err != nil {
		return nil, err
	}
	dir, err := openPrivate(home)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		closeErr := dir.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.Join(ErrSignerBusy, closeErr)
		}
		return nil, errors.Join(err, closeErr)
	}
	return &signerGuard{home: dir}, nil
}

func (guard *signerGuard) close(ctx context.Context, work string) error {
	if guard == nil || guard.home == nil {
		return nil
	}
	err := stopAgent(ctx, work, guard.home.Name())
	err = errors.Join(err, guard.home.Close())
	guard.home = nil
	return err
}

func validateSigner(ctx context.Context, work string, key SigningKey) (SigningKey, *signerGuard, error) {
	guard, err := lockSignerHome(key.Home, key.RejectPathPrefixes)
	if err != nil {
		return SigningKey{}, nil, err
	}
	key, err = guard.validate(ctx, work, key)
	if err != nil {
		return SigningKey{}, nil, errors.Join(err, guard.close(ctx, work))
	}
	return key, guard, nil
}

func (guard *signerGuard) validate(ctx context.Context, work string, key SigningKey) (SigningKey, error) {
	home := guard.home.Name()
	fingerprint, err := normalizeFingerprint(key.Fingerprint)
	if err != nil {
		return SigningKey{}, err
	}
	if err := rejectedFingerprint(fingerprint, key.RejectFingerprints); err != nil {
		return SigningKey{}, err
	}
	development, err := readPurpose(home)
	if err != nil {
		return SigningKey{}, err
	}
	switch key.Custody {
	case CustodyDevelopment:
		if !development {
			return SigningKey{}, fmt.Errorf("%w: development custody requires the package-signing marker", ErrSigner)
		}
	case CustodyProduction:
		if development {
			return SigningKey{}, fmt.Errorf("%w: development key cannot be used as production custody", ErrSigner)
		}
		if key.PassphraseFile == "" {
			return SigningKey{}, fmt.Errorf("%w: production custody requires an explicit passphrase file", ErrSigner)
		}
	default:
		return SigningKey{}, fmt.Errorf("%w: custody must be development or production", ErrSigner)
	}
	if key.PassphraseFile != "" {
		if err := checkPassphrase(key.PassphraseFile); err != nil {
			return SigningKey{}, err
		}
	}
	listed, err := listSecretFingerprint(ctx, work, home)
	if err != nil {
		return SigningKey{}, err
	}
	if listed != fingerprint {
		return SigningKey{}, fmt.Errorf("%w: fingerprint does not match the secret key", ErrSigner)
	}
	key.Home = home
	key.Fingerprint = fingerprint
	if err := validatePublicExclusions(ctx, work, key); err != nil {
		return SigningKey{}, err
	}
	return key, nil
}

func checkPassphrase(path string) error {
	cleaned, err := cleanAbsolute(path)
	if err != nil {
		return err
	}
	if err := rejectMacroUnsafe(cleaned); err != nil {
		return err
	}
	if err := rejectReservedHome(cleaned, nil); err != nil {
		return err
	}
	dir, err := openPrivate(filepath.Dir(cleaned))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	ok, err := statefs.CheckFile(int(dir.Fd()), filepath.Base(cleaned))
	if err != nil || !ok {
		return fmt.Errorf("%w: passphrase file is not a private regular file", ErrSigner)
	}
	return nil
}

// The caller holds the signer-home guard through all GPG use and cleanup.
func listSecretFingerprint(ctx context.Context, work, home string) (string, error) {
	stdout, _, err := runTool(ctx, work, toolCmd{
		Name: "gpg",
		Args: []string{"--no-options", "--batch", "--no-tty", "--homedir", home, "--with-colons", "--list-secret-keys"},
	})
	if err != nil {
		return "", fmt.Errorf("%w: cannot list package-signing key", ErrSigner)
	}
	var fingerprint string
	secrets := 0
	for _, line := range strings.Split(string(stdout), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "sec":
			secrets++
		case "fpr":
			if fingerprint == "" && len(fields) > 9 {
				fingerprint = strings.ToUpper(fields[9])
			}
		}
	}
	if secrets != 1 || fingerprint == "" {
		return "", fmt.Errorf("%w: key home must contain exactly one secret key", ErrSigner)
	}
	return normalizeFingerprint(fingerprint)
}

// GenerateDevelopmentSigner creates an isolated RSA package-signing key. It
// does not create a production key and does not read agent trust material.
func GenerateDevelopmentSigner(ctx context.Context, directory string) (*SigningKey, error) {
	key, guard, err := generateDevelopmentSigner(ctx, directory)
	if err != nil {
		return nil, err
	}
	if err := guard.close(ctx, directory); err != nil {
		return nil, errors.Join(err, removeWork(key.Home), os.Remove(key.PassphraseFile))
	}
	return key, nil
}

// Return ownership with the generated signer so fixture signing does not
// reacquire its own lock or expose an unlocked interval between GPG operations.
func generateDevelopmentSigner(ctx context.Context, directory string) (result *SigningKey, guard *signerGuard, err error) {
	parent, err := openPrivate(directory)
	if err != nil {
		return nil, nil, err
	}
	if err := parent.Close(); err != nil {
		return nil, nil, err
	}
	home := filepath.Join(directory, "package-signing-gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		return nil, nil, err
	}
	guard, err = lockSignerHome(home, nil)
	if err != nil {
		return nil, nil, errors.Join(err, removeWork(home))
	}
	owned := guard
	pass := filepath.Join(directory, "package-signing.pass")
	passCreated := false
	defer func() {
		if err != nil {
			err = errors.Join(err, owned.close(ctx, directory), removeWork(home))
			if passCreated {
				err = errors.Join(err, os.Remove(pass))
			}
			result, guard = nil, nil
		}
	}()
	if err := writeFile(pass, nil, 0o600, DefaultSourceDateEpoch); err != nil {
		return nil, nil, err
	}
	passCreated = true
	_, _, err = runTool(ctx, directory, toolCmd{
		Name: "gpg",
		Args: []string{
			"--no-options", "--batch", "--no-tty", "--pinentry-mode", "loopback",
			"--passphrase-file", pass, "--homedir", home, "--quick-generate-key",
			developmentUID, "rsa4096", "sign", "never",
		},
		Timeout: toolDeadline,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: development key generation failed", ErrSigner)
	}
	fingerprint, err := listSecretFingerprint(ctx, directory, home)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFile(filepath.Join(home, "purpose"), []byte(purposeText), 0o600, DefaultSourceDateEpoch); err != nil {
		return nil, nil, err
	}
	if _, err := owned.validate(ctx, directory, SigningKey{
		Home: home, Fingerprint: fingerprint, Custody: CustodyDevelopment, PassphraseFile: pass,
	}); err != nil {
		return nil, nil, err
	}
	return &SigningKey{
		Home:           home,
		Fingerprint:    fingerprint,
		Custody:        CustodyDevelopment,
		PassphraseFile: pass,
	}, guard, nil
}

func exportPublicKeys(ctx context.Context, work string, key SigningKey, dir string) (binaryPath, armorPath string, err error) {
	binaryPath = filepath.Join(dir, "lindm-package-signing.gpg")
	armorPath = filepath.Join(dir, "lindm-package-signing.asc")
	out, _, err := runTool(ctx, work, toolCmd{
		Name:     "gpg",
		Args:     []string{"--no-options", "--batch", "--homedir", key.Home, "--export", key.Fingerprint},
		ExtraEnv: gpgEnv(key.Home),
	})
	if err != nil {
		return "", "", err
	}
	if len(out) == 0 || len(out) > 1<<20 {
		return "", "", fmt.Errorf("%w: public key export is empty or too large", ErrSigner)
	}
	if err := writeMatching(binaryPath, out, 0o644); err != nil {
		return "", "", err
	}
	armor, _, err := runTool(ctx, work, toolCmd{
		Name:     "gpg",
		Args:     []string{"--no-options", "--batch", "--homedir", key.Home, "--armor", "--export", key.Fingerprint},
		ExtraEnv: gpgEnv(key.Home),
	})
	if err != nil {
		return "", "", err
	}
	if len(armor) == 0 || len(armor) > 1<<20 {
		return "", "", fmt.Errorf("%w: armored public key export rejected", ErrSigner)
	}
	if err := writeMatching(armorPath, armor, 0o644); err != nil {
		return "", "", err
	}
	return binaryPath, armorPath, nil
}

func writeMatching(path string, data []byte, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return writeFile(path, data, mode, DefaultSourceDateEpoch)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: existing public key is not a regular file", ErrSigner)
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, data) {
		return fmt.Errorf("%w: existing public key does not match this signer", ErrSigner)
	}
	return nil
}

func stopAgent(ctx context.Context, work, home string) error {
	// Agent shutdown must still run after the signing request is canceled.
	_, _, err := runTool(context.WithoutCancel(ctx), work, toolCmd{
		Name:    "gpgconf",
		Args:    []string{"--homedir", home, "--kill", "gpg-agent"},
		Timeout: 15 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("%w: signing-agent cleanup failed: %w", ErrSigner, err)
	}
	return nil
}

func passphraseFile(work string, key SigningKey) (string, error) {
	if key.PassphraseFile != "" {
		return key.PassphraseFile, nil
	}
	if key.Custody != CustodyDevelopment {
		return "", fmt.Errorf("%w: missing passphrase file", ErrSigner)
	}
	path := filepath.Join(work, "empty-passphrase")
	if err := writeFile(path, nil, 0o600, DefaultSourceDateEpoch); err != nil {
		if errors.Is(err, os.ErrExist) {
			return path, nil
		}
		return "", err
	}
	return path, nil
}

func gpgEnv(home string) []string {
	return []string{"GNUPGHOME=" + home, "GPG_TTY="}
}
