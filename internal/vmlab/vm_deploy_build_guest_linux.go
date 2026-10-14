// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"lindm/internal/custody"
)

// RunDeployBuildGuest is a lab-only child, compiled from the actual cloned Git
// commit inside the cold VM. It never returns or exports plaintext signing keys
// or the generated custody unlock phrase. This does not qualify a lifecycle.
func RunDeployBuildGuest(ctx context.Context, revision, epoch, first, newer string) error {
	if !coldReleaseRevision.MatchString(revision) || !coldReleaseEpoch.MatchString(epoch) || !coldReleaseVersionsValid(first, newer) {
		return errors.New("cold guest requires exact source revision, epoch and strictly newer release versions")
	}
	if err := custody.ProtectNativeSigningSecrets(); err != nil {
		return err
	}
	if err := custody.LockSecretMemory(); err != nil {
		return err
	}
	var entropy [48]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	passphrase := make([]byte, hex.EncodedLen(len(entropy)))
	hex.Encode(passphrase, entropy[:])
	clear(entropy[:])
	defer clear(passphrase)
	root := productionSigningGuestRoot
	export := filepath.Join(root, "export")
	if err := os.Mkdir(export, 0700); err != nil {
		return err
	}
	recipientPath := filepath.Join(root, "operator-recipient.txt")
	if err := encryptDeployEvidence(recipientPath, filepath.Join(export, "production-custody-passphrase.age"), passphrase); err != nil {
		return err
	}
	keys := filepath.Join(export, "keys")
	keyArguments := "--keys " + nativeQuote(keys) + " --ca-bundle /etc/ssl/certs/ca-certificates.crt --passphrase-fd 0"
	if err := runColdReleaseMake(ctx, recipientPath, export, "keys", "release-keys", "RELEASE_KEYS_ARGS="+keyArguments, io.MultiReader(bytes.NewReader(passphrase), strings.NewReader("\n"), bytes.NewReader(passphrase), strings.NewReader("\n"))); err != nil {
		return err
	}
	for _, release := range []struct{ directory, version string }{{"first", first}, {"newer", newer}} {
		arguments := "--repo " + nativeQuote(filepath.Join(root, "source")) + " --keys " + nativeQuote(keys) + " --output " + nativeQuote(filepath.Join(export, release.directory)) + " --version " + nativeQuote(release.version) + " --revision " + nativeQuote(revision) + " --source-date-epoch " + nativeQuote(epoch) + " --passphrase-fd 0"
		if err := runColdReleaseMake(ctx, recipientPath, export, release.directory, "release", "RELEASE_ARGS="+arguments, io.MultiReader(bytes.NewReader(passphrase), strings.NewReader("\n"))); err != nil {
			return err
		}
	}
	return nil
}

func runColdReleaseMake(ctx context.Context, recipientPath, export, label, target, arguments string, input io.Reader) (resultErr error) {
	body, err := os.ReadFile(recipientPath)
	if err != nil {
		return err
	}
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(string(body)))
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(export, label+".log.age"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	encrypted, err := age.Encrypt(file, recipient)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/usr/bin/make", target, arguments)
	command.Dir = filepath.Join(productionSigningGuestRoot, "source")
	command.Stdin = input
	log := &coldReleaseLogWriter{writer: encrypted, remaining: productionSigningLogLimit}
	command.Stdout, command.Stderr = log, log
	runErr := command.Run()
	closeErr := encrypted.Close()
	if runErr != nil {
		return errors.Join(fmt.Errorf("cold guest make %s failed; raw output retained only as encrypted lab evidence", target), closeErr)
	}
	if log.exceeded {
		return errors.Join(errors.New("cold Make output exceeded bounded encrypted diagnostic limit"), closeErr)
	}
	return errors.Join(closeErr, file.Sync())
}

// Excess output is drained without retaining plaintext. A truncated encrypted
// record never makes its stage pass and cannot exhaust disk via command output.
type coldReleaseLogWriter struct {
	writer    io.Writer
	remaining int
	exceeded  bool
}

func (writer *coldReleaseLogWriter) Write(body []byte) (int, error) {
	count := len(body)
	if len(body) > writer.remaining {
		body = body[:writer.remaining]
		writer.exceeded = true
	}
	if len(body) > 0 {
		if _, err := writer.writer.Write(body); err != nil {
			return 0, err
		}
		writer.remaining -= len(body)
	}
	return count, nil
}
