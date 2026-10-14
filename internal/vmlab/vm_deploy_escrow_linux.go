// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"filippo.io/age"
)

// encryptDeployEvidence is deliberately confined to maintained lab fixtures.
// It encrypts directly from protected memory to the explicit off-server operator
// recipient. Plaintext custody passphrases and credential-bearing diagnostics
// never enter server/release/support archives. Fixture custodians are not humans.
func encryptDeployEvidence(recipientFile, destination string, plaintext []byte) (err error) {
	body, err := os.ReadFile(recipientFile)
	if err != nil {
		return err
	}
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(string(body)))
	if err != nil {
		return errors.New("deploy escrow requires the explicit lab operator age recipient")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			err = errors.Join(err, os.Remove(destination))
		}
	}()
	encrypted, err := age.Encrypt(file, recipient)
	if err != nil {
		return err
	}
	_, writeErr := io.Copy(encrypted, bytes.NewReader(plaintext))
	return errors.Join(writeErr, encrypted.Close(), file.Sync())
}
