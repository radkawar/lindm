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

// escrowDeployPassphrase is deliberately confined to maintained lab fixtures.
// It encrypts directly from memory to the explicit off-server operator recipient
// and never places a recovery-export passphrase into a server/release/support
// archive. Development fixture custodians are not independent human custodians.
func escrowDeployPassphrase(recipientFile, destination string, passphrase []byte) (err error) {
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
	_, writeErr := io.Copy(encrypted, bytes.NewReader(passphrase))
	return errors.Join(writeErr, encrypted.Close())
}
