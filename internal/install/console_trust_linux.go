// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func printConsoleTrust(output io.Writer) error {
	file, err := os.Open("/etc/lindm/console-ca.crt")
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, io.LimitReader(file, 1<<20))
	if err := file.Close(); err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	_, err = fmt.Fprintf(output, "Console CA file: /etc/lindm/console-ca.crt\nConsole CA SHA256 (file bytes): %x\nImport this console CA, not the device CA, with the approved administrator-workstation trust process; never bypass browser certificate verification.\n", hash.Sum(nil))
	return err
}
