// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"lindm/internal/deploylab"
)

type VMDeployCustodyExport struct {
	Kind    string `json:"Kind"`
	Path    string `json:"Path"`
	SHA256  string `json:"SHA256"`
	Present bool   `json:"Present"`
}

type VMDeployCustodyStatus struct {
	DeploymentID       string
	PublicURL          string
	DevicePublicURL    string
	ConfigSHA256       string
	ConfirmationSHA256 string
	CreatedAt          string
	External           bool
	RequiresExport     bool
	Exports            []VMDeployCustodyExport
}

func readDeployCustodyStatus(ctx context.Context, guest *guestVM, origin, deviceOrigin string, expected map[string]string) (*VMDeployCustodyStatus, error) {
	body, err := serverGuestCommand(ctx, guest, "read native composite recovery export set", "lindmd custody-status -config /etc/lindm/server.json", nil)
	if err != nil {
		return nil, err
	}
	status := new(VMDeployCustodyStatus)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(status); err != nil {
		return nil, errors.New("deploy custody-status did not return the maintained public provider schema")
	}
	digest, err := hex.DecodeString(status.ConfirmationSHA256)
	if err != nil || len(digest) != 32 || status.DeploymentID == "" || status.PublicURL != origin || status.DevicePublicURL != deviceOrigin || status.External || !status.RequiresExport || len(status.Exports) != len(expected) {
		return nil, errors.New("deploy recovery export set does not match this generated-custody deployment")
	}
	seen := make(map[string]bool, len(status.Exports))
	for _, export := range status.Exports {
		expectedSHA, ok := expected[export.Kind]
		if !ok || seen[export.Kind] || export.SHA256 != expectedSHA || !export.Present || export.Path == "" {
			return nil, errors.New("deploy required recovery ciphertext does not match an observed off-server transfer")
		}
		if export.Kind == "canonical_authority" && export.Path != "/var/lib/lindmd-operations/recovery-custody.age" {
			return nil, errors.New("deploy canonical recovery export has an unexpected protected path")
		}
		if export.Kind == "fresh_database" {
			relative := strings.TrimPrefix(export.Path, "/var/lib/lindmd-operations/database-custody/")
			parts := strings.Split(relative, "/")
			if len(parts) != 2 || parts[1] != "identities.age" || len(parts[0]) != 64 {
				return nil, errors.New("deploy fresh database recovery export has an unexpected protected path")
			}
			if ca, err := hex.DecodeString(parts[0]); err != nil || len(ca) != 32 {
				return nil, errors.New("deploy fresh database recovery export is not bound to the actual CA digest")
			}
		}
		seen[export.Kind] = true
	}
	return status, nil
}

func deployCustodyExports(status *VMDeployCustodyStatus) []deploylab.CustodyExport {
	exports := make([]deploylab.CustodyExport, len(status.Exports))
	for index, export := range status.Exports {
		exports[index] = deploylab.CustodyExport{Kind: export.Kind, Path: export.Path, SHA256: export.SHA256}
	}
	return exports
}

func copyDeploySealedDatabaseCA(ctx context.Context, guest *guestVM, source, destination string, digest *string) error {
	if filepath.Base(source) != "sealed-pki-ca.age" {
		return errors.New("deploy sealed database CA path is invalid")
	}
	sourceHash, err := serverGuestCommand(ctx, guest, "hash protected sealed fresh database CA", "test \"$(stat -c %u "+nativeQuote(source)+")\" = 0; test \"$(stat -c %a "+nativeQuote(source)+")\" = 600; sha256sum "+nativeQuote(source), nil)
	if err != nil {
		return err
	}
	if err := copyDeployBackup(ctx, guest, source, destination, digest); err != nil {
		return err
	}
	fields := strings.Fields(string(sourceHash))
	if len(fields) != 2 || fields[0] != *digest || fields[1] != source {
		return errors.New("off-server sealed database CA digest does not match the protected source")
	}
	return nil
}

func copyDeployEvidence(ctx context.Context, source, destination string, limit int64, expectedSHA256 string) (err error) {
	input, err := openRegular(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, output.Close())
		if err != nil {
			err = errors.Join(err, os.Remove(destination))
		}
	}()
	var target io.Writer = output
	if expectedSHA256 != "" {
		checksum := sha256.New()
		target = io.MultiWriter(output, checksum)
		if _, err := copyVMBytes(ctx, target, input, limit); err != nil {
			return err
		}
		if hex.EncodeToString(checksum.Sum(nil)) != expectedSHA256 {
			return errors.New("deploy evidence copy differs from the verified artifact")
		}
	} else if _, err := copyVMBytes(ctx, target, input, limit); err != nil {
		return err
	}
	return output.Sync()
}
