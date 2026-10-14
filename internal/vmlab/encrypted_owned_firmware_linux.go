// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ownedFirmwareDBOwner = "5f28c885-908b-4d8b-88a9-7f949fa6c219"
const firmwareGlobalGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
const firmwareDBGUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
const firmwareX509GUID = "\xa1\x59\xc0\xa5\xe4\x94\xa7\x4a\x87\xb5\xab\x15\x5c\x2b\xf0\x72"

type ownedFirmwareVariable struct {
	Name string `json:"name"`
	GUID string `json:"guid"`
	Attr uint32 `json:"attr"`
	Data string `json:"data"`
	Time string `json:"time"`
}

// readOwnedFirmwareCertificate accepts only a single public certificate, never a
// key bundle. The tool receives a canonical copy, not the caller's mutable path.
func readOwnedFirmwareCertificate(path string) (_ *x509.Certificate, err error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, fmt.Errorf("open owned firmware certificate: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	return parseOwnedFirmwareCertificate(data)
}

func parseOwnedFirmwareCertificate(data []byte) (*x509.Certificate, error) {
	if len(data) > 64<<10 {
		return nil, errors.New("owned firmware certificate exceeds size limit")
	}
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Count(data, []byte("-----BEGIN ")) != 1 {
		return nil, errors.New("owned firmware signer requires one public PEM certificate")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("owned firmware signer requires one public PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse owned firmware certificate: %w", err)
	}
	return certificate, nil
}

// enrollOwnedFirmwareDB modifies only a disposable copy of the package-owned
// template. PK/KEK and all existing trust/revocations must survive unchanged.
func enrollOwnedFirmwareDB(ctx context.Context, dir string, evidence *EncryptedFirmwareEvidence, certificate *x509.Certificate) (err error) {
	before, err := encryptedHostOutput(ctx, dir, time.Minute, "virt-fw-vars", "--input", evidence.VarsPath, "--output-json", "/dev/stdout")
	if err != nil {
		return fmt.Errorf("inspect source firmware trust: %w", err)
	}
	if err := encryptedEnrolledVars(before); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(dir, ".owned-db-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()
	certPath := filepath.Join(staging, "signer.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0600); err != nil {
		return err
	}
	output := filepath.Join(staging, "enrolled.fd")
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if _, err := encryptedHostOutput(ctx, staging, time.Minute, "virt-fw-vars", "--input", evidence.VarsPath, "--output", output, "--add-db", ownedFirmwareDBOwner, certPath); err != nil {
		return fmt.Errorf("enroll owned firmware db certificate: %w", err)
	}
	info, err := os.Lstat(output)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("owned firmware derivative must remain a private regular file")
	}
	after, err := encryptedHostOutput(ctx, staging, time.Minute, "virt-fw-vars", "--input", output, "--output-json", "/dev/stdout")
	if err != nil {
		return fmt.Errorf("inspect owned firmware db enrollment: %w", err)
	}
	if err := validateOwnedFirmwareEnrollment(before, after, certificate.Raw); err != nil {
		return err
	}
	// Copy through the bounded regular-file helper; do not publish a tool-created
	// inode as the run's NVRAM. The initial package copy survives any failure.
	published := filepath.Join(staging, "verified.fd")
	digest, err := copyEncryptedFirmware(ctx, output, published)
	if err != nil {
		return err
	}
	if err := os.Rename(published, evidence.VarsPath); err != nil {
		return err
	}
	sum := sha256.Sum256(certificate.Raw)
	evidence.OwnedDBCertificateSHA256 = hex.EncodeToString(sum[:])
	evidence.OwnedDBEnrolled = true
	evidence.EnrolledKeys = true
	evidence.VarsSHA256 = digest
	return nil
}

func ownedFirmwareVariables(data []byte) (map[string]ownedFirmwareVariable, error) {
	if err := encryptedEnrolledVars(data); err != nil {
		return nil, err
	}
	var store struct {
		Variables []ownedFirmwareVariable `json:"variables"`
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	variables := make(map[string]ownedFirmwareVariable, len(store.Variables))
	for _, variable := range store.Variables {
		variable.GUID = strings.ToLower(variable.GUID)
		key := variable.GUID + "/" + variable.Name
		if _, exists := variables[key]; exists {
			return nil, errors.New("duplicate firmware variable")
		}
		if _, err := hex.DecodeString(variable.Data); err != nil {
			return nil, errors.New("malformed firmware variable data")
		}
		variables[key] = variable
	}
	return variables, nil
}

func validateOwnedFirmwareEnrollment(before, after, certificate []byte) error {
	original, err := ownedFirmwareVariables(before)
	if err != nil {
		return err
	}
	derivative, err := ownedFirmwareVariables(after)
	if err != nil {
		return err
	}
	if len(original) != len(derivative) {
		return errors.New("owned firmware enrollment changed unrelated variables")
	}
	for key, variable := range original {
		updated, exists := derivative[key]
		if !exists {
			return errors.New("owned firmware enrollment removed an existing variable")
		}
		if key != firmwareDBGUID+"/db" {
			if updated != variable {
				return errors.New("owned firmware enrollment changed unrelated trust or state")
			}
			continue
		}
		if variable.Attr != updated.Attr {
			return errors.New("owned firmware enrollment changed db attributes")
		}
		oldDB, err := hex.DecodeString(variable.Data)
		if err != nil {
			return err
		}
		newDB, err := hex.DecodeString(updated.Data)
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(newDB, oldDB) {
			return errors.New("owned firmware enrollment replaced vendor db trust")
		}
		if err := ownedFirmwareDBContains(newDB, certificate); err != nil {
			return err
		}
	}
	return nil
}

// UEFI signature lists contain little-endian size fields and owner-prefixed
// signatures. Match the complete DER only in an X.509 list, not arbitrary bytes
// elsewhere in NVRAM, and reject malformed trailing lists even after a match.
func ownedFirmwareDBContains(data, certificate []byte) error {
	found := false
	for len(data) > 0 {
		if len(data) < 28 {
			return errors.New("truncated firmware signature list")
		}
		size := uint64(binary.LittleEndian.Uint32(data[16:20]))
		header := uint64(binary.LittleEndian.Uint32(data[20:24]))
		signature := uint64(binary.LittleEndian.Uint32(data[24:28]))
		if size < 28 || size > uint64(len(data)) || header > size-28 || signature <= 16 || (size-28-header)%signature != 0 || size-28-header == 0 {
			return errors.New("invalid firmware signature list bounds")
		}
		if string(data[:16]) == firmwareX509GUID {
			for offset := 28 + header; offset < size; offset += signature {
				found = found || bytes.Equal(data[offset+16:offset+signature], certificate)
			}
		}
		data = data[size:]
	}
	if !found {
		return errors.New("owned signer certificate is absent from firmware db")
	}
	return nil
}
