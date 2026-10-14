// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"lindm/internal/deploylab"
	"lindm/internal/labmatrix"
)

// Inspect and hash the same open evidence input. Historical scoped log records
// remain importable; first-run JSON must retain its precise restricted scope.
func matrixImportEvidenceSHA256(path, cell, scope string) (sum string, err error) {
	if cell == "production-release-signing" {
		return productionSigningEvidenceSHA256(path, scope)
	}
	if cell != "deploy" && cell != "lifecycle" {
		return labmatrix.FileSHA256(path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	input := io.TeeReader(file, hash)
	var record struct {
		Scope              string `json:"scope"`
		LifecycleQualified *bool  `json:"lifecycle_qualified"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(input, 8<<20)).Decode(&record)
	if cell == "deploy" && decodeErr != nil && (scope == "" || scope == deploylab.FirstRunInstallScope) {
		return "", errors.New("unscoped deploy or first-run import requires bounded readable JSON evidence; historical logs require their explicit historical scope")
	}
	if decodeErr == nil {
		if record.Scope == productionSigningScope {
			return "", errors.New("production signing tests-only evidence cannot qualify deploy or lifecycle")
		}
		if record.Scope == "production-cold-release-build-only" || record.Scope == "lab-operator-custody-fixture-only" {
			return "", errors.New("cold release build or lab custody fixture evidence cannot qualify deploy or lifecycle")
		}
		if cell == "deploy" && record.Scope == deploylab.FirstRunInstallScope && scope != deploylab.FirstRunInstallScope {
			return "", errors.New("first-run setup evidence requires -scope first-run-install-only; it cannot qualify the full deploy cell")
		}
		if cell == "deploy" && record.LifecycleQualified != nil && !*record.LifecycleQualified && scope == "" {
			return "", errors.New("non-lifecycle evidence cannot be imported as an unscoped deploy result")
		}
	}
	if _, err := io.Copy(io.Discard, input); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
