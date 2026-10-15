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
	if scope == labmatrix.CinnamonLockConfirmationScope {
		return "", errors.New("native Cinnamon lock confirmation requires its dedicated matrix cell")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	input := io.TeeReader(file, hash)
	var record struct {
		Scope              string          `json:"scope"`
		LifecycleQualified *bool           `json:"lifecycle_qualified"`
		FindingsExcluded   bool            `json:"findings_excluded"`
		CinnamonLock       json.RawMessage `json:"cinnamon_lock"`
		WipePhase          string          `json:"wipe_phase"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(input, 8<<20)).Decode(&record)
	if decodeErr != nil && (scope == deploylab.ServerLifecycleScope || (cell == "deploy" && (scope == "" || scope == deploylab.FirstRunInstallScope))) {
		return "", errors.New("unscoped deploy or first-run import requires bounded readable JSON evidence; historical logs require their explicit historical scope")
	}
	if decodeErr == nil {
		if record.CinnamonLock != nil || record.WipePhase == "cinnamon-lock-confirmation" {
			return "", errors.New("native Cinnamon lock confirmation cannot qualify the complete device-action lane or another feature")
		}
	}
	if decodeErr == nil && (cell == "deploy" || cell == "lifecycle") {
		if record.Scope == deploylab.ServerLifecycleScope || record.FindingsExcluded || scope == deploylab.ServerLifecycleScope {
			if record.Scope != deploylab.ServerLifecycleScope || scope != deploylab.ServerLifecycleScope || !record.FindingsExcluded || record.LifecycleQualified == nil || *record.LifecycleQualified {
				return "", errors.New("server lifecycle without Findings requires matching -scope native-server-lifecycle-without-findings, findings_excluded:true and lifecycle_qualified:false")
			}
		}
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
