// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"lindm/internal/labmatrix"
)

const productionSigningScope = "production-signing-tests-only"

func productionSigningEvidenceSHA256(path, scope string, imageIDs ...string) (sum string, err error) {
	if scope != productionSigningScope {
		return "", errors.New("production signing evidence requires -scope production-signing-tests-only; it cannot qualify deploy or lifecycle")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return "", errors.New("production signing evidence must be a bounded regular JSON file")
	}
	decoder := json.NewDecoder(io.TeeReader(io.LimitReader(file, 8<<20), hash))
	var record struct {
		Scope                string            `json:"scope"`
		LifecycleQualified   *bool             `json:"lifecycle_qualified"`
		Passed               bool              `json:"passed"`
		OwnedCleanupComplete bool              `json:"owned_cleanup_complete"`
		GuestNoSwap          bool              `json:"guest_no_swap"`
		SourceSHA256         string            `json:"source_sha256"`
		ImageID              string            `json:"image_id"`
		ImageSHA256          string            `json:"image_sha256"`
		StartedAt            time.Time         `json:"started_at"`
		FinishedAt           time.Time         `json:"finished_at"`
		ToolVersions         map[string]string `json:"tool_versions"`
		TestEvidence         []struct {
			Name   string `json:"name"`
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		} `json:"test_evidence"`
	}
	if err := decoder.Decode(&record); err != nil {
		return "", err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return "", errors.New("production signing record must contain exactly one JSON object")
	}
	for _, imageID := range imageIDs {
		if imageID != "" && imageID != record.ImageID {
			return "", errors.New("production signing evidence image identity differs from the matrix image")
		}
	}
	validDigest := func(value string) bool {
		bytes, err := hex.DecodeString(value)
		return err == nil && len(bytes) == sha256.Size
	}
	if record.Scope != scope || record.LifecycleQualified == nil || *record.LifecycleQualified || !record.Passed || !record.OwnedCleanupComplete || !record.GuestNoSwap || !validDigest(record.SourceSHA256) || !validDigest(record.ImageSHA256) || record.ImageID == "" || record.StartedAt.IsZero() || record.FinishedAt.Before(record.StartedAt) || len(record.ToolVersions) == 0 || len(record.TestEvidence) == 0 {
		return "", errors.New("production signing record lacks successful tests-only, no-swap, cleanup or source/image metadata")
	}
	for name, version := range record.ToolVersions {
		if name == "" || version == "" {
			return "", errors.New("production signing tool version is empty")
		}
	}
	for _, evidence := range record.TestEvidence {
		if evidence.Name == "" || evidence.Path == "" || !validDigest(evidence.SHA256) || evidence.Size < 0 {
			return "", errors.New("production signing test evidence metadata is incomplete")
		}
		info, err := os.Stat(evidence.Path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Size() != evidence.Size {
			return "", errors.New("production signing test evidence size changed")
		}
		digest, err := labmatrix.FileSHA256(evidence.Path)
		if err != nil {
			return "", err
		}
		if digest != evidence.SHA256 {
			return "", errors.New("production signing test evidence hash changed")
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
