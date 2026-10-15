// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"path/filepath"
	"strconv"

	"lindm/internal/platform"
)

// These are references, never private key contents or a command replacement.
// All server OS lanes consume the same independently authenticated exports.
type deployMatrixInputs struct {
	FirstRelease               string `json:"firstRelease"`
	UpgradeRelease             string `json:"upgradeRelease"`
	ReleasePublicKey           string `json:"releasePublicKey"`
	ReleaseKeyID               string `json:"releaseKeyID"`
	TUFRootFile                string `json:"tufRootFile"`
	BackupRecipientFile        string `json:"backupRecipientFile"`
	CustodyEscrowRecipientFile string `json:"custodyEscrowRecipientFile"`
	BackupIdentityFile         string `json:"backupIdentityFile"`
	Lindmd                     string `json:"lindmd"`
	Lindmctl                   string `json:"lindmctl"`
	DeviceManifest             string `json:"deviceManifest,omitempty"`
	// Optional per-major off-server clients; absent entries use native tools.
	DrillImages map[string]string `json:"drillImages,omitempty"`
}

func readMatrixDeployInputs(path string) (*deployMatrixInputs, error) {
	inputs := new(deployMatrixInputs)
	if err := readConsoleBrowserJSON(path, inputs); err != nil {
		return nil, err
	}
	for _, value := range []string{inputs.FirstRelease, inputs.UpgradeRelease, inputs.ReleasePublicKey, inputs.TUFRootFile, inputs.BackupRecipientFile, inputs.CustodyEscrowRecipientFile, inputs.BackupIdentityFile, inputs.Lindmd, inputs.Lindmctl} {
		if !filepath.IsAbs(value) {
			return nil, errors.New("deploy matrix inputs require absolute authenticated artifact and protected backup input paths")
		}
	}
	if inputs.DeviceManifest != "" && !filepath.IsAbs(inputs.DeviceManifest) {
		return nil, errors.New("deploy matrix device manifest requires an absolute pinned image path")
	}
	if len(inputs.ReleaseKeyID) != 64 {
		return nil, errors.New("deploy matrix inputs require independently pinned release key ID")
	}
	for version, image := range inputs.DrillImages {
		major, err := strconv.Atoi(version)
		if err != nil || strconv.Itoa(major) != version || !platform.PostgreSQLMajorSupported(major) {
			return nil, errors.New("drill image map keys must be supported PostgreSQL majors")
		}
		if image == "" {
			return nil, errors.New("configured drill image must not be empty")
		}
		if err := validateDeployDrillImage(image); err != nil {
			return nil, err
		}
	}
	return inputs, nil
}

func (inputs *deployMatrixInputs) args() []string {
	args := []string{"-first-release", inputs.FirstRelease, "-upgrade-release", inputs.UpgradeRelease, "-release-public-key", inputs.ReleasePublicKey, "-release-key-id", inputs.ReleaseKeyID, "-tuf-root-file", inputs.TUFRootFile, "-backup-recipient-file", inputs.BackupRecipientFile, "-custody-escrow-recipient-file", inputs.CustodyEscrowRecipientFile, "-backup-identity-file", inputs.BackupIdentityFile, "-lindmd", inputs.Lindmd, "-lindmctl", inputs.Lindmctl}
	if inputs.DeviceManifest != "" {
		args = append(args, "-device-manifest", inputs.DeviceManifest)
	}
	return args
}
