// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"path/filepath"
)

// These are references, never private key contents or a command replacement.
// Both server OS lanes consume the same independently authenticated exports.
type deployMatrixInputs struct {
	FirstRelease        string `json:"firstRelease"`
	UpgradeRelease      string `json:"upgradeRelease"`
	ReleasePublicKey    string `json:"releasePublicKey"`
	ReleaseKeyID        string `json:"releaseKeyID"`
	TUFRootFile         string `json:"tufRootFile"`
	BackupRecipientFile string `json:"backupRecipientFile"`
	BackupIdentityFile  string `json:"backupIdentityFile"`
	Lindmd              string `json:"lindmd"`
	Lindmctl            string `json:"lindmctl"`
}

func readMatrixDeployInputs(path string) (*deployMatrixInputs, error) {
	inputs := new(deployMatrixInputs)
	if err := readConsoleBrowserJSON(path, inputs); err != nil {
		return nil, err
	}
	for _, value := range []string{inputs.FirstRelease, inputs.UpgradeRelease, inputs.ReleasePublicKey, inputs.TUFRootFile, inputs.BackupRecipientFile, inputs.BackupIdentityFile, inputs.Lindmd, inputs.Lindmctl} {
		if !filepath.IsAbs(value) {
			return nil, errors.New("deploy matrix inputs require absolute authenticated artifact and protected backup input paths")
		}
	}
	if len(inputs.ReleaseKeyID) != 64 {
		return nil, errors.New("deploy matrix inputs require independently pinned release key ID")
	}
	return inputs, nil
}

func (inputs *deployMatrixInputs) args() []string {
	return []string{"-first-release", inputs.FirstRelease, "-upgrade-release", inputs.UpgradeRelease, "-release-public-key", inputs.ReleasePublicKey, "-release-key-id", inputs.ReleaseKeyID, "-tuf-root-file", inputs.TUFRootFile, "-backup-recipient-file", inputs.BackupRecipientFile, "-backup-identity-file", inputs.BackupIdentityFile, "-lindmd", inputs.Lindmd, "-lindmctl", inputs.Lindmctl}
}
