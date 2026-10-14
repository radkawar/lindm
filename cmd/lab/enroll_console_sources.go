// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"lindm/internal/devlab"
)

// openPackageSourceConsole uses the same signed artifact, owner ceremony and
// clipboard runner as release acceptance. It creates no synthetic device.
func openPackageSourceConsole(ctx context.Context, root, code, server, private, evidence string) (fixture *devlab.AuthorityFixture, configPath string, err error) {
	fixture, err = devlab.OpenEnrollmentConsoleAuthorityFixture(ctx, root, code, server, []string{"amd64"}, "")
	if err != nil {
		return nil, "", err
	}
	owned := fixture
	defer func() {
		if err != nil {
			err = errors.Join(err, owned.Close())
		}
	}()
	if err = configureAcceptanceDispatch(ctx, fixture); err != nil {
		return nil, "", err
	}
	enrollment, err := fixture.CreateAcceptanceEnrollment(ctx, "package-source-owner", "owner")
	if err != nil {
		return nil, "", err
	}
	defer func() { enrollment.Secret = "" }()
	var password [24]byte
	if _, err = rand.Read(password[:]); err != nil {
		return nil, "", err
	}
	defer clear(password[:])
	cfg := acceptanceBrowserConfig{Mode: "enroll", Engine: "chromium", Origin: fixture.ConsoleOrigin, Username: "package-source-owner", EnrollmentSecret: enrollment.GetSecret(), Password: hex.EncodeToString(password[:]), EvidenceDirectory: filepath.Join(evidence, "console"), ResultPath: filepath.Join(private, "owner-result.json"), CredentialPath: filepath.Join(private, "owner-credential.json"), TimeoutMS: 120000}
	browser, err := runAcceptanceBrowser(ctx, code, private, cfg)
	browser.Grant.Secret, browser.Token.Secret = "", ""
	cfg.EnrollmentSecret = ""
	if err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, "", err
	}
	defer clear(data)
	configPath = filepath.Join(private, "owner-config.json")
	if err = os.WriteFile(configPath, data, 0600); err != nil {
		return nil, "", err
	}
	return fixture, configPath, nil
}
