// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/google/uuid"

	"lindm/internal/devlab"
	"lindm/internal/platform"
)

// consoleProvisioningCapture is a nonsecret binding to a real browser Copy of
// one provisioning snippet. The token secret and snippet bytes are not retained.
type consoleProvisioningCapture struct {
	SHA256           string   `json:"snippet_sha256"`
	Source           string   `json:"source"`
	Format           string   `json:"format"`
	Platform         string   `json:"platform"`
	TokenID          string   `json:"token_id"`
	ApprovalRequired bool     `json:"approval_required"`
	Screenshots      []string `json:"screenshots"`
}

// consoleProvisioningApproval records the independent-approval path through
// visible console controls: the approver decides, the token creator executes.
type consoleProvisioningApproval struct {
	InstallationID    string   `json:"installation_id"`
	DeviceID          string   `json:"device_id"`
	ApprovalID        string   `json:"approval_id"`
	TokenID           string   `json:"token_id"`
	ApproverAccount   string   `json:"approver"`
	RequesterExecuted bool     `json:"requester_executed"`
	Lifecycle         string   `json:"lifecycle"`
	Screenshots       []string `json:"screenshots"`
}

// consoleProvisioningHost is the lab public console host named by a
// provisioning browser config's origin; guests map it to the fixture.
func consoleProvisioningHost(configPath string) (string, error) {
	var cfg acceptanceBrowserConfig
	if err := readConsoleBrowserJSON(configPath, &cfg); err != nil {
		return "", err
	}
	host, err := provisioningBrowserHost(&cfg)
	cfg.Password = ""
	if cfg.Approver != nil {
		cfg.Approver.Password = ""
	}
	return host, err
}

// provisioningBrowserHost requires the public-host origin of
// `lab console-enrollment -public-host` and a Chromium resolver rule mapping
// exactly that host to the loopback fixture (or its reverse forward).
func provisioningBrowserHost(cfg *acceptanceBrowserConfig) (string, error) {
	origin, err := url.Parse(cfg.Origin)
	if err != nil || origin.Scheme != "https" || origin.User != nil || origin.Port() == "" || origin.Scheme+"://"+origin.Host != cfg.Origin {
		return "", errors.New("provisioning browser config requires an exact https://HOST:PORT origin")
	}
	host := origin.Hostname()
	if err := devlab.ValidatePublicHost(host); err != nil {
		return "", errors.New("provisioning browser origin must name the console's -public-host, not localhost or an address")
	}
	if cfg.HostResolverRules != "MAP "+host+" 127.0.0.1" {
		return "", errors.New("provisioning browser config requires hostResolverRules \"MAP " + host + " 127.0.0.1\"")
	}
	if cfg.EvidenceDirectory == "" {
		return "", errors.New("provisioning browser config requires a persistent private evidenceDirectory for screenshots")
	}
	return host, nil
}

func captureConsoleProvisioning(ctx context.Context, repository, private, configPath, snippetPath, format string, release *platform.Release) (*consoleProvisioningCapture, error) {
	var cfg acceptanceBrowserConfig
	if err := readConsoleBrowserJSON(configPath, &cfg); err != nil {
		return nil, err
	}
	// This run is the owner's alone; the approver's password never enters it.
	cfg.Approver = nil
	defer func() { cfg.Password = "" }()
	if _, err := provisioningBrowserHost(&cfg); err != nil {
		return nil, err
	}
	if release == nil || !slices.Contains(release.Provisioning, platform.Provisioning(format)) || platform.Provisioning(format) == platform.ProvisionNixOS {
		return nil, errors.New("provisioning capture requires an installer format the release offers")
	}
	if !filepath.IsAbs(snippetPath) {
		return nil, errors.New("provisioning snippet destination must be absolute")
	}
	if _, err := os.Lstat(snippetPath); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("provisioning snippet destination must not exist")
	}
	cfg.Mode, cfg.Engine = "provision", "chromium"
	cfg.EnrollmentScreenshots = true
	cfg.ProvisionFormat, cfg.ProvisionPlatform, cfg.ProvisionSnippetPath = format, release.Name, snippetPath
	cfg.EnrollmentPlatforms, cfg.EnrollmentCommandPaths, cfg.RequireRepositories = nil, nil, false
	cfg.EnrollmentSecret, cfg.DeviceID, cfg.InstallationID = "", "", ""
	cfg.ResultPath = filepath.Join(private, "browser-provision-result.json")
	browser, err := runAcceptanceBrowser(ctx, repository, private, cfg)
	browser.Grant.Secret, browser.Token.Secret = "", ""
	if err != nil {
		return nil, err
	}
	var captured struct {
		Provision struct {
			TokenID          string `json:"tokenId"`
			Format           string `json:"format"`
			Platform         string `json:"platform"`
			ApprovalRequired bool   `json:"approvalRequired"`
			SHA256           string `json:"snippetSHA256"`
			Source           string `json:"snippetSource"`
		} `json:"provision"`
		Screenshots []string `json:"screenshots"`
	}
	if err := readConsoleBrowserJSON(cfg.ResultPath, &captured); err != nil {
		return nil, err
	}
	p := captured.Provision
	digest, err := hex.DecodeString(p.SHA256)
	if err != nil || len(digest) != sha256.Size || p.Source != "browser-clipboard" || len(captured.Screenshots) == 0 {
		return nil, errors.New("browser did not provide a clipboard snippet binding and screenshots")
	}
	if p.Format != format || p.Platform != release.Name || !p.ApprovalRequired || !canonicalUUID(p.TokenID) {
		return nil, errors.New("browser provisioning token differs from the requested approval-required format and platform")
	}
	written, err := consoleSnippetDigest(snippetPath)
	if err != nil {
		return nil, err
	}
	if written != p.SHA256 {
		return nil, errors.New("written provisioning snippet differs from the browser clipboard")
	}
	return &consoleProvisioningCapture{SHA256: p.SHA256, Source: p.Source, Format: p.Format, Platform: p.Platform, TokenID: p.TokenID, ApprovalRequired: p.ApprovalRequired, Screenshots: captured.Screenshots}, nil
}

// consoleSnippetDigest hashes the runner's private snippet file without
// following links, so the lane feeds exactly the bytes the clipboard held.
func consoleSnippetDigest(path string) (_ string, err error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 1<<20 {
		return "", errors.New("provisioning snippet must be an owned mode0600 bounded regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 1<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func approveConsoleProvisioning(ctx context.Context, repository, private, configPath, installationID string) (*consoleProvisioningApproval, error) {
	var cfg acceptanceBrowserConfig
	if err := readConsoleBrowserJSON(configPath, &cfg); err != nil {
		return nil, err
	}
	defer func() {
		cfg.Password = ""
		if cfg.Approver != nil {
			cfg.Approver.Password = ""
		}
	}()
	if _, err := provisioningBrowserHost(&cfg); err != nil {
		return nil, err
	}
	if err := validateConsoleApprover(&cfg); err != nil {
		return nil, err
	}
	if !canonicalUUID(installationID) {
		return nil, errors.New("provisioning approval requires the guest's pending installation ID")
	}
	cfg.Mode, cfg.Engine, cfg.InstallationID = "approve-enrollment", "chromium", installationID
	// Pending lookup (≤2 min) plus server-side Enrolled (≤3 min) within the
	// runner's 8-minute process bound, including its 45 s close grace.
	cfg.TimeoutMS = 420_000
	cfg.EnrollmentPlatforms, cfg.EnrollmentCommandPaths, cfg.RequireRepositories = nil, nil, false
	cfg.EnrollmentScreenshots = false
	cfg.EnrollmentSecret, cfg.DeviceID = "", ""
	cfg.ProvisionFormat, cfg.ProvisionPlatform, cfg.ProvisionSnippetPath = "", "", ""
	cfg.ResultPath = filepath.Join(private, "browser-approval-result.json")
	if _, err := runAcceptanceBrowser(ctx, repository, private, cfg); err != nil {
		return nil, err
	}
	var approved struct {
		Approval struct {
			InstallationID    string `json:"installationId"`
			DeviceID          string `json:"deviceId"`
			ApprovalID        string `json:"approvalId"`
			TokenID           string `json:"tokenId"`
			Approver          string `json:"approver"`
			Approved          bool   `json:"approved"`
			RequesterExecuted bool   `json:"requesterExecuted"`
		} `json:"approval"`
		EnrolledDevice struct {
			DeviceID  string `json:"deviceId"`
			Lifecycle string `json:"lifecycle"`
		} `json:"enrolledDevice"`
		Screenshots []string `json:"screenshots"`
	}
	if err := readConsoleBrowserJSON(cfg.ResultPath, &approved); err != nil {
		return nil, err
	}
	a := approved.Approval
	if a.InstallationID != installationID || !canonicalUUID(a.DeviceID) || !canonicalUUID(a.ApprovalID) || !canonicalUUID(a.TokenID) || a.Approver != cfg.Approver.Username || !a.Approved || !a.RequesterExecuted {
		return nil, errors.New("browser did not approve and execute the exact pending enrollment as two humans")
	}
	if approved.EnrolledDevice.DeviceID != a.DeviceID || approved.EnrolledDevice.Lifecycle != "Enrolled" || len(approved.Screenshots) == 0 {
		return nil, errors.New("browser did not confirm the approved device is enrolled on the server")
	}
	return &consoleProvisioningApproval{InstallationID: installationID, DeviceID: a.DeviceID, ApprovalID: a.ApprovalID, TokenID: a.TokenID, ApproverAccount: a.Approver, RequesterExecuted: a.RequesterExecuted, Lifecycle: approved.EnrolledDevice.Lifecycle, Screenshots: approved.Screenshots}, nil
}

// validateConsoleApprover requires a second, distinct human with its own
// password and owned private passkey state.
func validateConsoleApprover(cfg *acceptanceBrowserConfig) error {
	a := cfg.Approver
	if a == nil || a.Username == "" || a.Password == "" || a.CredentialPath == "" {
		return errors.New("provisioning approval requires approver username, password and credentialPath")
	}
	if a.Username == cfg.Username || filepath.Clean(a.CredentialPath) == filepath.Clean(cfg.CredentialPath) {
		return errors.New("provisioning approver must be a distinct account with its own credential file")
	}
	var state struct {
		Origin   string `json:"origin"`
		Username string `json:"username"`
	}
	if err := readConsoleBrowserJSON(a.CredentialPath, &state); err != nil {
		return err
	}
	if state.Origin != cfg.Origin || state.Username != a.Username {
		return errors.New("provisioning approver credential is not enrolled for this console origin and account")
	}
	return nil
}

// canonicalUUID admits only the lowercase hyphenated form the console shows.
func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}
