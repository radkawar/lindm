// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// consoleBrowserCapture is a nonsecret binding to an actual browser Copy event.
// Commands and credentials from the runner's protected result are not retained.
type consoleBrowserCapture struct {
	SHA256      string   `json:"command_sha256"`
	Source      string   `json:"source"`
	Screenshots []string `json:"screenshots"`
}

func captureConsoleBrowser(ctx context.Context, repository, private, configPath, commandPath string, manifest *labv1.ImageManifest) (*consoleBrowserCapture, error) {
	var cfg acceptanceBrowserConfig
	if err := readConsoleBrowserJSON(configPath, &cfg); err != nil {
		return nil, err
	}
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	family, err := consoleEnrollmentFamily(release.Native().Packages.Backend)
	if err != nil {
		return nil, err
	}
	cfg.Mode, cfg.Engine = "grant", "chromium"
	cfg.RequireRepositories, cfg.EnrollmentScreenshots = true, true
	cfg.EnrollmentPlatforms = map[string]string{family: release.Name}
	cfg.EnrollmentCommandPaths = map[string]string{family: commandPath}
	cfg.ResultPath = filepath.Join(private, "browser-result.json")
	if cfg.EvidenceDirectory == "" {
		return nil, errors.New("browser capture requires a persistent private evidenceDirectory for screenshots")
	}
	browser, err := runAcceptanceBrowser(ctx, repository, private, cfg)
	browser.Grant.Secret, browser.Token.Secret = "", ""
	cfg.Password, cfg.EnrollmentSecret = "", ""
	if err != nil {
		return nil, err
	}
	var captured struct {
		Grant struct {
			SHA256  map[string]string `json:"commandSHA256"`
			Sources map[string]string `json:"commandSources"`
		} `json:"grant"`
		Screenshots []string `json:"screenshots"`
	}
	if err := readConsoleBrowserJSON(cfg.ResultPath, &captured); err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(captured.Grant.SHA256[family])
	if err != nil || len(digest) != 32 || captured.Grant.Sources[family] != "browser-clipboard" || len(captured.Screenshots) == 0 {
		return nil, errors.New("browser did not provide a clipboard command binding and screenshots")
	}
	return &consoleBrowserCapture{SHA256: captured.Grant.SHA256[family], Source: captured.Grant.Sources[family], Screenshots: captured.Screenshots}, nil
}

func consoleEnrollmentFamily(backend platform.Backend) (string, error) {
	switch backend {
	case platform.BackendAPT:
		return "apt", nil
	case platform.BackendDNF4, platform.BackendDNF5:
		return "dnf", nil
	case platform.BackendPacman:
		return "pacman", nil
	case platform.BackendZypper:
		return "zypper", nil
	default:
		return "", errors.New("console enrollment requires a registered native package family")
	}
}

type consoleBrowserEnrollment struct {
	DeviceID    string   `json:"device_id"`
	Lifecycle   string   `json:"lifecycle"`
	Screenshots []string `json:"screenshots"`
	// ToolCustodyPath is the unprotected tool path the device page named with
	// its remedy; set only for a stock image whose / the agent refuses.
	ToolCustodyPath string `json:"tool_custody_path,omitempty"`
}

// confirmConsoleBrowserEnrollment requires the exact device's Enrolled state
// and, when expectToolPath is set, the device page's unprotected-tool-path
// alert naming that path and its native remedy.
func confirmConsoleBrowserEnrollment(ctx context.Context, repository, private, configPath, deviceID, expectToolPath string) (*consoleBrowserEnrollment, error) {
	var cfg acceptanceBrowserConfig
	if err := readConsoleBrowserJSON(configPath, &cfg); err != nil {
		return nil, err
	}
	cfg.Mode, cfg.Engine, cfg.DeviceID = "enrollment-status", "chromium", deviceID
	cfg.EnrollmentCommandPaths, cfg.EnrollmentPlatforms = nil, nil
	cfg.EnrollmentSecret = ""
	cfg.ExpectToolCustodyPath = expectToolPath
	// Light/dark desktop/mobile captures of the alert, never of a credential.
	cfg.EnrollmentScreenshots = expectToolPath != ""
	cfg.ResultPath = filepath.Join(private, "browser-enrollment-result.json")
	_, err := runAcceptanceBrowser(ctx, repository, private, cfg)
	cfg.Password = ""
	if err != nil {
		return nil, err
	}
	var confirmation struct {
		EnrolledDevice struct {
			DeviceID    string `json:"deviceId"`
			Lifecycle   string `json:"lifecycle"`
			ToolCustody struct {
				Path   string `json:"path"`
				Remedy bool   `json:"remedy"`
			} `json:"toolCustody"`
		} `json:"enrolledDevice"`
		Screenshots []string `json:"screenshots"`
	}
	if err := readConsoleBrowserJSON(cfg.ResultPath, &confirmation); err != nil {
		return nil, err
	}
	if confirmation.EnrolledDevice.DeviceID != deviceID || confirmation.EnrolledDevice.Lifecycle != "Enrolled" || len(confirmation.Screenshots) == 0 {
		return nil, errors.New("browser did not confirm the installed device is enrolled on the server")
	}
	custody := confirmation.EnrolledDevice.ToolCustody
	if expectToolPath != "" && (custody.Path != expectToolPath || !custody.Remedy) {
		return nil, errors.New("browser did not show the device's unprotected tool path with its remedy")
	}
	return &consoleBrowserEnrollment{DeviceID: deviceID, Lifecycle: confirmation.EnrolledDevice.Lifecycle, Screenshots: confirmation.Screenshots, ToolCustodyPath: custody.Path}, nil
}

func readConsoleBrowserJSON(path string, target any) (err error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 1<<20 {
		return errors.New("browser capture configuration/result must be an owned mode0600 bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	defer clear(data)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("browser capture document exceeds bound")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return errors.New("browser capture document is invalid JSON")
	}
	return nil
}
