package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"lindm/internal/devlab"
)

type acceptanceBrowser struct {
	Engine               string          `json:"engine"`
	Passed               bool            `json:"passed"`
	Failure              json.RawMessage `json:"failure,omitempty"`
	Steps                json.RawMessage `json:"steps,omitempty"`
	Versions             json.RawMessage `json:"versions,omitempty"`
	Screenshots          []string        `json:"screenshots,omitempty"`
	PasswordPhase        json.RawMessage `json:"passwordPhase,omitempty"`
	PasskeyPhase         json.RawMessage `json:"passkeyPhase,omitempty"`
	OriginPost           json.RawMessage `json:"originPost,omitempty"`
	Storage              json.RawMessage `json:"storage,omitempty"`
	StorageNotApplicable json.RawMessage `json:"storageNotApplicable,omitempty"`
	Assignment           json.RawMessage `json:"assignment,omitempty"`
	CleanupFailure       string          `json:"cleanupFailure,omitempty"`
	Grant                struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	} `json:"grant"`
	Token struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	} `json:"token"`
}

type acceptanceBrowserConfig struct {
	Mode                       string                   `json:"mode"`
	Engine                     string                   `json:"engine"`
	Origin                     string                   `json:"origin"`
	Username                   string                   `json:"username"`
	EnrollmentSecret           string                   `json:"enrollmentSecret,omitempty"`
	Password                   string                   `json:"password"`
	EvidenceDirectory          string                   `json:"evidenceDirectory"`
	ResultPath                 string                   `json:"resultPath"`
	CredentialPath             string                   `json:"credentialPath"`
	TimeoutMS                  int                      `json:"timeoutMs"`
	DeviceID                   string                   `json:"deviceId,omitempty"`
	ProfileRevisionID          string                   `json:"profileRevisionId,omitempty"`
	StorageActions             []string                 `json:"storageActions"`
	RequireNoWWN               bool                     `json:"requireNoWWN"`
	StorageNotApplicableReason string                   `json:"storageNotApplicableReason,omitempty"`
	IgnoreHTTPSErrors          bool                     `json:"ignoreHTTPSErrors"`
	PasswordProbe              *acceptancePasswordProbe `json:"passwordProbe,omitempty"`
}

type acceptancePasswordProbe struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type acceptanceRecord struct {
	StartedAt            time.Time                    `json:"started_at"`
	DurationSeconds      float64                      `json:"duration_seconds"`
	Mode                 string                       `json:"mode"`
	Passed               bool                         `json:"passed"`
	Browsers             []acceptanceBrowser          `json:"browsers"`
	Feeds                *devlab.AcceptanceFeedResult `json:"feeds,omitempty"`
	Native               any                          `json:"native,omitempty"`
	Failures             []string                     `json:"failures,omitempty"`
	OwnedCleanupComplete bool                         `json:"owned_cleanup_complete"`
	ServerSHA256         string                       `json:"server_sha256"`
	LabSHA256            string                       `json:"lab_sha256"`
}

type acceptanceOptions struct {
	repository, fixture, binary, labBinary, evidence, cache, work, host  string
	webOnly                                                              bool
	skipFeeds                                                            bool
	feedBytes                                                            int64
	feedDuration                                                         time.Duration
	firmwareCode, firmwareVars, firmwarePackage, firmwareVersion, golden string
}

func runAcceptance(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("acceptance", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options acceptanceOptions
	flags.StringVar(&options.repository, "repo", ".", "checkout under test: browser journeys and native package sources")
	flags.StringVar(&options.fixture, "fixture", "", "checkout with protected dev trust and live PostgreSQL (default -repo)")
	flags.StringVar(&options.binary, "lindmd", "artifacts/bin/lindmd", "release-stamped real server with embedded console")
	flags.StringVar(&options.labBinary, "lab-binary", "artifacts/bin/lab", "matching native guest probe")
	flags.StringVar(&options.evidence, "evidence", "", "new private directory for report and cross-browser screenshots")
	flags.StringVar(&options.cache, "cache", ".cache/lab/images", "verified vendor-image cache")
	flags.StringVar(&options.work, "work-dir", "", "parent for owned disposable VM state")
	flags.BoolVar(&options.skipFeeds, "skip-feeds", false, "diagnostic only: omit feed refresh/exposure qualification; never a release pass")
	flags.StringVar(&options.host, "host", "local", "configured native lab host")
	flags.BoolVar(&options.webOnly, "web-only", false, "fast browser journey only; not a full release pass")
	flags.Int64Var(&options.feedBytes, "feed-byte-budget", 2<<30, "total vendor feed bytes, including digest-verified cache hits")
	flags.DurationVar(&options.feedDuration, "feed-duration-budget", 15*time.Minute, "complete real vendor refresh deadline")
	flags.StringVar(&options.golden, "golden-cache", ".cache/lab/encrypted", "verified encrypted installer golden cache")
	flags.StringVar(&options.firmwareCode, "firmware-code", "", "package-owned OVMF code")
	flags.StringVar(&options.firmwareVars, "firmware-vars", "", "matching package-owned OVMF variables")
	flags.StringVar(&options.firmwarePackage, "firmware-package", "", "host firmware package")
	flags.StringVar(&options.firmwareVersion, "firmware-version", "", "exact installed firmware package version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || options.evidence == "" {
		return errors.New("lab acceptance requires -evidence NEW_DIRECTORY and no positional arguments")
	}
	if options.webOnly && options.skipFeeds {
		return errors.New("choose -web-only or -skip-feeds, not both")
	}
	var err error
	options.repository, err = filepath.Abs(options.repository)
	if err != nil {
		return err
	}
	if options.fixture == "" {
		options.fixture = options.repository
	}
	options.fixture, err = filepath.Abs(options.fixture)
	if err != nil {
		return err
	}
	options.evidence, err = filepath.Abs(options.evidence)
	if err != nil {
		return err
	}
	if err := os.Mkdir(options.evidence, 0700); err != nil {
		return err
	}
	record := &acceptanceRecord{StartedAt: time.Now().UTC(), Mode: "release"}
	if options.skipFeeds {
		record.Mode = "diagnostic-skip-feeds-NOT-A-RELEASE-PASS"
	}
	if options.webOnly {
		record.Mode = "web-only"
	}
	defer func() {
		if options.skipFeeds {
			resultErr = errors.Join(resultErr, errors.New("NOT A RELEASE PASS: feed refresh and known-exposure qualification were explicitly skipped"))
		}
		record.DurationSeconds = time.Since(record.StartedAt).Seconds()
		record.Passed = resultErr == nil
		if resultErr != nil {
			record.Failures = append(record.Failures, resultErr.Error())
		}
		resultErr = errors.Join(resultErr, writeLabEvidence(stdout, filepath.Join(options.evidence, "acceptance.json"), record))
	}()
	record.ServerSHA256, err = acceptanceFileDigest(options.binary)
	if err != nil {
		return err
	}
	record.LabSHA256, err = acceptanceFileDigest(options.labBinary)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Hour)
	defer cancel()
	private, err := os.MkdirTemp("", "lindm-acceptance-secrets-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(private)) }()
	fixture, err := devlab.OpenLocalConsoleAuthorityFixture(ctx, options.fixture, options.binary)
	if err != nil {
		return err
	}
	defer func() {
		err := fixture.Close()
		record.OwnedCleanupComplete = err == nil
		resultErr = errors.Join(resultErr, err)
	}()
	if !options.webOnly {
		// Before browser sessions: configuring signing restarts the server.
		if err := configureAcceptanceDispatch(ctx, fixture); err != nil {
			return err
		}
	}
	var chromium acceptanceBrowser
	var chromiumConfig acceptanceBrowserConfig
	for _, engine := range []string{"chromium", "webkit", "firefox"} {
		username := "acceptance-" + engine
		enrollment, err := fixture.CreateAcceptanceEnrollment(ctx, username)
		if err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("%s enrollment fixture: %w", engine, err))
			continue
		}
		var password [24]byte
		if _, err := rand.Read(password[:]); err != nil {
			return errors.Join(resultErr, err)
		}
		cfg := acceptanceBrowserConfig{Mode: "enroll", Engine: engine, Origin: fixture.ConsoleOrigin, Username: username, EnrollmentSecret: enrollment.GetSecret(), Password: hex.EncodeToString(password[:]), EvidenceDirectory: filepath.Join(options.evidence, engine), ResultPath: filepath.Join(private, engine+"-result.json"), CredentialPath: filepath.Join(private, engine+"-credential.json"), TimeoutMS: 120000}
		if engine != "chromium" && chromiumConfig.Username != "" {
			cfg.PasswordProbe = &acceptancePasswordProbe{Username: chromiumConfig.Username, Password: chromiumConfig.Password}
		}
		browser, err := runAcceptanceBrowser(ctx, options.repository, private, cfg)
		enrollment.Secret, cfg.EnrollmentSecret = "", ""
		if engine == "chromium" {
			chromium, chromiumConfig = browser, cfg
		}
		browser.Grant.Secret, browser.Token.Secret = "", ""
		record.Browsers = append(record.Browsers, browser)
		resultErr = errors.Join(resultErr, err)
	}
	if options.webOnly {
		return resultErr
	}
	// Run feeds even when a browser failed: independent failures must remain
	// visible instead of masking the vendor-size path behind the first UI error.
	if !options.skipFeeds {
		record.Feeds, err = fixture.RefreshAcceptanceFeeds(ctx, filepath.Join(options.fixture, ".cache/lab/acceptance-feeds"), options.feedBytes, options.feedDuration)
		resultErr = errors.Join(resultErr, err)
	}
	if !chromium.Passed || chromium.Grant.Secret == "" || chromium.Token.Secret == "" {
		return errors.Join(resultErr, errors.New("native journey unqualified: Chromium did not deliver real UI enrollment credentials"))
	}
	record.Native, err = runAcceptanceNative(ctx, fixture, options, private, chromiumConfig, chromium)
	chromium.Grant.Secret, chromium.Token.Secret = "", ""
	return errors.Join(resultErr, err)
}

func runAcceptanceBrowser(ctx context.Context, repository, private string, cfg acceptanceBrowserConfig) (acceptanceBrowser, error) {
	result := acceptanceBrowser{Engine: cfg.Engine}
	cfg.IgnoreHTTPSErrors = true // Owned fixture CA only; production origin/CSRF checks remain intact.
	if err := os.MkdirAll(cfg.EvidenceDirectory, 0700); err != nil {
		return result, err
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return result, err
	}
	path := filepath.Join(private, cfg.Engine+"-"+cfg.Mode+"-config.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		return result, err
	}
	clear(encoded)
	bounded, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	command := exec.CommandContext(bounded, "node", filepath.Join(repository, "web/acceptance/run.mjs"), path)
	command.Dir, command.WaitDelay = repository, 45*time.Second
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	// Browser output can contain UI credentials in framework diagnostics; the
	// maintained runner writes sanitized failures and masked screenshots itself.
	command.Stdout, command.Stderr = io.Discard, io.Discard
	runErr := command.Run()
	resultFile, readErr := os.Open(cfg.ResultPath)
	var body []byte
	if readErr == nil {
		body, readErr = io.ReadAll(io.LimitReader(resultFile, (1<<20)+1))
		readErr = errors.Join(readErr, resultFile.Close())
	}
	if readErr != nil {
		result.Failure = json.RawMessage(`{"code":"runner_evidence_missing"}`)
		return result, errors.Join(fmt.Errorf("%s: browser runner did not produce evidence", cfg.Engine), runErr, readErr)
	}
	defer clear(body)
	if len(body) > 1<<20 {
		return result, errors.New("browser result exceeds evidence budget")
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return result, errors.New("browser result is invalid")
	}
	if runErr != nil || !result.Passed {
		return result, errors.Join(fmt.Errorf("%s browser journey: %s", cfg.Engine, result.Failure), runErr)
	}
	return result, nil
}

func acceptanceFileDigest(path string) (_ string, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
