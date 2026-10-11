//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
	"lindm/internal/labhost"
)

// runBrowserBaseline is an explicitly authorized prerequisite transaction, not
// acceptance evidence. The private record survives partial package installation.
func runBrowserBaseline(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("hosts baseline-browser", flag.ContinueOnError)
	flags.SetOutput(stderr)
	hostName := flags.String("host", "local", "configured lab host name, local, or plain SSH alias")
	record := flags.String("record", "", "required new private JSON prerequisite evidence file")
	repository := flags.String("repo", ".", "checkout containing the maintained browser installer")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *record == "" {
		return errors.New("hosts baseline-browser requires -record NEW_FILE [-host NAME] [-repo DIR]; invocation authorizes browser dependencies through sudo -n and private pinned Firefox/geckodriver installation")
	}
	cfg, err := labhost.Load()
	if err != nil {
		return err
	}
	alias := *hostName
	local := alias == "local"
	for _, host := range cfg.GetHosts() {
		if host.GetName() == *hostName {
			if host.GetTransport() != "local" && host.GetTransport() != "ssh" {
				return errors.New("browser baseline supports local and SSH hosts only")
			}
			local = host.GetTransport() == "local"
			alias = host.GetSshAlias()
			break
		}
	}
	if !local {
		if alias == "" || strings.HasPrefix(alias, "-") || len(alias) > 253 {
			return errors.New("browser baseline requires a plain SSH alias")
		}
		for _, c := range alias {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
				continue
			}
			return errors.New("browser baseline requires a plain SSH alias")
		}
	}
	script, err := os.ReadFile(filepath.Join(*repository, "web", "acceptance", "install-browsers.sh"))
	if err != nil {
		return err
	}
	if len(script) > 128<<10 {
		return errors.New("browser baseline installer exceeds size bound")
	}
	file, err := os.OpenFile(*record, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("reserve private browser baseline evidence: %w", err)
	}
	evidence := struct {
		Host             string    `json:"host"`
		StartedAt        time.Time `json:"startedAt"`
		FinishedAt       time.Time `json:"finishedAt"`
		Installed        bool      `json:"installed"`
		BrowserQualified bool      `json:"browserQualified"`
		FirefoxVersion   string    `json:"firefoxVersion"`
		GeckoVersion     string    `json:"geckodriverVersion"`
		Transcript       string    `json:"transcript"`
		Failure          string    `json:"failure,omitempty"`
	}{Host: *hostName, StartedAt: time.Now().UTC(), FirefoxVersion: "157.0.1", GeckoVersion: "0.37.1"}
	defer func() {
		evidence.FinishedAt = time.Now().UTC()
		if resultErr != nil {
			evidence.Failure = resultErr.Error()
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		writeErr := encoder.Encode(evidence)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		resultErr = errors.Join(resultErr, writeErr, file.Close())
	}()
	command := labexec.Command{Path: "/bin/bash", Args: []string{"--noprofile", "--norc", "-s"}, Timeout: 20 * time.Minute, Interrupt: syscall.SIGTERM, Grace: 5 * time.Second}
	if !local {
		command.Path, command.Args = "ssh", []string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ControlMaster=no", "-o", "ControlPath=none", "--", alias, "/bin/bash --noprofile --norc -s"}
	}
	output := nativeexec.NewBuffer(4 << 20)
	writer := io.MultiWriter(output, stderr)
	command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(script), writer, writer
	err = labexec.Run(ctx, command)
	if err == nil && output.Truncated() {
		err = errors.New("browser baseline output exceeds 4 MiB evidence bound")
	}
	evidence.Transcript = output.String()
	if err != nil {
		return fmt.Errorf("browser prerequisite transaction failed; private evidence retained at %s: %w", *record, err)
	}
	evidence.Installed = true
	_, err = fmt.Fprintf(stdout, "Browser prerequisites installed; actual versions and paths recorded in %s. Native WebAuthn acceptance remains unqualified until lab acceptance runs.\n", *record)
	return err
}
