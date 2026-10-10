package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labhost"
)

func runHostsBaseline(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("hosts baseline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	hostName := flags.String("host", "", "required configured host name, local, or plain SSH alias for bootstrap")
	record := flags.String("record", "", "required new private JSON evidence file; partial changes are recorded on failure")
	repo := flags.String("repo", ".", "checkout containing maintained lab/baseline package pins")
	config := flags.String("config", "", "strict LabConfig JSON (default: LINDM_LAB_CONFIG, then user config, then local defaults)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *hostName == "" || *record == "" {
		return errors.New("hosts baseline requires -host NAME -record NEW_FILE and accepts optional -repo DIR -config FILE; invoking it authorizes the maintained exact package transaction and r's kvm membership")
	}
	var cfg *labv1.LabConfig
	var err error
	if *config == "" {
		cfg, err = labhost.Load()
	} else {
		cfg, err = labhost.LoadFile(*config)
	}
	if err != nil {
		return err
	}
	var host *labv1.LabHost
	for _, configured := range cfg.GetHosts() {
		if configured.GetName() == *hostName {
			host = configured
			break
		}
	}
	if host == nil {
		if *hostName == "local" {
			host = &labv1.LabHost{Name: "local", Transport: "local"}
		} else {
			name := strings.NewReplacer(".", "-", "_", "-").Replace(strings.ToLower(*hostName))
			host = &labv1.LabHost{Name: name, Transport: "ssh", SshAlias: *hostName}
		}
	}
	// Reserve the record before any host mutation. O_EXCL prevents overwriting
	// earlier evidence or following a final-component symlink.
	file, err := os.OpenFile(*record, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("reserve baseline evidence before host mutation: %w", err)
	}
	result, baselineErr := labhost.RunBaseline(ctx, labhost.BaselineOptions{Host: host, RepoDir: *repo, Diagnostics: stderr})
	var hostJSON []byte
	if baselineErr == nil {
		hostJSON, err = (protojson.MarshalOptions{Indent: "  "}).Marshal(result.Host)
		baselineErr = errors.Join(baselineErr, err)
	}
	evidence := struct {
		*labhost.BaselineResult
		Host json.RawMessage `json:"host,omitempty"`
	}{BaselineResult: result, Host: hostJSON}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(evidence)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	writeErr = errors.Join(writeErr, file.Close())
	if writeErr != nil {
		return errors.Join(baselineErr, fmt.Errorf("persist baseline evidence at %s (host may already have changed): %w", *record, writeErr))
	}
	if baselineErr != nil {
		return fmt.Errorf("baseline failed; before/after evidence retained at %s: %w", *record, baselineErr)
	}
	// stdout contains only strict protobuf JSON suitable as a LabConfig hosts
	// entry. A failed readiness check never prints a usable host entry.
	_, err = stdout.Write(append(hostJSON, '\n'))
	return err
}
