// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"lindm/internal/vmlab"
)

func runDeployIntegrationProof(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("deploy integrations-proof", flag.ContinueOnError)
	flags.SetOutput(stderr)
	destination := flags.String("destination-id", "", "real browser-created integration destination UUID")
	digest := flags.String("secret-sha256", "", "browser-observed random signing secret digest, never the secret")
	captured := flags.Bool("ciphertext-stdin", false, "read original encrypted destination bytes as bounded JSON from stdin")
	reject := flags.Bool("reject-fresh-key", false, "prove the fresh host's actual different key cannot decrypt the original ciphertext")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *destination == "" || *digest == "" || (*reject && !*captured) {
		return errors.New("deploy integration proof requires destination UUID and secret digest; fresh rejection also requires ciphertext stdin")
	}
	var ciphertext []byte
	if *captured {
		input := io.LimitReader(os.Stdin, 4097)
		decoder := json.NewDecoder(input)
		if err := decoder.Decode(&ciphertext); err != nil || len(ciphertext) < 32 || len(ciphertext) > 256 {
			return errors.New("deploy: invalid_integration_ciphertext")
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return errors.New("deploy: trailing_integration_ciphertext")
		}
	}
	defer clear(ciphertext)
	proof, err := vmlab.ObserveDeployIntegration(ctx, *destination, *digest, ciphertext, *reject)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(proof)
}

func runDeployDatabaseDiagnostic(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("deploy database-diagnostic accepts no arguments or credentials")
	}
	result, err := vmlab.ObserveDeployDatabaseDiagnostic(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
