// SPDX-License-Identifier: Apache-2.0
//go:build linux

// Command release provisions operator-owned custody and builds production releases.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"lindm/internal/custody"
	"lindm/internal/pki"
	"lindm/internal/releasekit"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("use init, build or verify; run the selected command with --help")
	}
	switch args[0] {
	case "init":
		return runInit(ctx, args[1:], stdout, stderr)
	case "build":
		return runBuild(ctx, args[1:], stdout, stderr)
	case "verify":
		return runVerify(ctx, args[1:], stdout, stderr)
	default:
		return errors.New("unknown command; use init, build or verify")
	}
}

type repeated []string

func (v *repeated) String() string { return strings.Join(*v, ",") }
func (v *repeated) Set(value string) error {
	*v = append(*v, value)
	return nil
}

func runInit(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	flags := flag.NewFlagSet("release init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("keys", "release-keys", "new operator custody directory; refuses overwrite")
	caPath := flags.String("ca-bundle", "/etc/ssl/certs/ca-certificates.crt", "operator-approved PEM public roots to pin for OCI; this command explicitly selects this source")
	passFD := flags.Int("passphrase-fd", -1, "owner-private anonymous pipe; two matching LF-terminated passphrases; default private terminal")
	var recipients repeated
	flags.Var(&recipients, "recipient", "operator-owned age X25519 recipient; repeat for multiple custodians; otherwise passphrase-sealed quick start")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (len(recipients) > 0 && *passFD >= 0) {
		return errors.New("init accepts no positional arguments; recipient and passphrase modes are exclusive")
	}
	if err := protectSecrets(); err != nil {
		return err
	}
	roots, err := readRegular(*caPath, 4<<20)
	if err != nil {
		return fmt.Errorf("read explicitly selected CA roots: %w", err)
	}
	selected, skipped, selectionErr := pki.SelectReleaseCARoots(roots)
	for _, certificate := range skipped {
		if _, err := fmt.Fprintf(stderr, "warning: skipping non-CA trust entry: subject=%q certificate_sha256=%s\n", certificate.Subject.String(), sha256Hex(certificate.Raw)); err != nil {
			return err
		}
	}
	if selectionErr != nil {
		return selectionErr
	}
	roots = selected
	var passphrase []byte
	if len(recipients) == 0 {
		var buffer *custody.SecretBuffer
		buffer, err = readPassphrase(ctx, *passFD, true)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, buffer.Close()) }()
		passphrase = buffer.Bytes()
	}
	public, err := releasekit.Init(ctx, *directory, recipients, passphrase, roots)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(*directory)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Production release custody created: %s\nCA roots explicitly selected from: %s\nAttestation SPKI SHA256: %s\nPackage fingerprint: %s\nInventory SHA256: %s\nCA SHA256: %s\nBack up the ENTIRE directory %s (custody.age contains every private key).\nKeep a separate authenticated copy of attestation.pub and pins.txt for verification.\nBack up the passphrase separately, or retain each recipient's private age identity with its custodian.\nQuick-start backup identity, if generated, is only inside custody.age; backup-recipient.txt is public.\nNever copy custody.age, passphrases or private age identities into a release bundle or onto the server.\n", absolute, *caPath, public.AttestationKeyID, public.PackageFingerprint, public.InventorySHA256, public.CASHA256, absolute)
	return err
}

func protectSecrets() error {
	if err := custody.ProtectNativeSigningSecrets(); err != nil {
		return fmt.Errorf("protect production signing secret allocations: %w", err)
	}
	return nil
}
