// SPDX-License-Identifier: Apache-2.0

//go:build linux

// lindm-install provisions an authenticated private native release.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"lindm/internal/install"
)

type recipientFiles []string

func (r *recipientFiles) String() string { return strings.Join(*r, ",") }
func (r *recipientFiles) Set(path string) error {
	if len(*r) >= 3 {
		return errors.New("at most three root custodian recipient files")
	}
	*r = append(*r, path)
	return nil
}

func main() {
	var o install.Options
	var rootRecipients recipientFiles
	flag.StringVar(&o.Bundle, "bundle", ".", "authenticated release export directory")
	flag.StringVar(&o.ReleaseKey, "release-key-file", "", "independently authenticated release public key")
	flag.StringVar(&o.ReleaseKeyID, "release-key-id", "", "independently authenticated SPKI SHA256")
	flag.StringVar(&o.Origin, "origin", "", "public console HTTPS origin")
	flag.StringVar(&o.DeviceOrigin, "device-origin", "", "public device HTTPS origin")
	flag.StringVar(&o.BackupRecipient, "backup-recipient-file", "", "operator age public recipient file; never a private key")
	flag.Var(&rootRecipients, "execution-root-recipient-file", "repeat up to three distinct offline root custodian age public-recipient files; missing identities use encrypted quick custody")
	flag.IntVar(&o.CustodyPassphraseFD, "custody-passphrase-fd", -1, "anonymous root-protected pipe with two identical newline-terminated custody passphrases; never a file, argv or environment secret")
	flag.StringVar(&o.DatabaseURL, "database-url-file", "", "protected runtime PostgreSQL URL file")
	flag.StringVar(&o.DatabaseURL, "database-url", "", "alias for database-url-file; never a URL value")
	flag.StringVar(&o.MigrationURL, "migration-url-file", "", "protected migrator PostgreSQL URL file")
	flag.StringVar(&o.TLSCertificate, "tls-cert-file", "", "bring-own TLS certificate chain")
	flag.StringVar(&o.TLSKey, "tls-key-file", "", "bring-own protected TLS private key")
	flag.StringVar(&o.TLSCA, "tls-ca-file", "", "required bring-own independently approved public TLS roots")
	flag.StringVar(&o.SetupCodeFile, "setup-code-file", "", "new root-only setup-code output instead of private terminal")
	flag.UintVar(&o.AdminPort, "admin-port", 18444, "native admin listener port")
	flag.UintVar(&o.DevicePort, "device-port", 18445, "native device listener port")
	flag.BoolVar(&o.Airgap, "airgap", false, "prohibit package repository network access")
	flag.BoolVar(&o.Rollback, "rollback", false, "explicit compatible-schema package rollback; never applies Down migrations")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "lindm install: positional arguments are not accepted")
		os.Exit(1)
	}
	o.ExecutionRootRecipients = []string(rootRecipients)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if err := install.Run(ctx, o); err != nil {
		fmt.Fprintln(os.Stderr, "lindm install:", err)
		os.Exit(1)
	}
}
