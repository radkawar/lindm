// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/config"
	"lindm/internal/identity"
	"lindm/internal/server"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if err := disableCoreDumps(); err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New("usage: lindmd {serve|migrate|setup-code|bootstrap-owner|check-config|schema-check|backup-keygen|backup|restore|restore-drill|support|update|custody-status|advisories-refresh|advisories-import|bundle-import} -config FILE; lindmd version")
	}
	command := args[0]
	switch command {
	case "version":
		if len(args) != 1 {
			return errors.New("version accepts no arguments")
		}
		_, err := io.WriteString(os.Stdout, buildinfo.Line())
		return err
	case "advisories-refresh", "advisories-import":
		return runAdvisories(ctx, args)
	case "bundle-import":
		return runBundleImport(ctx, args)
	case "setup-code":
		return runSetupCode(ctx, args[1:])
	case "schema-check":
		return runSchemaCheck(ctx, args[1:], os.Stdout, os.Stderr)
	case "backup-keygen", "backup", "restore", "restore-drill", "support", "update", "custody-status":
		return runOperations(ctx, args)
	case "serve", "migrate", "bootstrap-owner", "check-config":
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("config", "", "protobuf JSON configuration file")
	var databaseCredential string
	if command == "serve" || command == "migrate" || command == "check-config" {
		flags.StringVar(&databaseCredential, "database-url-credential", "", "systemd credential name in CREDENTIALS_DIRECTORY (no persistent-file fallback)")
	}
	var issuer, subject, tenantID, objectID string
	if command == "bootstrap-owner" {
		flags.StringVar(&issuer, "issuer", "", "exact configured issuer")
		flags.StringVar(&subject, "subject", "", "immutable upstream owner subject")
		flags.StringVar(&tenantID, "tenant-id", "", "configured Entra tenant UUID")
		flags.StringVar(&objectID, "object-id", "", "immutable Entra owner object UUID")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("-config FILE is required; positional arguments are not accepted")
	}
	document, err := config.Load(*path)
	if err != nil {
		return err
	}
	if err := useDatabaseURLCredential(document, flags, databaseCredential); err != nil {
		return err
	}
	if command == "migrate" {
		return migrate(ctx, document)
	}
	resources, err := document.Resolve()
	if err != nil {
		return err
	}
	if command == "serve" {
		return server.Run(ctx, resources)
	}
	defer resources.HTTPClient.CloseIdleConnections()
	if command == "check-config" {
		slog.Info("configuration and runtime files are valid", "connectivity_checked", false)
		return nil
	}
	local := resources.Proto.GetAuthentication().GetLocal() != nil
	if local {
		return errors.New("LOCAL first-run requires setup-code and browser setup; bootstrap-owner only binds an external identity")
	} else if entra := resources.Proto.GetAuthentication().GetEntra(); entra != nil {
		if tenantID == "" || objectID == "" || issuer != "" || subject != "" {
			return errors.New("entra bootstrap-owner requires -tenant-id and -object-id and rejects -issuer/-subject")
		}
		configuredIssuer, err := identity.EntraIssuer(entra.GetTenantId())
		if err != nil {
			return err
		}
		issuer, err = identity.EntraIssuer(tenantID)
		if err != nil || issuer != configuredIssuer {
			return identity.ErrIssuerMismatch
		}
		object, err := uuid.Parse(objectID)
		if err != nil || object == uuid.Nil {
			return identity.ErrSubjectUnqualified
		}
		subject = object.String()
	} else if issuer == "" || subject == "" || tenantID != "" || objectID != "" {
		return errors.New("external bootstrap-owner requires -issuer and -subject and rejects -tenant-id/-object-id")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, resources.Database)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Check(ctx, pool); err != nil {
		return err
	}
	auth, err := server.NewIdentity(ctx, pool, resources)
	if err != nil {
		return err
	}
	if err := auth.BootstrapOwner(ctx, issuer, subject); err != nil {
		return err
	}
	slog.Info("owner binding confirmed", "issuer", issuer, "subject", subject)
	return nil
}

func migrate(ctx context.Context, document *config.Document) error {
	cfg, err := document.MigrationDatabase()
	if err != nil {
		return err
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = "5s"
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "2min"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "1min"
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	if err := db.Check(ctx, pool); err != nil {
		return err
	}
	slog.Info("database migrations are current")
	return nil
}

func useDatabaseURLCredential(document *config.Document, flags *flag.FlagSet, name string) error {
	var requested bool
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "database-url-credential" {
			requested = true
		}
	})
	if !requested {
		return nil
	}
	return document.UseDatabaseURLCredential(name, os.Getenv("CREDENTIALS_DIRECTORY"))
}
