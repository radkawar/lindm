package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/config"
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
	if len(args) == 0 {
		return errors.New("usage: lindmd {serve|migrate|bootstrap-owner|check-config} -config FILE")
	}
	command := args[0]
	switch command {
	case "serve", "migrate", "bootstrap-owner", "check-config":
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("config", "", "protobuf JSON configuration file")
	var issuer, subject string
	if command == "bootstrap-owner" {
		flags.StringVar(&issuer, "issuer", "", "exact configured issuer")
		flags.StringVar(&subject, "subject", "", "immutable upstream owner subject")
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
	if issuer == "" || subject == "" {
		return errors.New("bootstrap-owner requires -issuer and -subject")
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
