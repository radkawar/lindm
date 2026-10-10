package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/advisory"
	"lindm/internal/config"
)

// Explicit operator commands reuse exactly the server's validated feed config,
// HTTP trust, parser and transactional publication; no parallel import database.
func runAdvisories(ctx context.Context, args []string) (resultErr error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := flags.String("config", "", "protobuf JSON server configuration")
	var feedID, inputPath string
	if args[0] == "advisories-import" {
		flags.StringVar(&feedID, "feed", "", "configured feed ID with pinned expected_sha256")
		flags.StringVar(&inputPath, "file", "", "cached vendor feed bytes")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("advisories: -config FILE is required; positional arguments are not accepted")
	}
	if args[0] == "advisories-import" && (feedID == "" || inputPath == "") {
		return errors.New("advisories-import requires -feed ID and -file FILE")
	}
	document, err := config.Load(*path)
	if err != nil {
		return err
	}
	resources, err := document.Resolve()
	if err != nil {
		return err
	}
	defer resources.HTTPClient.CloseIdleConnections()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(startup, resources.Database)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Check(startup, pool); err != nil {
		return err
	}
	service, err := advisory.New(startup, pool, resources.Proto.GetAdvisories(), resources.HTTPClient)
	if err != nil {
		return err
	}
	cancel()
	if args[0] == "advisories-refresh" {
		if err := service.Refresh(ctx); err != nil {
			return err
		}
	} else {
		input, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("open advisory input: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
		info, err := input.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("advisory input must be a regular file")
		}
		if err := service.Import(ctx, feedID, input); err != nil {
			return err
		}
	}
	slog.Info("advisory feeds published", "command", args[0])
	return nil
}
