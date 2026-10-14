// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/config"
	"lindm/internal/serverops"
)

// runSchemaCheck exposes a read-only, non-secret installer decision using the
// separately protected migration configuration; it does not load runtime keys.
func runSchemaCheck(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	flags := flag.NewFlagSet("schema-check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "protected migration protobuf JSON configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("schema-check requires -config FILE and no positional arguments")
	}
	var document *config.Document
	if os.Geteuid() == 0 {
		var cleanup func() error
		document, cleanup, err = serverops.StageDatabaseConfig(*path)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, cleanup()) }()
	} else {
		document, err = config.Load(*path)
	}
	if err != nil {
		return err
	}
	cfg, err := document.MigrationDatabase()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	status, err := db.Preflight(ctx, pool)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(status)
}
