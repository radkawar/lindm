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
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/config"
	"lindm/internal/identity"
)

func runSetupCode(ctx context.Context, args []string) (err error) {
	flags := flag.NewFlagSet("setup-code", flag.ContinueOnError)
	path := flags.String("config", "", "protobuf JSON migration configuration")
	output := flags.String("output", "", "new issuer-owned 0600 setup-code file")
	credential := flags.String("database-url-credential", "", "systemd credential name in CREDENTIALS_DIRECTORY (no persistent-file fallback)")
	if err = flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("setup-code requires -config FILE -output NEW_FILE and no positional arguments")
	}
	document, err := config.Load(*path)
	if err != nil {
		return err
	}
	if document.Proto.GetAuthentication().GetLocal() == nil {
		return errors.New("setup-code requires LOCAL authentication")
	}
	if err := useDatabaseURLCredential(document, flags, *credential); err != nil {
		return err
	}
	cfg, err := document.MigrationDatabase()
	if err != nil {
		return err
	}
	file, err := createSetupOutput(*output)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		err = errors.Join(err, file.Close())
		if !complete {
			err = errors.Join(err, os.Remove(file.Name()))
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err = db.Check(ctx, pool); err != nil {
		return err
	}
	code, err := identity.IssueSetupCode(ctx, pool)
	if err != nil {
		return err
	}
	if _, err = io.WriteString(file, code+"\n"); err != nil {
		return errors.New("write setup code file failed; issue a replacement to a new protected file")
	}
	if err = file.Sync(); err != nil {
		return errors.New("sync setup code file failed; issue a replacement to a new protected file")
	}
	complete = true
	slog.Info("first-run code written to protected file", "expires_in_hours", 24)
	return nil
}

// The target must not exist. Reject symlinks and replaceable ancestry rather
// than overwriting another secret, following a link or widening its permissions.
func createSetupOutput(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve setup output: %w", err)
	}
	for directory := filepath.Dir(absolute); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return nil, fmt.Errorf("inspect setup output directory: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) ||
			(info.Mode().Perm()&0022 != 0 && (stat.Uid != 0 || info.Mode()&os.ModeSticky == 0)) {
			return nil, errors.New("setup output ancestry must use owned, non-replaceable directories")
		}
		if directory == filepath.Dir(directory) {
			break
		}
	}
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("create setup output: %w", err)
	}
	return file, nil
}
