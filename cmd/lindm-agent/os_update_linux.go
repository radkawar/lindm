//go:build linux

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"lindm/internal/agent/osupdate"
)

// osUpdateCommand dispatches the packaged lindm-os-update{,-now,-status}
// units and the unprivileged notification child. Every verb takes no
// arguments; paths and policy are fixed root-owned files.
func osUpdateCommand(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("os-update requires exactly one of run, run-now, status")
	}
	if args[0] == "notify" {
		return osupdate.Notify(ctx, os.Stdin)
	}
	if os.Geteuid() != 0 {
		return errors.New("os-update requires root")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	runner, err := osupdate.New(osupdate.Config{
		Clock:      time.Now,
		Logger:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Executable: executable,
	})
	if err != nil {
		return err
	}
	switch args[0] {
	case "run":
		return runner.Run(ctx)
	case "run-now":
		return runner.RunNow(ctx)
	case "status":
		return runner.Status(ctx)
	default:
		return errors.New("os-update requires exactly one of run, run-now, status")
	}
}
